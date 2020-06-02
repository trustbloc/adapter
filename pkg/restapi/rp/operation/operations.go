/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-adapter/pkg/db"
	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
	"github.com/trustbloc/edge-adapter/pkg/presentationex"
	commhttp "github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/http"
)

// API endpoints.
const (
	hydraLoginEndpoint                 = "/login"
	hydraConsentEndpoint               = "/consent"
	OIDCCallbackEndpoint               = "/callback"
	createPresentationRequestEndpoint  = "/presentations/create"
	handlePresentationResponseEndpoint = "/presentations/handleResponse"
	userInfoEndpoint                   = "/userinfo"
)

// errors.
const (
	invalidRequestErrMsg = "invalid request"
)

var logger = log.New("edge-adapter/rp-operations")

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type presentationExProvider interface {
	Create(scopes []string) (*presentationex.PresentationDefinitions, error)
}

// Hydra is the client used to interface with the Hydra service.
type Hydra interface {
	GetLoginRequest(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error)
	AcceptLoginRequest(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error)
	GetConsentRequest(*admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error)
	AcceptConsentRequest(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error)
}

// OAuth2Config is an OAuth2 client.
type OAuth2Config interface {
	ClientID() string
	AuthCodeURL(string) string
}

// UsersDAO is the EndUser DAO.
type UsersDAO interface {
	Insert(*db.EndUser) error
	FindBySub(string) (*db.EndUser, error)
}

// OidcRequestsDAO is the OIDCRequest DAO.
type OidcRequestsDAO interface {
	Insert(*db.OIDCRequest) error
	FindByUserSubAndRPClientID(string, string) (*db.OIDCRequest, error)
	Update(*db.OIDCRequest) error
}

// RelyingPartiesDAO is the RelyingParty DAO.
type RelyingPartiesDAO interface {
	FindByClientID(string) (*db.RelyingParty, error)
}

// Trx is a DB transaction.
type Trx interface {
	Commit() error
	Rollback() error
}

type consentRequest struct {
	pd *presentationex.PresentationDefinitions
	cr *admin.GetConsentRequestOK
}

// New returns CreateCredential instance.
func New(config *Config) (*Operation, error) {
	return &Operation{
		presentationExProvider: config.PresentationExProvider,
		hydra:                  config.Hydra,
		oidc:                   config.OIDC,
		oauth2Config:           config.OAuth2Config,
		oidcStates:             make(map[string]*models.LoginRequest),
		trxProvider:            config.TrxProvider,
		users:                  config.UsersDAO,
		oidcRequests:           config.OIDCRequestsDAO,
		relyingPartiesDAO:      config.RelyingPartiesDAO,
		consentRequests:        make(map[string]*consentRequest),
		uiEndpoint:             config.UIEndpoint,
	}, nil
}

// Config defines configuration for rp operations.
type Config struct {
	PresentationExProvider presentationExProvider
	Hydra                  Hydra
	OIDC                   func(string, context.Context) (*oidc.IDToken, error)
	OAuth2Config           OAuth2Config
	TrxProvider            func(context.Context, *sql.TxOptions) (Trx, error)
	UsersDAO               UsersDAO
	RelyingPartiesDAO      RelyingPartiesDAO
	OIDCRequestsDAO        OidcRequestsDAO
	UIEndpoint             string
}

// TODO implement an eviction strategy for Operation.oidcStates and OIDC.consentRequests
//  https://github.com/trustbloc/edge-adapter/issues/29

// Operation defines handlers for rp operations.
type Operation struct {
	presentationExProvider presentationExProvider
	hydra                  Hydra
	oidc                   func(string, context.Context) (*oidc.IDToken, error)
	oauth2Config           OAuth2Config
	oidcStates             map[string]*models.LoginRequest
	oidcStateLock          sync.Mutex
	trxProvider            func(context.Context, *sql.TxOptions) (Trx, error)
	users                  UsersDAO
	oidcRequests           OidcRequestsDAO
	relyingPartiesDAO      RelyingPartiesDAO
	consentRequests        map[string]*consentRequest
	presDefsLock           sync.Mutex
	uiEndpoint             string
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(hydraLoginEndpoint, http.MethodGet, o.hydraLoginHandler),
		support.NewHTTPHandler(hydraConsentEndpoint, http.MethodGet, o.hydraConsentHandler),
		support.NewHTTPHandler(OIDCCallbackEndpoint, http.MethodGet, o.oidcCallbackHandler),
		support.NewHTTPHandler(createPresentationRequestEndpoint, http.MethodPost, o.createPresentationDefinition),
		support.NewHTTPHandler(handlePresentationResponseEndpoint, http.MethodPost, o.presentationResponseHandler),
		support.NewHTTPHandler(userInfoEndpoint, http.MethodGet, o.userInfoHandler),
	}
}

// Hydra redirects the user here in the authentication phase.
// TODO redirect to UI when not skipping
// TODO ensure request's origin is the same as the hydraUrl
//  https://stackoverflow.com/q/27234861/1623885
func (o *Operation) hydraLoginHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("hydra login request: %s", r.URL.String())

	challenge := r.URL.Query().Get("login_challenge")
	if challenge == "" {
		logger.Warnf("missing challenge on login request")
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, invalidRequestErrMsg)

		return
	}

	req := admin.NewGetLoginRequestParams()

	req.SetLoginChallenge(challenge)

	login, err := o.hydra.GetLoginRequest(req)
	if err != nil {
		msg := fmt.Sprintf("failed to contact hydra : %s", err.Error())
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	if login.GetPayload().Skip {
		logger.Debugf("hydra instruction to skip login screen")

		err := acceptLoginAndRedirectToHydra(w, r, o.hydra, login.GetPayload())
		if err != nil {
			msg := fmt.Sprintf("failed to accept login request : %s", err.Error())
			logger.Errorf(msg)
			commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)
		}

		return
	}

	state := uuid.New().String()

	o.setLoginRequestForState(state, login.GetPayload())

	authURL := o.oauth2Config.AuthCodeURL(state)

	http.Redirect(w, r, authURL, http.StatusFound)
	logger.Debugf("redirected to: %s", authURL)
}

func (o *Operation) setLoginRequestForState(state string, request *models.LoginRequest) {
	o.oidcStateLock.Lock()
	defer o.oidcStateLock.Unlock()

	o.oidcStates[state] = request
}

func (o *Operation) getAndUnsetLoginRequest(state string) *models.LoginRequest {
	o.oidcStateLock.Lock()
	defer o.oidcStateLock.Unlock()

	r := o.oidcStates[state]
	delete(o.oidcStates, state)

	return r
}

func (o *Operation) setConsentRequest(handle string, r *consentRequest) {
	o.presDefsLock.Lock()
	defer o.presDefsLock.Unlock()

	o.consentRequests[handle] = r
}

func (o *Operation) getAndUnsetConsentRequest(handle string) *consentRequest {
	o.presDefsLock.Lock()
	defer o.presDefsLock.Unlock()

	r := o.consentRequests[handle]
	delete(o.consentRequests, handle)

	return r
}

func acceptLoginAndRedirectToHydra(
	w http.ResponseWriter, r *http.Request, hydra Hydra, login *models.LoginRequest) error {
	accept := admin.NewAcceptLoginRequestParams()

	accept.SetLoginChallenge(login.Challenge)
	accept.SetBody(&models.AcceptLoginRequest{
		Subject: &login.Subject,
	})

	loginResponse, err := hydra.AcceptLoginRequest(accept)
	if err != nil {
		return fmt.Errorf("failed to accept login request : %w", err)
	}

	http.Redirect(w, r, loginResponse.GetPayload().RedirectTo, http.StatusFound)
	logger.Debugf("redirected to: %s", loginResponse.GetPayload().RedirectTo)

	return nil
}

// OIDC provider redirects the user here after they've been authenticated.
func (o *Operation) oidcCallbackHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("oidc callback request: %s", r.URL.String())
	login := o.getAndUnsetLoginRequest(r.URL.Query().Get("state"))

	if login == nil {
		logger.Warnf("missing state parameter in oidc callback request")
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, invalidRequestErrMsg)

		return
	}

	idToken, err := o.oidc(r.URL.Query().Get("code"), r.Context())
	if err != nil {
		msg := fmt.Sprintf("failed to exchange code for an id_token : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	err = o.saveUserAndRequest(r.Context(), login, idToken.Subject)
	if err != nil {
		msg := fmt.Sprintf("failed to save user and request : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	accept := admin.NewAcceptLoginRequestParams()

	accept.SetLoginChallenge(login.Challenge)
	accept.SetBody(&models.AcceptLoginRequest{
		Subject: &idToken.Subject,
	})

	resp, err := o.hydra.AcceptLoginRequest(accept)
	if err != nil {
		msg := fmt.Sprintf("failed to accept login request at hydra : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	http.Redirect(w, r, resp.GetPayload().RedirectTo, http.StatusFound)
	logger.Debugf("redirected to: %s", resp.GetPayload().RedirectTo)
}

func (o *Operation) saveUserAndRequest(ctx context.Context, login *models.LoginRequest, sub string) (errResult error) {
	tx, err := o.trxProvider(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start a db transaction : %w", err)
	}

	defer func() {
		switch errResult {
		case nil:
			errResult = tx.Commit()
		default:
			txErr := tx.Rollback()
			if txErr != nil {
				errResult = errors.Wrap(errResult, err.Error())
			}
		}
	}()

	rp, err := o.relyingPartiesDAO.FindByClientID(login.Client.ClientID)
	if err != nil {
		return fmt.Errorf("failed to find a relying party with client_id=%s : %w", login.Client.ClientID, err)
	}

	user := &db.EndUser{
		Sub: sub,
	}

	err = o.users.Insert(user)
	if err != nil {
		return fmt.Errorf("failed to insert user : %w", err)
	}

	err = o.oidcRequests.Insert(&db.OIDCRequest{
		EndUserID:      user.ID,
		RelyingPartyID: rp.ID,
		Scopes:         login.RequestedScope,
	})
	if err != nil {
		return fmt.Errorf("failed to insert oidc requests : %w", err)
	}

	return nil
}

// Hydra redirects the user here in the consent phase.
func (o *Operation) hydraConsentHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("hydraConsentHandler request: " + r.URL.String())

	challenge := r.URL.Query().Get("consent_challenge")
	if challenge == "" {
		logger.Warnf("missing consent_challenge")
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, invalidRequestErrMsg)

		return
	}

	req := admin.NewGetConsentRequestParamsWithContext(r.Context())
	req.SetConsentChallenge(challenge)

	consent, err := o.hydra.GetConsentRequest(req)
	if err != nil {
		logger.Errorf("failed to get fetch consent request from hydra : %s", err)
		commhttp.WriteErrorResponse(
			w, http.StatusInternalServerError, fmt.Sprintf("failed to contact hydra : %s", err))

		return
	}

	if consent.GetPayload().Skip {
		o.skipConsentScreen(w, r, consent)

		return
	}

	presentationDefinition, err := o.presentationExProvider.Create(consent.GetPayload().RequestedScope)
	if err != nil {
		logger.Errorf("failed to create presentation-exchange request: %s", err)
		commhttp.WriteErrorResponse(
			w, http.StatusInternalServerError, fmt.Sprintf("failed to create the presentation definition : %s", err))

		return
	}

	handle := url.QueryEscape(uuid.New().String())
	o.setConsentRequest(handle, &consentRequest{
		cr: consent,
		pd: presentationDefinition,
	})

	redirectURL := fmt.Sprintf("%s?pd=%s", o.uiEndpoint, handle)

	http.Redirect(w, r, redirectURL, http.StatusFound)
	logger.Debugf("redirected to: %s", redirectURL)
}

func (o *Operation) skipConsentScreen(w http.ResponseWriter, r *http.Request, consent *admin.GetConsentRequestOK) {
	logger.Debugf("skipping consent screen")

	params := admin.NewAcceptConsentRequestParamsWithContext(r.Context())

	params.SetConsentChallenge(consent.GetPayload().Challenge)

	accepted, err := o.hydra.AcceptConsentRequest(params)
	if err != nil {
		logger.Errorf("failed to accept consent request at hydra: %s", err)
		commhttp.WriteErrorResponse(
			w, http.StatusInternalServerError, fmt.Sprintf("hydra failed to accept consent request : %s", err))

		return
	}

	http.Redirect(w, r, accepted.GetPayload().RedirectTo, http.StatusFound)
	logger.Debugf("redirected to: %s", accepted.GetPayload().RedirectTo)
}

// Frontend requests to create presentation definition.
func (o *Operation) createPresentationDefinition(rw http.ResponseWriter, req *http.Request) {
	logger.Debugf("createPresentationDefinition request: %s", req.URL.String())

	// get the request
	handle := req.URL.Query().Get("pd")
	if handle == "" {
		logger.Warnf("missing handle for presentation definition")
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, invalidRequestErrMsg)

		return
	}

	cr := o.getAndUnsetConsentRequest(handle)
	if cr == nil {
		logger.Warnf("unrecognized handle for presentation definition: %s", handle)
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, invalidRequestErrMsg)

		return
	}

	err := o.saveConsentRequest(req.Context(), cr)
	if err != nil {
		logger.Errorf("failed to save consent request: %s", err)
		commhttp.WriteErrorResponse(
			rw, http.StatusInternalServerError, fmt.Sprintf("failed to save consent request : %s", err))

		return
	}

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponse(rw, cr.pd)
	logger.Debugf("wrote response: %+v", cr.pd)
}

func (o *Operation) saveConsentRequest(ctx context.Context, r *consentRequest) (errResult error) {
	trx, err := o.trxProvider(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to obtain a db transaction : %w", err)
	}

	defer func() {
		switch errResult {
		case nil:
			errResult = trx.Commit()
		default:
			errRollback := trx.Rollback()
			if errRollback != nil {
				errResult = errors.Wrap(errResult, errRollback.Error())
			}
		}
	}()

	user, err := o.users.FindBySub(r.cr.GetPayload().Subject)
	if err != nil {
		return fmt.Errorf("failed to find user with sub=%s : %w", r.cr.GetPayload().Subject, err)
	}

	oidcReq, err := o.oidcRequests.FindByUserSubAndRPClientID(user.Sub, r.cr.GetPayload().Client.ClientID)
	if err != nil {
		return fmt.Errorf(
			"failed to find oidc request for sub=%s clientID=%s : %w",
			user.Sub, r.cr.GetPayload().Client.ClientID, err)
	}

	oidcReq.PresDef = r.pd

	err = o.oidcRequests.Update(oidcReq)
	if err != nil {
		return fmt.Errorf("failed to update oidc request with id=%d: %w", oidcReq.ID, err)
	}

	return nil
}

// Frontend submits the user's presentation for evaluation.
//
// The user may have provided either:
// - all required credentials in a single response, or
// - consent credential + didcomm endpoint where the requested presentations can be obtained, or
// - nothing (an error response?), indicating they cannot satisfy the request.
func (o *Operation) presentationResponseHandler(w http.ResponseWriter, _ *http.Request) {
	// TODO validate response, do DIDComm with the issuer if required, gather all credentials,
	//  make sure they're all valid and all present, load the consent_challenge and accept the user's
	//  consent at hydra's /consent/accept endpoint and respond with hydra's redirect URL.
	testResponse(w)
}

// RP requests user data.
func (o *Operation) userInfoHandler(w http.ResponseWriter, _ *http.Request) {
	// TODO introspect RP's access_token (Authorization request header) with hydra and validate.
	//  Load VPs related to the user and map them to a normal id_token and reply with that.
	testResponse(w)
}

func testResponse(w io.Writer) {
	_, err := w.Write([]byte("OK"))
	if err != nil {
		fmt.Printf("error writing test response: %s", err.Error())
	}
}
