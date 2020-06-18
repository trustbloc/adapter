/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	didexchangesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edge-adapter/pkg/db/rp"
	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
	"github.com/trustbloc/edge-adapter/pkg/presentationex"
	commhttp "github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/http"
)

// API endpoints.
const (
	hydraLoginEndpoint                 = "/login"
	hydraConsentEndpoint               = "/consent"
	OIDCCallbackEndpoint               = "/callback"
	getPresentationsRequestEndpoint    = "/presentations/create"
	handlePresentationResponseEndpoint = "/presentations/handleResponse"
	userInfoEndpoint                   = "/userinfo"
	createRPTenantEndpoint             = "/relyingparties"
)

// errors.
const (
	invalidRequestErrMsg = "invalid request"
)

const (
	// didexhange protocol service is setting the connection record's namespace to "my" on inbound invitations
	connectionRecordNamespace = "my"
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
	CreateOAuth2Client(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error)
}

// OAuth2Config is an OAuth2 client.
type OAuth2Config interface {
	ClientID() string
	AuthCodeURL(string) string
}

// DIDClient is the didexchange Client.
type DIDClient interface {
	RegisterActionEvent(chan<- service.DIDCommAction) error
	RegisterMsgEvent(chan<- service.StateMsg) error
	CreateInvitationWithDID(string, string) (*didexchange.Invitation, error)
}

// PublicDIDCreator creates public DIDs.
type PublicDIDCreator interface {
	Create() (*did.Doc, error)
}

// AriesStorageProvider is the dependency interface for the connection.Recorder.
type AriesStorageProvider interface {
	StorageProvider() ariesstorage.Provider
	TransientStorageProvider() ariesstorage.Provider
}

type consentRequest struct {
	pd      *presentationex.PresentationDefinitions
	cr      *admin.GetConsentRequestOK
	rpDID   string
	rpLabel string
}

type invitationData struct {
	id          string
	userSubject string
	rpPublicDID string
	rpPeerDID   string
}

// New returns CreateCredential instance.
func New(config *Config) (*Operation, error) {
	o := &Operation{
		presentationExProvider:  config.PresentationExProvider,
		hydra:                   config.Hydra,
		oidc:                    config.OIDC,
		oauth2Config:            config.OAuth2Config,
		oidcStates:              make(map[string]*models.LoginRequest),
		consentRequests:         make(map[string]*consentRequest),
		uiEndpoint:              config.UIEndpoint,
		didClient:               config.DIDExchClient,
		didActions:              make(chan service.DIDCommAction),
		didStateMsgs:            make(chan service.StateMsg),
		transientInvitationData: make(map[string]*invitationData),
		publicDIDCreator:        config.PublicDIDCreator,
	}

	err := o.didClient.RegisterActionEvent(o.didActions)
	if err != nil {
		return nil, fmt.Errorf("failed to register listener for action events on didexchange client : %w", err)
	}

	err = o.didClient.RegisterMsgEvent(o.didStateMsgs)
	if err != nil {
		return nil, fmt.Errorf("failed to register listener for state msgs on didexchange client : %w", err)
	}

	o.rpStore, err = rp.New(config.Store)
	if err != nil {
		return nil, fmt.Errorf("failed to open relying party store : %w", err)
	}

	o.connections, err = connection.NewRecorder(config.AriesStorageProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create a connection recorder : %w", err)
	}

	go o.listenForIncomingConnections()

	go o.listenForConnectionCompleteEvents()

	return o, nil
}

// Config defines configuration for rp operations.
type Config struct {
	PresentationExProvider presentationExProvider
	Hydra                  Hydra
	OIDC                   func(string, context.Context) (*oidc.IDToken, error)
	OAuth2Config           OAuth2Config
	UIEndpoint             string
	DIDExchClient          DIDClient
	Store                  storage.Provider
	PublicDIDCreator       PublicDIDCreator
	AriesStorageProvider   AriesStorageProvider
}

// TODO implement an eviction strategy for Operation.oidcStates and OIDC.consentRequests
//  https://github.com/trustbloc/edge-adapter/issues/29

// Operation defines handlers for rp operations.
type Operation struct {
	presentationExProvider  presentationExProvider
	hydra                   Hydra
	oidc                    func(string, context.Context) (*oidc.IDToken, error)
	oauth2Config            OAuth2Config
	oidcStates              map[string]*models.LoginRequest
	oidcStateLock           sync.Mutex
	consentRequests         map[string]*consentRequest
	presDefsLock            sync.Mutex
	uiEndpoint              string
	didClient               DIDClient
	didActions              chan service.DIDCommAction
	didStateMsgs            chan service.StateMsg
	invLock                 sync.RWMutex
	transientInvitationData map[string]*invitationData
	rpStore                 *rp.Store
	publicDIDCreator        PublicDIDCreator
	connections             *connection.Recorder
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(hydraLoginEndpoint, http.MethodGet, o.hydraLoginHandlerIterOne),
		support.NewHTTPHandler(hydraConsentEndpoint, http.MethodGet, o.hydraConsentHandler),
		support.NewHTTPHandler(OIDCCallbackEndpoint, http.MethodGet, o.oidcCallbackHandler),
		support.NewHTTPHandler(getPresentationsRequestEndpoint, http.MethodGet, o.getPresentationsRequest),
		support.NewHTTPHandler(handlePresentationResponseEndpoint, http.MethodPost, o.chapiResponseHandler),
		support.NewHTTPHandler(userInfoEndpoint, http.MethodGet, o.userInfoHandler),
		support.NewHTTPHandler(createRPTenantEndpoint, http.MethodPost, o.createRPTenant),
	}
}

//nolint:funlen
func (o *Operation) hydraLoginHandlerIterOne(w http.ResponseWriter, r *http.Request) {
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

	tenant, err := o.rpStore.GetRP(login.GetPayload().Client.ClientID)
	if err != nil {
		msg := fmt.Sprintf("failed to fetch the rp tenant from the database : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	_, err = o.rpStore.GetUserConnection(login.GetPayload().Client.ClientID, login.GetPayload().Subject)
	if err != nil && !errors.Is(err, storage.ErrValueNotFound) {
		msg := fmt.Sprintf("failed to query rp user connections : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	if errors.Is(err, storage.ErrValueNotFound) {
		err = o.rpStore.SaveUserConnection(&rp.UserConnection{
			User: &rp.User{
				Subject: login.GetPayload().Subject,
			},
			RP: &rp.Tenant{
				ClientID:  tenant.ClientID,
				PublicDID: tenant.PublicDID,
				Label:     tenant.Label,
			},
			Request: &rp.DataRequest{
				Scope: login.GetPayload().RequestedScope,
			},
		})
		if err != nil {
			msg := fmt.Sprintf("failed to save rp user connection to the databse : %s", err)
			logger.Errorf(msg)
			commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

			return
		}
	}

	accept := admin.NewAcceptLoginRequestParams()

	accept.SetLoginChallenge(login.GetPayload().Challenge)
	accept.SetBody(&models.AcceptLoginRequest{
		Subject: &login.GetPayload().Subject,
	})

	loginResponse, err := o.hydra.AcceptLoginRequest(accept)
	if err != nil {
		msg := fmt.Sprintf("failed to accept login request : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	http.Redirect(w, r, loginResponse.GetPayload().RedirectTo, http.StatusFound)
	logger.Debugf("redirected to: %s", loginResponse.GetPayload().RedirectTo)
}

// Hydra redirects the user here in the authentication phase.
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

func (o *Operation) setInvitationData(i *invitationData) {
	o.invLock.Lock()
	defer o.invLock.Unlock()

	o.transientInvitationData[i.id] = i
}

func (o *Operation) getAndUnsetInvitationData(id string) *invitationData {
	o.invLock.Lock()
	defer o.invLock.Unlock()

	i := o.transientInvitationData[id]
	delete(o.transientInvitationData, id)

	return i
}

func (o *Operation) peekInvitationData(id string) *invitationData {
	o.invLock.Lock()
	defer o.invLock.Unlock()

	return o.transientInvitationData[id]
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

	err = o.saveUserAndRequest(login, idToken.Subject)
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

func (o *Operation) saveUserAndRequest(login *models.LoginRequest, sub string) error {
	rpData, err := o.rpStore.GetRP(login.Client.ClientID)
	if err != nil {
		return fmt.Errorf("failed to find a relying party with client_id=%s : %w", login.Client.ClientID, err)
	}

	conn := &rp.UserConnection{
		User: &rp.User{
			Subject: sub,
		},
		RP: rpData,
		Request: &rp.DataRequest{
			Scope: login.RequestedScope,
		},
	}

	err = o.rpStore.SaveUserConnection(conn)
	if err != nil {
		return fmt.Errorf("failed to save new rp-user connection : %w", err)
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

	conn, err := o.rpStore.GetUserConnection(consent.GetPayload().Client.ClientID, consent.GetPayload().Subject)
	if err != nil {
		msg := fmt.Sprintf(
			"failed to fetch rp-user connection for clientID=%s userSub=%s : %s",
			consent.GetPayload().Client.ClientID, consent.GetPayload().Subject, err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	handle := url.QueryEscape(uuid.New().String())
	o.setConsentRequest(handle, &consentRequest{
		cr:      consent,
		pd:      presentationDefinition,
		rpDID:   conn.RP.PublicDID,
		rpLabel: conn.RP.Label,
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
func (o *Operation) getPresentationsRequest(rw http.ResponseWriter, req *http.Request) {
	logger.Debugf("getPresentationsRequest request: %s", req.URL.String())

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

	err := o.saveConsentRequest(cr)
	if err != nil {
		logger.Errorf("failed to save consent request: %s", err)
		commhttp.WriteErrorResponse(
			rw, http.StatusInternalServerError, fmt.Sprintf("failed to save consent request : %s", err))

		return
	}

	invitation, err := o.didClient.CreateInvitationWithDID(cr.rpLabel, cr.rpDID)
	if err != nil {
		msg := fmt.Sprintf("failed to create didexchange invitation with DID : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, msg)

		return
	}

	o.setInvitationData(&invitationData{
		id:          invitation.ID,
		userSubject: cr.cr.GetPayload().Subject,
		rpPublicDID: cr.rpDID,
	})

	response := &GetPresentationRequestResponse{
		PD:  cr.pd,
		Inv: invitation,
	}

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponse(rw, response)

	logger.Debugf("wrote response: %+v", response)
}

func (o *Operation) saveConsentRequest(r *consentRequest) error {
	conn, err := o.rpStore.GetUserConnection(r.cr.GetPayload().Client.ClientID, r.cr.GetPayload().Subject)
	if err != nil {
		return fmt.Errorf("failed to fetch rp-user connection : %w", err)
	}

	conn.Request.PD = r.pd

	err = o.rpStore.SaveUserConnection(conn)
	if err != nil {
		return fmt.Errorf("failed to update user-rp connection data : %w", err)
	}

	return nil
}

// Frontend submits the user's presentation for evaluation.
//
// The user may have provided either:
// - all required credentials in a single response, or
// - consent credential + didcomm endpoint where the requested presentations can be obtained, or
// - nothing (an error response?), indicating they cannot satisfy the request.
func (o *Operation) chapiResponseHandler(w http.ResponseWriter, r *http.Request) { //nolint:funlen
	request := &HandleCHAPIResponse{}

	err := json.NewDecoder(r.Body).Decode(request)
	if err != nil {
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, "malformed request")

		return
	}

	invData := o.getAndUnsetInvitationData(request.InvitationID)
	if invData == nil {
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, "stale or invalid invitation ID")

		return
	}

	// TODO save issuer DID VC and user Consent VC https://github.com/trustbloc/edge-adapter/issues/92

	issuerDIDVC, _, err := getCustomCredentials(request.VerifiablePresentation)
	if errors.Is(err, errMalformedCredential) {
		logger.Warnf("malformed credentials : %s", err)
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, "malformed credentials")

		return
	}

	if err != nil {
		msg := fmt.Sprintf("failed to parse custom credentials : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	diddocBytes, err := base64.URLEncoding.DecodeString(issuerDIDVC.Subject.DIDDoc)
	if err != nil {
		msg := fmt.Sprintf("failed to decode did document : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, msg)

		return
	}

	doc, err := did.ParseDocument(diddocBytes)
	if err != nil {
		msg := fmt.Sprintf("failed to parse did document : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, msg)

		return
	}

	dest, err := service.CreateDestination(doc)
	if err != nil {
		msg := fmt.Sprintf("failed to create didcomm destination : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, msg)

		return
	}

	// TODO Issuer's label on the connection record https://github.com/trustbloc/edge-adapter/issues/93
	err = o.connections.SaveConnectionRecord(&connection.Record{
		ConnectionID:    uuid.New().String(),
		State:           didexchangesvc.StateIDCompleted,
		ThreadID:        uuid.New().String(),
		ParentThreadID:  invData.id,
		TheirLabel:      "",
		TheirDID:        doc.ID,
		MyDID:           invData.rpPeerDID,
		ServiceEndPoint: dest.ServiceEndpoint,
		RecipientKeys:   dest.RecipientKeys,
		RoutingKeys:     dest.RoutingKeys,
		InvitationID:    invData.id,
		InvitationDID:   invData.rpPublicDID,
		Implicit:        false,
		Namespace:       connectionRecordNamespace,
	})
	if err != nil {
		msg := fmt.Sprintf("failed to save connection record : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	// TODO send request-presentation to issuer, validate response against presentation-definitions,
	//  build response object for RP, accept the consent request at hydra (include response object),
	//  respond with a redirect URL to hydra
	testResponse(w)
}

// RP requests user data.
func (o *Operation) userInfoHandler(w http.ResponseWriter, _ *http.Request) {
	// TODO introspect RP's access_token (Authorization request header) with hydra and validate.
	//  Load VPs related to the user and map them to a normal id_token and reply with that.
	testResponse(w)
}

func (o *Operation) listenForIncomingConnections() {
	for action := range o.didActions {
		if action.Message.Type() == didexchange.RequestMsgType {
			// TODO submit to worker pool?
			o.handleIncomingDIDExchangeRequestAction(action)
			continue
		}

		logger.Warnf("stopping action for unsupported didexchange action message type %s", action.Message.Type())
		action.Stop(nil)
	}
}

// We accept incoming did-exchange requests on the following conditions if the request
// has a parent invitation ID found in our transient store.
func (o *Operation) handleIncomingDIDExchangeRequestAction(action service.DIDCommAction) {
	invitation := o.peekInvitationData(action.Message.ParentThreadID())
	if invitation == nil {
		action.Stop(fmt.Errorf("no such invitation with id %s", action.Message.ParentThreadID()))

		return
	}

	action.Continue(nil)
}

// TODO Capture the RP's peer DID when the connection with the user is established
//  https://github.com/trustbloc/edge-adapter/issues/94
func (o *Operation) listenForConnectionCompleteEvents() {
	for msg := range o.didStateMsgs {
		if msg.Type != service.PostState || msg.StateID != didexchangesvc.StateIDCompleted {
			continue
		}
	}
}

func testResponse(w io.Writer) {
	_, err := w.Write([]byte("OK"))
	if err != nil {
		fmt.Printf("error writing test response: %s", err.Error())
	}
}

//nolint:funlen
func (o *Operation) createRPTenant(w http.ResponseWriter, r *http.Request) {
	request := &CreateRPTenantRequest{}

	err := json.NewDecoder(r.Body).Decode(request)
	if err != nil {
		msg := fmt.Sprintf("failed to decode request: %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, msg)

		return
	}

	if request.Label == "" {
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, "missing required parameters")

		return
	}

	req := admin.NewCreateOAuth2ClientParams()
	req.SetBody(&models.OAuth2Client{
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code", "id_token"},
		Scope:         "CreditCardStatement",
	})

	created, err := o.hydra.CreateOAuth2Client(req)
	if err != nil {
		msg := fmt.Sprintf("failed to create oauth2 client at hydra : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	_, err = o.rpStore.GetRP(created.Payload.ClientID)
	if !errors.Is(err, storage.ErrValueNotFound) {
		msg := fmt.Sprintf(
			"either failed to query rp store or rp tenant with clientID=%s already exists", created.Payload.ClientID)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	publicDID, err := o.publicDIDCreator.Create()
	if err != nil {
		msg := fmt.Sprintf("failed to create public did : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	// RP not found - we're good to go
	err = o.rpStore.SaveRP(&rp.Tenant{
		ClientID:  created.Payload.ClientID,
		PublicDID: publicDID.ID,
		Label:     request.Label,
	})
	if err != nil {
		msg := fmt.Sprintf("failed to save relying party : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	w.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(w, &CreateRPTenantResponse{
		ClientID:     created.Payload.ClientID,
		ClientSecret: created.Payload.ClientSecret,
		PublicDID:    publicDID.ID,
	})
}
