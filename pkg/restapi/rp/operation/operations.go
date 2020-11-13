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
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	didexchangesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	mediatorsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	"github.com/trustbloc/edge-adapter/pkg/aries/message"
	"github.com/trustbloc/edge-adapter/pkg/crypto"
	"github.com/trustbloc/edge-adapter/pkg/db/rp"
	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
	"github.com/trustbloc/edge-adapter/pkg/presexch"
	commhttp "github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/http"
	"github.com/trustbloc/edge-adapter/pkg/route"
	"github.com/trustbloc/edge-adapter/pkg/vc"
)

// API endpoints.
const (
	hydraLoginEndpoint                 = "/login"
	hydraConsentEndpoint               = "/consent"
	OIDCCallbackEndpoint               = "/callback"
	getPresentationsRequestEndpoint    = "/presentations/create"
	handlePresentationResponseEndpoint = "/presentations/handleResponse"
	getPresentationResultEndpoint      = "/presentations/result"
	userInfoEndpoint                   = "/userinfo"
	createRPTenantEndpoint             = "/relyingparties"
)

// errors.
const (
	invalidRequestErrMsg = "invalid request"
)

const (
	// TODO define present-proof V2 formats for did uris, presentation_definition, presentation_submission,
	//  and consentVC: https://github.com/trustbloc/edge-adapter/issues/106
	consentVCAttachmentFormat = "trustbloc/UserConsentVerifiableCredential@0.1.0"

	transientStoreName   = "rpadapter_trx"
	persistenceStoreName = "rpadapter_pst"
)

// Msg svc constants.
const (
	msgTypeBaseURI = "https://trustbloc.dev/adapter/1.0"
	didDocReq      = msgTypeBaseURI + "/diddoc-req"
	didDocResp     = msgTypeBaseURI + "/diddoc-resp"
)

var logger = log.New("edge-adapter/rp-operations")

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type presentationExProvider interface {
	Create(scopes []string) (*presexch.PresentationDefinitions, error)
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

// OOBClient is the aries framework OutOfBand client.
type OOBClient interface {
	CreateInvitation([]string, ...outofband.MessageOption) (*outofband.Invitation, error)
}

// DIDClient is the didexchange Client.
type DIDClient interface {
	RegisterActionEvent(chan<- service.DIDCommAction) error
	RegisterMsgEvent(chan<- service.StateMsg) error
	CreateConnection(string, *did.Doc, ...didexchange.ConnectionOption) (string, error)
}

// PresentProofClient is the aries framework's presentproof.Client.
type PresentProofClient interface {
	service.Event
	SendRequestPresentation(*presentproof.RequestPresentation, string, string) (string, error)
}

// PublicDIDCreator creates public DIDs.
type PublicDIDCreator interface {
	Create() (*did.Doc, error)
}

type routeService interface {
	GetDIDDoc(connID string, requiresBlindedRoute bool) (*did.Doc, error)
}

type connectionRecorder interface {
	GetConnectionIDByDIDs(string, string) (string, error)
	GetConnectionRecord(id string) (*connection.Record, error)
}

// GovernanceProvider governance provider.
type GovernanceProvider interface {
	IssueCredential(didID, profileID string) ([]byte, error)
	GetCredential(profileID string) ([]byte, error)
}

// AriesContextProvider is the dependency interface for the connection.Recorder.
type AriesContextProvider interface {
	StorageProvider() ariesstorage.Provider
	ProtocolStateStorageProvider() ariesstorage.Provider
	VDRegistry() vdrapi.Registry
	KMS() kms.KeyManager
	Crypto() ariescrypto.Crypto
	Service(id string) (interface{}, error)
	ServiceEndpoint() string
}

// Storage config.
type Storage struct {
	Persistent storage.Provider
	Transient  storage.Provider
}

// context active in the consent phase all the way up to sending the CHAPI request.
type consentRequestCtx struct {
	InvitationID  string
	PD            *presexch.PresentationDefinitions
	CR            *admin.GetConsentRequestOK
	UserDID       string
	RPPublicDID   string
	ConnectionID  string
	RPPairwiseDID string
	RPLabel       string
	UserData      *userDataCollection
}

type userDataCollection struct {
	Local  map[string][]byte
	Remote map[string]string
}

// New returns CreateCredential instance.
func New(config *Config) (*Operation, error) { // nolint:funlen
	o := &Operation{
		presentationExProvider: config.PresentationExProvider,
		hydra:                  config.Hydra,
		oidc:                   config.OIDC,
		oauth2Config:           config.OAuth2Config,
		oidcStates:             make(map[string]*models.LoginRequest),
		uiEndpoint:             config.UIEndpoint,
		oobClient:              config.OOBClient,
		didClient:              config.DIDExchClient,
		didActions:             make(chan service.DIDCommAction),
		didStateMsgs:           make(chan service.StateMsg),
		publicDIDCreator:       config.PublicDIDCreator,
		ppClient:               config.PresentProofClient,
		ppActions:              make(chan service.DIDCommAction),
		vdrReg:                 config.AriesContextProvider.VDRegistry(),
		governanceProvider:     config.GovernanceProvider,
		km:                     config.AriesContextProvider.KMS(),
		ariesCrypto:            config.AriesContextProvider.Crypto(),
		messenger:              config.AriesMessenger,
	}

	err := o.didClient.RegisterActionEvent(o.didActions)
	if err != nil {
		return nil, fmt.Errorf("failed to register listener for action events on didexchange client : %w", err)
	}

	err = o.didClient.RegisterMsgEvent(o.didStateMsgs)
	if err != nil {
		return nil, fmt.Errorf("failed to register listener for state msgs on didexchange client : %w", err)
	}

	o.rpStore, err = rp.New(config.Storage.Persistent)
	if err != nil {
		return nil, fmt.Errorf("failed to open relying party store : %w", err)
	}

	o.connections, err = connection.NewRecorder(config.AriesContextProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create a connection recorder : %w", err)
	}

	err = o.ppClient.RegisterActionEvent(o.ppActions)
	if err != nil {
		return nil, fmt.Errorf("failed to register listener for action events on present proof client : %w", err)
	}

	o.transientStore, err = transientStore(config.Storage.Transient)
	if err != nil {
		return nil, fmt.Errorf("failed to open transient store : %w", err)
	}

	o.persistenceStore, err = persistenceStore(config.Storage.Persistent)
	if err != nil {
		return nil, fmt.Errorf("failed to open persistence store : %w", err)
	}

	o.routeSvc, err = createRouteSvc(config, o.connections)
	if err != nil {
		return nil, fmt.Errorf("create route message service : %w", err)
	}

	go o.listenForIncomingConnections()

	go o.listenForConnectionCompleteEvents()

	go o.listenForIssuerResponses()

	msgCh := make(chan message.Msg, 1)

	err = config.MsgRegistrar.Register(
		message.NewMsgSvc("rp-diddoc-req", didDocReq, msgCh),
	)
	if err != nil {
		return nil, fmt.Errorf("message service client: %w", err)
	}

	go o.didCommMsgListener(msgCh)

	return o, nil
}

// Config defines configuration for rp operations.
type Config struct {
	PresentationExProvider presentationExProvider
	Hydra                  Hydra
	OIDC                   func(string, context.Context) (*oidc.IDToken, error)
	OAuth2Config           OAuth2Config
	UIEndpoint             string
	OOBClient              OOBClient
	DIDExchClient          DIDClient
	PublicDIDCreator       PublicDIDCreator
	AriesContextProvider   AriesContextProvider
	PresentProofClient     PresentProofClient
	Storage                *Storage
	GovernanceProvider     GovernanceProvider
	AriesMessenger         service.Messenger
	MsgRegistrar           *msghandler.Registrar
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
	uiEndpoint             string
	oobClient              OOBClient
	didClient              DIDClient
	didActions             chan service.DIDCommAction
	didStateMsgs           chan service.StateMsg
	rpStore                *rp.Store
	publicDIDCreator       PublicDIDCreator
	connections            connectionRecorder
	ppClient               PresentProofClient
	ppActions              chan service.DIDCommAction
	vdrReg                 vdrapi.Registry
	transientStore         storage.Store
	persistenceStore       storage.Store
	governanceProvider     GovernanceProvider
	km                     kms.KeyManager
	ariesCrypto            ariescrypto.Crypto
	routeSvc               routeService
	messenger              service.Messenger
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
		support.NewHTTPHandler(getPresentationResultEndpoint, http.MethodGet, o.getPresentationResponseResultHandler),
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

	subject := login.Payload.Subject

	if subject == "" {
		// subject is empty when Hydra cannot determine the user subject for any number of reasons,
		// so for now we set it ourselves.
		// This value should be handed to us by the OIDC provider once we're integrated with it.
		subject = uuid.New().String()
	}

	_, err = o.rpStore.GetUserConnection(login.GetPayload().Client.ClientID, subject)
	if err != nil && !errors.Is(err, storage.ErrValueNotFound) {
		msg := fmt.Sprintf("failed to query rp user connections : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	if errors.Is(err, storage.ErrValueNotFound) {
		err = o.rpStore.SaveUserConnection(&rp.UserConnection{
			User: &rp.User{
				Subject: subject,
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
		Subject: &subject,
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
func (o *Operation) hydraConsentHandler(w http.ResponseWriter, r *http.Request) { // nolint:funlen
	logger.Debugf("hydraConsentHandler request: " + r.URL.String())

	challenge := r.URL.Query().Get("consent_challenge")
	if challenge == "" {
		handleError(w, http.StatusBadRequest, "missing consent_challenge")

		return
	}

	req := admin.NewGetConsentRequestParamsWithContext(r.Context())
	req.SetConsentChallenge(challenge)

	consent, err := o.hydra.GetConsentRequest(req)
	if err != nil {
		handleError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get fetch consent request from hydra : %s", err))

		return
	}

	if consent.GetPayload().Skip {
		o.skipConsentScreen(w, r, consent)

		return
	}

	presentationDefinition, err := o.presentationExProvider.Create(removeOIDCScope(consent.GetPayload().RequestedScope))
	if err != nil {
		handleError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create the presentation definition : %s", err))

		return
	}

	conn, err := o.rpStore.GetUserConnection(consent.GetPayload().Client.ClientID, consent.GetPayload().Subject)
	if err != nil {
		handleError(w, http.StatusInternalServerError, fmt.Sprintf(
			"failed to fetch rp-user connection for clientID=%s userSub=%s : %s",
			consent.GetPayload().Client.ClientID, consent.GetPayload().Subject, err))

		return
	}

	handle := url.QueryEscape(uuid.New().String())

	err = newTransientStorage(o.transientStore).Put(handle, &consentRequestCtx{
		CR:          consent,
		PD:          presentationDefinition,
		RPPublicDID: conn.RP.PublicDID,
		RPLabel:     conn.RP.Label,
	})
	if err != nil {
		handleError(w, http.StatusInternalServerError, fmt.Sprintf("failed to write to transient storage : %s", err))

		return
	}

	redirectURL := fmt.Sprintf("%s?h=%s", o.uiEndpoint, handle)

	http.Redirect(w, r, redirectURL, http.StatusFound)
	logger.Debugf("redirected to: %s", redirectURL)
}

func (o *Operation) skipConsentScreen(w http.ResponseWriter, r *http.Request, consent *admin.GetConsentRequestOK) {
	logger.Debugf("skipping consent screen")

	params := admin.NewAcceptConsentRequestParamsWithContext(r.Context())

	params.SetConsentChallenge(consent.GetPayload().Challenge)

	accepted, err := o.hydra.AcceptConsentRequest(params)
	if err != nil {
		handleError(w, http.StatusInternalServerError,
			fmt.Sprintf("hydra failed to accept consent request at hydra: %s", err))

		return
	}

	http.Redirect(w, r, accepted.GetPayload().RedirectTo, http.StatusFound)
	logger.Debugf("redirected to: %s", accepted.GetPayload().RedirectTo)
}

// Frontend requests to create presentation definition.
func (o *Operation) getPresentationsRequest(w http.ResponseWriter, r *http.Request) { //nolint:funlen
	logger.Debugf("getPresentationsRequest request: %s", r.URL.String())

	// get the request
	handle := r.URL.Query().Get("h")
	if handle == "" {
		handleError(w, http.StatusBadRequest, "missing handle for presentation definition")

		return
	}

	cr, err := newTransientStorage(o.transientStore).GetConsentRequest(handle)
	if err != nil {
		handleError(w, http.StatusBadRequest,
			fmt.Sprintf("unrecognized handle for presentation definition: %s", handle))

		return
	}

	err = o.updateUserConnection(cr)
	if err != nil {
		logger.Errorf("failed to save consent request: %s", err)
		commhttp.WriteErrorResponse(
			w, http.StatusInternalServerError, fmt.Sprintf("failed to save consent request : %s", err))

		return
	}

	invitation, err := o.oobClient.CreateInvitation(
		[]string{didexchangesvc.PIURI},
		outofband.WithLabel(cr.RPLabel),
		outofband.WithServices(cr.RPPublicDID),
	)
	if err != nil {
		handleError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create didcomm invitation with DID : %s", err))

		return
	}

	cr.InvitationID = invitation.ID

	// TODO delete transient data: https://github.com/trustbloc/edge-adapter/issues/255
	err = newTransientStorage(o.transientStore).Put(invitation.ID, cr)
	if err != nil {
		handleError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to update consentRequestCtx in transient store : %s", err))

		return
	}

	var governanceVC []byte

	if o.governanceProvider != nil {
		var err error
		governanceVC, err = o.governanceProvider.GetCredential(cr.CR.GetPayload().Client.ClientID)

		if err != nil {
			handleError(w, http.StatusInternalServerError,
				fmt.Sprintf("error retrieving governance vc : %s", err))

			return
		}
	}

	response := &GetPresentationRequestResponse{
		PD:          cr.PD,
		Inv:         invitation,
		Credentials: []json.RawMessage{governanceVC},
	}

	w.WriteHeader(http.StatusOK)
	commhttp.WriteResponse(w, response)

	logger.Debugf("wrote response: %+v", response)
}

func (o *Operation) updateUserConnection(r *consentRequestCtx) error {
	conn, err := o.rpStore.GetUserConnection(r.CR.GetPayload().Client.ClientID, r.CR.GetPayload().Subject)
	if err != nil {
		return fmt.Errorf("failed to fetch rp-user connection : %w", err)
	}

	conn.Request.PD = r.PD

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
func (o *Operation) chapiResponseHandler(w http.ResponseWriter, r *http.Request) { //nolint:funlen,gocyclo
	request := &HandleCHAPIResponse{}

	err := json.NewDecoder(r.Body).Decode(request)
	if err != nil {
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, "malformed request")

		return
	}

	crCtx, err := newTransientStorage(o.transientStore).GetConsentRequest(request.InvitationID)
	if errors.Is(err, storage.ErrValueNotFound) {
		handleError(w, http.StatusBadRequest, "stale or invalid invitation ID")

		return
	}

	if err != nil {
		handleError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to read from the transient store : %s", err))

		return
	}

	// TODO save user Consent VC https://github.com/trustbloc/edge-adapter/issues/92
	// TODO validate the user consent credential (expected rp and user DIDs, etc.)

	local, remote, err := parseWalletResponse(crCtx.PD, o.vdrReg, request.VerifiablePresentation)
	if err != nil {
		if errors.Is(err, errInvalidCredential) {
			handleError(w, http.StatusBadRequest, fmt.Sprintf("malformed credentials: %s", err.Error()))
		} else {
			handleError(w, http.StatusInternalServerError, fmt.Sprintf("failed to parse credentials : %s", err.Error()))
		}

		return
	}

	localMarshalled, err := marshalCreds(local)
	if err != nil {
		handleError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal local credentials: %s", err.Error()))

		return
	}

	basket := &userDataCollection{
		Local:  localMarshalled,
		Remote: make(map[string]string),
	}

	for descriptorID, authz := range remote {
		// TODO do not send multiple requests for each scope in an authz cred:
		//  https://github.com/trustbloc/edge-adapter/issues/253
		thid, remoteErr := o.requestRemoteCredential(authz, crCtx)
		if remoteErr != nil {
			if errors.Is(remoteErr, errInvalidCredential) {
				handleError(w, http.StatusBadRequest, remoteErr.Error())
			} else {
				handleError(w, http.StatusInternalServerError, remoteErr.Error())
			}

			return
		}

		basket.Remote[descriptorID] = thid
	}

	crCtx.UserData = basket

	err = newTransientStorage(o.transientStore).Put(crCtx.InvitationID, crCtx)
	if err != nil {
		handleError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to save user data basket to store: %s", err.Error()))

		return
	}

	w.WriteHeader(http.StatusAccepted)

	_, err = w.Write([]byte("OK"))
	if err != nil {
		logger.Errorf("failed to write response: %s", err.Error())
	}
}

func (o *Operation) requestRemoteCredential(authz *verifiable.Credential,
	crCtx *consentRequestCtx) (threadID string, err error) {
	sub, err := vc.AuthZSubject(authz)
	if err != nil {
		return "", fmt.Errorf("%w: failed to parse authz subject: %s", errInvalidCredential, err.Error())
	}

	issuerDID, err := did.ParseDocument(sub.IssuerDIDDoc.Doc)
	if err != nil {
		return "", fmt.Errorf("%w: failed to parse issuer did document: %s", errInvalidCredential, err.Error())
	}

	val, err := o.transientStore.Get(getConnectionToAuthZDIDMappingDBKey(crCtx.ConnectionID))
	if err != nil {
		return "", fmt.Errorf("get connection-authzDID mapping : %w", err)
	}

	rpAuthZDID := string(val)
	if rpAuthZDID != sub.RPDIDDoc.ID {
		return "", fmt.Errorf("rp did '%s' in authz doesn't match the expected rp did '%s'",
			sub.RPDIDDoc.ID, rpAuthZDID)
	}

	// TODO Issuer's label on the connection record https://github.com/trustbloc/edge-adapter/issues/93
	_, err = o.didClient.CreateConnection(rpAuthZDID, issuerDID)
	if err != nil {
		return "", fmt.Errorf(
			"failed to create didcomm connection between %s and %s: %w",
			rpAuthZDID, issuerDID.ID, err)
	}

	vpBytes, err := o.toMarshalledVP(authz, rpAuthZDID)
	if err != nil {
		return "", fmt.Errorf("failed to convert authz credential to verifiable presentation: %w", err)
	}

	attachID := uuid.New().String()

	thid, err := o.ppClient.SendRequestPresentation(&presentproof.RequestPresentation{
		Formats: []presentproofsvc.Format{{
			AttachID: attachID,
			Format:   consentVCAttachmentFormat,
		}},
		RequestPresentationsAttach: []decorator.Attachment{{
			ID:       attachID,
			MimeType: "application/ld+json",
			Data: decorator.AttachmentData{
				Base64: base64.StdEncoding.EncodeToString(vpBytes),
			},
		}},
	}, rpAuthZDID, issuerDID.ID)
	if err != nil {
		return "", fmt.Errorf("failed to send request-presentation: %w", err)
	}

	logger.Debugf("sent request-presentation with threadID=%s", thid)

	return thid, nil
}

// nolint:funlen
func (o *Operation) getPresentationResponseResultHandler(w http.ResponseWriter, r *http.Request) {
	logger.Infof("handling request")

	handle := r.URL.Query().Get("h")
	if handle == "" {
		handleError(w, http.StatusBadRequest, "missing handle for presentation definition")

		return
	}

	crCtx, err := newTransientStorage(o.transientStore).GetConsentRequest(handle)
	if err != nil {
		handleError(w, http.StatusBadRequest,
			fmt.Sprintf("unrecognized handle for presentation definition: %s", handle))

		return
	}

	// TODO validate all credentials against presentation definitions:
	//  https://github.com/trustbloc/edge-adapter/issues/108
	userData, err := o.collectedUserData(crCtx.UserData)
	if err != nil {
		// TODO we should distinguish between classes of errors here
		//  (timeout, not all responses have been received, generic error):
		//  https://github.com/trustbloc/edge-adapter/issues/109
		handleError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to lookup collected credentials: %s", err.Error()))

		return
	}

	// TODO delete transient data: https://github.com/trustbloc/edge-adapter/issues/255
	rpData, err := transformUserData(userData) // userData: map of all descriptorID -> credentials
	if err != nil {
		handleError(w, http.StatusInternalServerError, fmt.Sprintf("failed to map VCs into RP object : %s", err))

		return
	}

	// TODO support selective disclosure
	accept := &admin.AcceptConsentRequestParams{}
	accept.SetContext(r.Context())
	accept.SetConsentChallenge(crCtx.CR.Payload.Challenge)
	accept.SetBody(&models.AcceptConsentRequest{
		GrantAccessTokenAudience: crCtx.CR.Payload.RequestedAccessTokenAudience,
		GrantScope:               crCtx.CR.Payload.RequestedScope,
		HandledAt:                models.NullTime(time.Now()),
		Remember:                 true, // TODO support user choice whether consent should be remembered
		Session: &models.ConsentRequestSession{
			IDToken: rpData,
		},
	})

	resp, err := o.hydra.AcceptConsentRequest(accept)
	if err != nil {
		handleError(w, http.StatusBadGateway, fmt.Sprintf("failed to accept consent request at hydra : %s", err))

		return
	}

	commhttp.WriteResponse(w, &HandleCHAPIResponseResult{
		RedirectURL: resp.Payload.RedirectTo,
	})

	logger.Debugf("redirected user to: %s", resp.Payload.RedirectTo)
}

func (o *Operation) collectedUserData(ref *userDataCollection) (map[string]*verifiable.Credential, error) {
	collected := make(map[string]*verifiable.Credential)

	for descriptorID, rawCred := range ref.Local {
		// credential's proof has been validated upstream in the flow
		cred, err := verifiable.ParseUnverifiedCredential(rawCred)
		if err != nil {
			return nil, fmt.Errorf("failed to parse credential [%s]: %w", rawCred, err)
		}

		collected[descriptorID] = cred
	}

	for descriptorID, thid := range ref.Remote {
		// if thid not found then either we haven't received the response from that issuer,
		//  or there was a generic error accessing the transient store
		bits, err := o.transientStore.Get(thid)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch remote credential for thid %s: %w", thid, err)
		}

		// credential's proof has been validated upstream in the flow
		cred, err := verifiable.ParseUnverifiedCredential(bits)
		if err != nil {
			return nil, fmt.Errorf("failed to parse credential [%s]: %w", bits, err)
		}

		collected[descriptorID] = cred
	}

	return collected, nil
}

func transformUserData(userData map[string]*verifiable.Credential) (map[string]interface{}, error) {
	claimNames := make(map[string]string)
	claimSources := make(map[string]interface{})
	idx := 1

	for scope, cred := range userData {
		raw, err := json.Marshal(cred.Subject)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal user data subject: %w", err)
		}

		data := make([]map[string]interface{}, 0)

		err = json.Unmarshal(raw, &data)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal user data subject: %w", err)
		}

		ref := fmt.Sprintf("src%d", idx)

		claimNames[scope] = ref
		claimSources[ref] = map[string]interface{}{
			"claims": filterJSONLDisms(data[0]),
		}

		idx++
	}

	return map[string]interface{}{
		"_claim_names":   claimNames,
		"_claim_sources": claimSources,
	}, nil
}

func filterJSONLDisms(in map[string]interface{}) map[string]interface{} {
	// TODO filter JSONLD-isms from the credential subject like "@id", "@type", "@context", etc.
	//  https://github.com/trustbloc/edge-adapter/issues/127
	return in
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
	_, err := newTransientStorage(o.transientStore).GetConsentRequest(action.Message.ParentThreadID())
	if errors.Is(err, storage.ErrValueNotFound) {
		msg := fmt.Sprintf("no such context for id %s", action.Message.ParentThreadID())

		logger.Errorf(msg)
		action.Stop(errors.New(msg))

		return
	}

	if err != nil {
		logger.Errorf(
			"failed to fetch consentRequestCtx from transient storage while processing didexchange request pthid %s: %w",
			action.Message.ParentThreadID(), err)

		return
	}

	logger.Debugf("approving didcomm connection from invitation with id: %s", action.Message.ParentThreadID())

	action.Continue(nil)
}

func (o *Operation) listenForConnectionCompleteEvents() { // nolint: gocyclo
	for msg := range o.didStateMsgs {
		if msg.Type != service.PostState || msg.StateID != didexchangesvc.StateIDCompleted {
			continue
		}

		var event didexchange.Event

		switch p := msg.Properties.(type) {
		case didexchange.Event:
			event = p
		default:
			logger.Warnf("failed to cast didexchange event properties")

			continue
		}

		logger.Debugf(
			"received connection complete event for invitationID=%s connectionID=%s",
			event.InvitationID(), event.ConnectionID())

		crCtx, err := newTransientStorage(o.transientStore).GetConsentRequest(event.InvitationID())
		if err != nil {
			logger.Warnf("unable to fetch consentRquestCtx data transient storage: %s", err)

			continue
		}

		record, err := o.connections.GetConnectionRecord(event.ConnectionID())
		if err != nil {
			logger.Errorf("failed to fetch connection record for id=%s : %s", event.ConnectionID(), err)

			continue
		}

		crCtx.RPPairwiseDID = record.MyDID
		crCtx.UserDID = record.TheirDID
		crCtx.ConnectionID = record.ConnectionID

		err = newTransientStorage(o.transientStore).Put(crCtx.InvitationID, crCtx)
		if err != nil {
			logger.Errorf("failed to update invitation data in transient storage : %s", err)
		}

		err = o.persistenceStore.Put(getConnToTenantMappingDBKey(event.ConnectionID()),
			[]byte(crCtx.CR.Payload.Client.ClientID))
		if err != nil {
			logger.Errorf("failed to update connectionID to rp client id : %s", err)
		}

		err = o.messenger.Send(service.NewDIDCommMsgMap(&aries.DIDCommMsg{
			ID:   uuid.New().String(),
			Type: aries.DIDExStateComp,
		}), record.MyDID, record.TheirDID)
		if err != nil {
			logger.Errorf("send didex state complete msg : %s", err)
		}
	}
}

func (o *Operation) listenForIssuerResponses() {
	for action := range o.ppActions {
		if action.Message.Type() != presentproofsvc.PresentationMsgType {
			logger.Debugf("ignoring present-proof message of type: %s", action.Message.Type())

			continue
		}

		err := o.handleIssuerPresentationMsg(action.Message)
		if err != nil {
			logger.Warnf("failed to handle present-proof response : %s", err)
			action.Stop(err)

			continue
		}

		action.Continue(presentproof.WithFriendlyNames(uuid.New().String()))
	}
}

func (o *Operation) didCommMsgListener(ch <-chan message.Msg) {
	for msg := range ch {
		var err error

		var msgMap service.DIDCommMsgMap

		switch msg.DIDCommMsg.Type() {
		case didDocReq:
			msgMap, err = o.handleDIDDocReq(msg)
		default:
			err = fmt.Errorf("unsupported message service type : %s", msg.DIDCommMsg.Type())
		}

		if err != nil {
			msgType := msg.DIDCommMsg.Type()
			if msg.DIDCommMsg.Type() == didDocReq {
				msgType = didDocResp
			}

			msgMap = service.NewDIDCommMsgMap(&ErrorResp{
				ID:   uuid.New().String(),
				Type: msgType,
				Data: &ErrorRespData{ErrorMsg: err.Error()},
			})

			logger.Errorf("msgType=[%s] id=[%s] errMsg=[%s]", msg.DIDCommMsg.Type(), msg.DIDCommMsg.ID(), err.Error())
		}

		err = o.messenger.ReplyTo(msg.DIDCommMsg.ID(), msgMap)
		if err != nil {
			logger.Errorf("sendReply : msgType=[%s] id=[%s] errMsg=[%s]",
				msg.DIDCommMsg.Type(), msg.DIDCommMsg.ID(), err.Error())

			continue
		}

		logger.Infof("msgType=[%s] id=[%s] msg=[%s]", msg.DIDCommMsg.Type(), msg.DIDCommMsg.ID(), "success")
	}
}

func (o *Operation) handleDIDDocReq(msg message.Msg) (service.DIDCommMsgMap, error) {
	connID, err := o.connections.GetConnectionIDByDIDs(msg.MyDID, msg.TheirDID)
	if err != nil {
		return nil, fmt.Errorf("get connection by DIDs : %w", err)
	}

	cID, err := o.persistenceStore.Get(getConnToTenantMappingDBKey(connID))
	if err != nil {
		return nil, fmt.Errorf("get connection to rp tenant mapping : %w", err)
	}

	rpTenant, err := o.rpStore.GetRP(string(cID))
	if err != nil {
		return nil, fmt.Errorf("get rp tenant data : %w", err)
	}

	newDidDoc, err := o.routeSvc.GetDIDDoc(connID, rpTenant.RequiresBlindedRoute)
	if err != nil {
		return nil, fmt.Errorf("create new peer did : %w", err)
	}

	docBytes, err := newDidDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("marshal did doc : %w", err)
	}

	err = o.transientStore.Put(getConnectionToAuthZDIDMappingDBKey(connID), []byte(newDidDoc.ID))
	if err != nil {
		return nil, fmt.Errorf("save connection-authzDID mapping  : %w", err)
	}

	return service.NewDIDCommMsgMap(&DIDDocResp{
		ID:   uuid.New().String(),
		Type: didDocResp,
		Data: &DIDDocRespData{
			DIDDoc: docBytes,
		},
	}), nil
}

func (o *Operation) handleIssuerPresentationMsg(msg service.DIDCommMsg) error {
	logger.Infof("handling issuer presentation msg")

	thid, err := msg.ThreadID()
	if err != nil {
		return fmt.Errorf("failed to extract threadID from didcomm msg : %w", err)
	}

	presentation := &presentproof.Presentation{}

	err = msg.Decode(presentation)
	if err != nil {
		return fmt.Errorf("failed to decode present-proof message for threadID=%s: %w", thid, err)
	}

	logger.Debugf("handling present-proof message: %+v", presentation)

	userData, err := parseIssuerResponse(presentation, o.vdrReg)
	if err != nil {
		return fmt.Errorf("failed to parse verifiable presentation for threadID=%s: %w", thid, err)
	}

	bits, err := json.Marshal(userData)
	if err != nil {
		return fmt.Errorf("failed to marshal remote credential from issuer: %w", err)
	}

	err = o.transientStore.Put(thid, bits)
	if err != nil {
		return fmt.Errorf("failed to save remote credential to store: %w", err)
	}

	return nil
}

func testResponse(w io.Writer) {
	_, err := w.Write([]byte("OK"))
	if err != nil {
		fmt.Printf("error writing test response: %s", err.Error())
	}
}

//nolint:funlen,gocyclo
func (o *Operation) createRPTenant(w http.ResponseWriter, r *http.Request) {
	request := &CreateRPTenantRequest{}

	err := json.NewDecoder(r.Body).Decode(request)
	if err != nil {
		msg := fmt.Sprintf("failed to decode request: %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, msg)

		return
	}

	if request.Label == "" || request.Callback == "" {
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, "missing required parameters")

		return
	}

	if len(request.Scopes) == 0 {
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, "missing scopes")

		return
	}

	created, err := o.createOAuth2Client(request.Scopes, request.Callback)
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

	if o.governanceProvider != nil {
		_, err = o.governanceProvider.IssueCredential(publicDID.ID, created.Payload.ClientID)
		if err != nil {
			msg := fmt.Sprintf("failed to issue governance vc : %s", err)
			logger.Errorf(msg)
			commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

			return
		}
	}

	// RP not found - we're good to go
	err = o.rpStore.SaveRP(&rp.Tenant{
		ClientID:             created.Payload.ClientID,
		PublicDID:            publicDID.ID,
		Label:                request.Label,
		Scopes:               request.Scopes,
		RequiresBlindedRoute: request.RequiresBlindedRoute,
	})
	if err != nil {
		msg := fmt.Sprintf("failed to save relying party : %s", err)
		logger.Errorf(msg)
		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, msg)

		return
	}

	w.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(w, &CreateRPTenantResponse{
		ClientID:             created.Payload.ClientID,
		ClientSecret:         created.Payload.ClientSecret,
		PublicDID:            publicDID.ID,
		Scopes:               request.Scopes,
		RequiresBlindedRoute: request.RequiresBlindedRoute,
	})
}

func (o *Operation) createOAuth2Client(scopes []string, callback string) (*admin.CreateOAuth2ClientCreated, error) {
	req := admin.NewCreateOAuth2ClientParams()
	req.SetBody(&models.OAuth2Client{
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code", "id_token"},
		Scope:         strings.Join(append(scopes, oidc.ScopeOpenID), " "),
		RedirectUris:  []string{callback},
	})

	return o.hydra.CreateOAuth2Client(req)
}

// TODO add an LD proof that contains the issuer's challenge: https://github.com/trustbloc/edge-adapter/issues/145
func (o *Operation) toMarshalledVP(authZ *verifiable.Credential, signingDID string) ([]byte, error) {
	vp, err := authZ.Presentation()
	if err != nil {
		return nil, fmt.Errorf("failed to convert authz credential to presentation: %w", err)
	}

	rpDIDDoc, err := o.vdrReg.Resolve(signingDID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve rp did %s: %w", signingDID, err)
	}

	verificationMethod, err := crypto.GetVerificationMethodFromDID(rpDIDDoc, did.Authentication)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain a verification method from rp did %s: %w", signingDID, err)
	}

	signedVP, err := crypto.New(o.km, o.ariesCrypto, o.vdrReg).SignPresentation(vp, verificationMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to sign authZ vp with verMethod %s: %w", verificationMethod, err)
	}

	return json.Marshal(signedVP)
}

func removeOIDCScope(scopes []string) []string {
	filtered := make([]string, 0)

	for i := range scopes {
		if scopes[i] != oidc.ScopeOpenID {
			filtered = append(filtered, scopes[i])
		}
	}

	return filtered
}

func transientStore(p storage.Provider) (storage.Store, error) {
	err := p.CreateStore(transientStoreName)
	if err != nil && !errors.Is(err, storage.ErrDuplicateStore) {
		return nil, fmt.Errorf("failed to create transient store : %w", err)
	}

	return p.OpenStore(transientStoreName)
}

func persistenceStore(p storage.Provider) (storage.Store, error) {
	err := p.CreateStore(persistenceStoreName)
	if err != nil && !errors.Is(err, storage.ErrDuplicateStore) {
		return nil, fmt.Errorf("failed to create persistence store : %w", err)
	}

	return p.OpenStore(persistenceStoreName)
}

func handleError(w http.ResponseWriter, statusCode int, msg string) {
	logger.Errorf(msg)
	commhttp.WriteErrorResponse(w, statusCode, msg)
}

func marshalCreds(in map[string]*verifiable.Credential) (map[string][]byte, error) {
	out := make(map[string][]byte, len(in))

	for id, cred := range in {
		bits, err := json.Marshal(cred)
		if err != nil {
			return nil, fmt.Errorf("marshalCreds: failed to marshal vc for descriptorID %s: %w", id, err)
		}

		out[id] = bits
	}

	return out, nil
}

func createRouteSvc(config *Config, connectionLookup connectionRecorder) (routeService, error) {
	s, err := config.AriesContextProvider.Service(mediatorsvc.Coordination)
	if err != nil {
		return nil, fmt.Errorf("mediator service lookup: %s", err)
	}

	mediatorSvc, ok := s.(mediatorsvc.ProtocolService)
	if !ok {
		return nil, errors.New("failed to cast mediator service")
	}

	mediatorClient, err := mediator.New(config.AriesContextProvider)
	if err != nil {
		return nil, err
	}

	routeSvc, err := route.New(&route.Config{
		VDRIRegistry:      config.AriesContextProvider.VDRegistry(),
		AriesMessenger:    config.AriesMessenger,
		MsgRegistrar:      config.MsgRegistrar,
		DIDExchangeClient: config.DIDExchClient,
		MediatorClient:    mediatorClient,
		ServiceEndpoint:   config.AriesContextProvider.ServiceEndpoint(),
		Store:             config.Storage.Transient,
		ConnectionLookup:  connectionLookup,
		MediatorSvc:       mediatorSvc,
	})
	if err != nil {
		return nil, fmt.Errorf("create service : %w", err)
	}

	return routeSvc, nil
}

func getConnectionToAuthZDIDMappingDBKey(connID string) string {
	return "connauthzmap_" + connID
}

func getConnToTenantMappingDBKey(connID string) string {
	return "conntenantmap_" + connID
}
