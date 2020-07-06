/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	issuecredsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
	"github.com/trustbloc/edge-adapter/pkg/profile/issuer"
	commhttp "github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/http"
	issuervc "github.com/trustbloc/edge-adapter/pkg/vc/issuer"
)

const (
	// API endpoints
	issuerBasePath  = "/issuer"
	didCommBasePath = issuerBasePath + "/didcomm"

	profileEndpoint                 = "/profile"
	getProfileEndpoint              = profileEndpoint + "/{id}"
	walletConnectEndpoint           = "/{id}/connect/wallet"
	getCHAPIRequestEndpoint         = didCommBasePath + "/chapi/request"
	validateConnectResponseEndpoint = "/connect/validate"

	// http params
	idPathParam     = "id"
	txnIDQueryParam = "txnID"
	stateQueryParam = "state"
	redirectURLFmt  = "%s?state=%s&token=%s"

	txnStoreName   = "issuer_txn"
	tokenStoreName = "issuer_token"

	// protocol
	didExCompletedState = "completed"

	// DIDConnectCHAPIQueryType CHAPI query type DIDConnect
	DIDConnectCHAPIQueryType = "DIDConnect"
)

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type connections interface {
	GetConnectionIDByDIDs(string, string) (string, error)
	GetConnectionRecord(string) (*connection.Record, error)
}

// Config defines configuration for issuer operations.
type Config struct {
	AriesCtx      aries.CtxProvider
	UIEndpoint    string
	StoreProvider storage.Provider
}

// New returns issuer rest instance.
func New(config *Config) (*Operation, error) {
	didExClient, err := didExchangeClient(config.AriesCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create aries did exchange client : %s", err)
	}

	actionCh := make(chan service.DIDCommAction, 1)

	issueCredClient, err := issueCredentialClient(config.AriesCtx, actionCh)
	if err != nil {
		return nil, fmt.Errorf("failed to create aries issue credential client : %s", err)
	}

	presentProofClient, err := presentProofClient(config.AriesCtx, actionCh)
	if err != nil {
		return nil, fmt.Errorf("failed to create aries present proof client : %s", err)
	}

	p, err := issuer.New(config.StoreProvider)
	if err != nil {
		return nil, err
	}

	txnStore, err := getTxnStore(config.StoreProvider)
	if err != nil {
		return nil, err
	}

	tokenStore, err := getTokenStore(config.StoreProvider)
	if err != nil {
		return nil, err
	}

	connectionLookup, err := connection.NewLookup(config.AriesCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection lookup : %w", err)
	}

	op := &Operation{
		didExClient:        didExClient,
		issueCredClient:    issueCredClient,
		presentProofClient: presentProofClient,
		uiEndpoint:         config.UIEndpoint,
		profileStore:       p,
		txnStore:           txnStore,
		tokenStore:         tokenStore,
		connectionLookup:   connectionLookup,
		vdriRegistry:       config.AriesCtx.VDRIRegistry(),
		serviceEndpoint:    config.AriesCtx.ServiceEndpoint(),
	}

	go op.didCommActionListener(actionCh)

	return op, nil
}

// Operation defines handlers for rp operations.
type Operation struct {
	didExClient        *didexchange.Client
	issueCredClient    *issuecredential.Client
	presentProofClient *presentproof.Client
	uiEndpoint         string
	profileStore       *issuer.Profile
	txnStore           storage.Store
	tokenStore         storage.Store
	connectionLookup   connections
	vdriRegistry       vdri.Registry
	serviceEndpoint    string
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		// profile
		support.NewHTTPHandler(profileEndpoint, http.MethodPost, o.createIssuerProfileHandler),
		support.NewHTTPHandler(getProfileEndpoint, http.MethodGet, o.getIssuerProfileHandler),

		// didcomm
		support.NewHTTPHandler(walletConnectEndpoint, http.MethodGet, o.walletConnectHandler),
		support.NewHTTPHandler(validateConnectResponseEndpoint, http.MethodPost, o.validateWalletResponseHandler),
		support.NewHTTPHandler(getCHAPIRequestEndpoint, http.MethodGet, o.getCHAPIRequestHandler),
	}
}

func (o *Operation) createIssuerProfileHandler(rw http.ResponseWriter, req *http.Request) {
	data := &ProfileDataRequest{}

	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err.Error()))

		return
	}

	created := time.Now().UTC()
	profileData := &issuer.ProfileData{
		ID:                  data.ID,
		Name:                data.Name,
		SupportedVCContexts: data.SupportedVCContexts,
		CallbackURL:         data.CallbackURL,
		CreatedAt:           &created,
	}

	err := o.profileStore.SaveProfile(profileData)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to create profile: %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(rw, profileData)
}

func (o *Operation) getIssuerProfileHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)[idPathParam]

	profile, err := o.profileStore.GetProfile(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	commhttp.WriteResponse(rw, profile)
}

func (o *Operation) walletConnectHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)[idPathParam]

	profile, err := o.profileStore.GetProfile(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	state := req.URL.Query().Get(stateQueryParam)
	if state == "" {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, "failed to get state from the url")

		return
	}

	// store the txn data
	txnID, err := o.createTxn(profile, state)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to create txn : %s", err.Error()))

		return
	}

	http.Redirect(rw, req, o.uiEndpoint+"?"+txnIDQueryParam+"="+txnID, http.StatusFound)
}

func (o *Operation) validateWalletResponseHandler(rw http.ResponseWriter, req *http.Request) { //nolint: funlen
	// get the txnID
	txnID := req.URL.Query().Get(txnIDQueryParam)

	if txnID == "" {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, "failed to get txnID from the url")

		return
	}

	// validate the response
	connectResp := &WalletConnect{}

	if err := json.NewDecoder(req.Body).Decode(&connectResp); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err.Error()))

		return
	}

	// get txnID data from the storage
	txnData, err := o.getTxn(txnID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("txn data not found: %s", err.Error()))

		return
	}

	connectData, err := issuervc.ParseWalletResponse(connectResp.Resp)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to validate presentation: %s", err.Error()))

		return
	}

	conn, err := o.validateAndGetConnection(connectData)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to validate DIDComm connection: %s", err.Error()))

		return
	}

	profile, err := o.profileStore.GetProfile(txnData.IssuerID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("profile not found: %s", err.Error()))

		return
	}

	token := uuid.New().String()

	err = o.tokenStore.Put(conn.ConnectionID, []byte(token))
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to store token mapping: %s", err.Error()))

		return
	}

	redirectURL := fmt.Sprintf(redirectURLFmt, profile.CallbackURL, txnData.State, token)

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponse(rw, &ValidateConnectResp{RedirectURL: redirectURL})
}

func (o *Operation) getCHAPIRequestHandler(rw http.ResponseWriter, req *http.Request) {
	// get the txnID
	txnID := req.URL.Query().Get(txnIDQueryParam)

	if txnID == "" {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, "failed to get txnID from the url")

		return
	}

	// get txnID data from the storage
	txnData, err := o.getTxn(txnID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("txn data not found: %s", err.Error()))

		return
	}

	manifestVC, err := issuervc.CreateManifestCredential(txnData.SupportedVCContexts)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("error creating manifest vc : %s", err.Error()))

		return
	}

	commhttp.WriteResponse(rw, &CHAPIRequest{
		Query:             &CHAPIQuery{Type: DIDConnectCHAPIQueryType},
		DIDCommInvitation: txnData.DIDCommInvitation,
		Manifest:          manifestVC,
	})
}

func (o *Operation) validateAndGetConnection(connectData *issuervc.DIDConnectCredentialSubject) (*connection.Record, error) { // nolint: lll
	connID, err := o.connectionLookup.GetConnectionIDByDIDs(connectData.InviterDID, connectData.InviteeDID)
	if err != nil {
		return nil, fmt.Errorf("connection using DIDs not found: %w", err)
	}

	conn, err := o.connectionLookup.GetConnectionRecord(connID)
	if err != nil {
		return nil, fmt.Errorf("connection using id not found: %w", err)
	}

	// TODO https://github.com/trustbloc/edge-adapter/issues/101 validate the parent thread id with the invitation id

	if conn.State != didExCompletedState {
		return nil, errors.New("connection state is not complete")
	}

	if conn.ThreadID != connectData.ThreadID {
		return nil, errors.New("thread id not found")
	}

	return conn, nil
}

func (o *Operation) createTxn(profile *issuer.ProfileData, state string) (string, error) {
	invitation, err := o.didExClient.CreateInvitation("issuer")
	if err != nil {
		return "", fmt.Errorf("failed to create invitation : %w", err)
	}

	txnID := uuid.New().String()

	// store the txn data
	data := &txnData{
		IssuerID:            profile.ID,
		SupportedVCContexts: profile.SupportedVCContexts,
		State:               state,
		DIDCommInvitation:   invitation,
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	err = o.txnStore.Put(txnID, dataBytes)
	if err != nil {
		return "", err
	}

	return txnID, nil
}

func (o *Operation) getTxn(id string) (*txnData, error) {
	bytes, err := o.txnStore.Get(id)
	if err != nil || bytes == nil {
		return nil, err
	}

	data := &txnData{}

	err = json.Unmarshal(bytes, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func didExchangeClient(ariesCtx aries.CtxProvider) (*didexchange.Client, error) {
	didExClient, err := didexchange.New(ariesCtx)
	if err != nil {
		return nil, err
	}

	actionCh := make(chan service.DIDCommAction, 1)

	err = didExClient.RegisterActionEvent(actionCh)
	if err != nil {
		return nil, err
	}

	// TODO https://github.com/trustbloc/edge-adapter/issues/102 verify connection request before approving
	go service.AutoExecuteActionEvent(actionCh)

	return didExClient, nil
}

func issueCredentialClient(prov issuecredential.Provider, actionCh chan service.DIDCommAction) (*issuecredential.Client, error) { // nolint: lll
	issueCredentialClient, err := issuecredential.New(prov)
	if err != nil {
		return nil, err
	}

	err = issueCredentialClient.RegisterActionEvent(actionCh)
	if err != nil {
		return nil, err
	}

	return issueCredentialClient, nil
}

func presentProofClient(prov presentproof.Provider, actionCh chan service.DIDCommAction) (*presentproof.Client, error) { // nolint: lll
	presentProofClient, err := presentproof.New(prov)
	if err != nil {
		return nil, err
	}

	err = presentProofClient.RegisterActionEvent(actionCh)
	if err != nil {
		return nil, err
	}

	return presentProofClient, nil
}

func (o *Operation) didCommActionListener(ch <-chan service.DIDCommAction) {
	for msg := range ch {
		switch msg.Message.Type() {
		case issuecredsvc.RequestCredentialMsgType:
			err := o.handleRequestCredential(msg)
			if err != nil {
				msg.Stop(fmt.Errorf("handle credential request : %w", err))
			}
		case presentproofsvc.RequestPresentationMsgType:
			o.handleRequestPresentation(msg)
		default:
			msg.Stop(fmt.Errorf("unsupported message type : %s", msg.Message.Type()))
		}
	}
}

func (o *Operation) handleRequestCredential(msg service.DIDCommAction) error {
	// TODO https://github.com/trustbloc/edge-adapter/issues/124 Validate credential request from wallet
	newDidDoc, err := o.vdriRegistry.Create("peer", vdri.WithServiceEndpoint(o.serviceEndpoint))
	if err != nil {
		return err
	}

	docJSON, err := newDidDoc.JSONBytes()
	if err != nil {
		return err
	}

	vc := issuervc.CreateDIDCommInitCredential(docJSON)

	msg.Continue(issuecredential.WithIssueCredential(&issuecredential.IssueCredential{
		CredentialsAttach: []decorator.Attachment{
			{Data: decorator.AttachmentData{JSON: vc}},
		},
	}))

	return nil
}

func (o *Operation) handleRequestPresentation(msg service.DIDCommAction) {
	// TODO https://github.com/trustbloc/edge-adapter/issues/139 validate the presentation request
	msg.Continue(presentproof.WithPresentation(&presentproof.Presentation{
		PresentationsAttach: []decorator.Attachment{{
			Data: decorator.AttachmentData{
				JSON: issuervc.CreatePresentation(),
			},
		}},
	}))
}

func getTxnStore(prov storage.Provider) (storage.Store, error) {
	err := prov.CreateStore(txnStoreName)
	if err != nil && err != storage.ErrDuplicateStore {
		return nil, err
	}

	txnStore, err := prov.OpenStore(txnStoreName)
	if err != nil {
		return nil, err
	}

	return txnStore, nil
}

func getTokenStore(prov storage.Provider) (storage.Store, error) {
	err := prov.CreateStore(tokenStoreName)
	if err != nil && err != storage.ErrDuplicateStore {
		return nil, err
	}

	txnStore, err := prov.OpenStore(tokenStoreName)
	if err != nil {
		return nil, err
	}

	return txnStore, nil
}
