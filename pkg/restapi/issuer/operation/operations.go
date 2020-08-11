/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	issuecredsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	"github.com/trustbloc/edge-adapter/pkg/crypto"
	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
	"github.com/trustbloc/edge-adapter/pkg/profile/issuer"
	commhttp "github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/http"
	adaptervc "github.com/trustbloc/edge-adapter/pkg/vc"
	issuervc "github.com/trustbloc/edge-adapter/pkg/vc/issuer"
)

var logger = log.New("edge-adapter/issuerops")

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

// PublicDIDCreator creates public DIDs.
type PublicDIDCreator interface {
	Create() (*did.Doc, error)
}

// Config defines configuration for issuer operations.
type Config struct {
	AriesCtx         aries.CtxProvider
	UIEndpoint       string
	StoreProvider    storage.Provider
	PublicDIDCreator PublicDIDCreator
	TLSConfig        *tls.Config
}

// New returns issuer rest instance.
func New(config *Config) (*Operation, error) { // nolint:funlen
	oobClient, err := outofbandClient(config.AriesCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create aries outofband client : %w", err)
	}

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

	vccrypto := crypto.New(config.AriesCtx.KMS(), config.AriesCtx.Crypto(), config.AriesCtx.VDRIRegistry())

	op := &Operation{
		oobClient:          oobClient,
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
		vccrypto:           vccrypto,
		publicDIDCreator:   config.PublicDIDCreator,
		httpClient:         &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
	}

	go op.didCommActionListener(actionCh)

	return op, nil
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Operation defines handlers for rp operations.
type Operation struct {
	oobClient          *outofband.Client
	didExClient        *didexchange.Client
	issueCredClient    *issuecredential.Client
	presentProofClient *presentproof.Client
	uiEndpoint         string
	profileStore       *issuer.Profile
	txnStore           storage.Store
	tokenStore         storage.Store
	connectionLookup   connections
	vdriRegistry       vdri.Registry
	vccrypto           adaptervc.Crypto
	serviceEndpoint    string
	publicDIDCreator   PublicDIDCreator
	httpClient         httpClient
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
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			fmt.Sprintf("invalid request: %s", err.Error()), profileEndpoint, logger)

		return
	}

	newDidDoc, err := o.publicDIDCreator.Create()
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to create public did : %s", err.Error()), profileEndpoint, logger)

		return
	}

	if len(newDidDoc.AssertionMethod) == 0 {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			"missing assertionMethod in public did", profileEndpoint, logger)

		return
	}

	if len(newDidDoc.Authentication) == 0 {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			"missing authentication in public did", profileEndpoint, logger)

		return
	}

	created := time.Now().UTC()
	profileData := &issuer.ProfileData{
		ID:                     data.ID,
		Name:                   data.Name,
		SupportedVCContexts:    data.SupportedVCContexts,
		URL:                    data.URL,
		CredentialSigningKey:   newDidDoc.AssertionMethod[0].PublicKey.ID,
		PresentationSigningKey: newDidDoc.Authentication[0].PublicKey.ID,
		CreatedAt:              &created,
	}

	err = o.profileStore.SaveProfile(profileData)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to create profile: %s", err.Error()), profileEndpoint, logger)

		return
	}

	rw.WriteHeader(http.StatusCreated)
	commhttp.WriteResponseWithLog(rw, profileData, profileEndpoint, logger)
}

func (o *Operation) getIssuerProfileHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)[idPathParam]

	profile, err := o.profileStore.GetProfile(profileID)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			fmt.Sprintf("id=%s - %s", profileID, err.Error()), getProfileEndpoint, logger)

		return
	}

	commhttp.WriteResponseWithLog(rw, profile, getProfileEndpoint, logger)
}

func (o *Operation) walletConnectHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)[idPathParam]

	profile, err := o.profileStore.GetProfile(profileID)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			fmt.Sprintf("id=%s - %s", profileID, err.Error()), walletConnectEndpoint, logger)

		return
	}

	state := req.URL.Query().Get(stateQueryParam)
	if state == "" {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			"failed to get state from the url", walletConnectEndpoint, logger)

		return
	}

	// store the txn data
	txnID, err := o.createTxn(profile, state)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to create txn : %s", err.Error()), walletConnectEndpoint, logger)

		return
	}

	http.Redirect(rw, req, o.uiEndpoint+"?"+txnIDQueryParam+"="+txnID, http.StatusFound)
}

func (o *Operation) validateWalletResponseHandler(rw http.ResponseWriter, req *http.Request) { //nolint: funlen
	// get the txnID
	txnID := req.URL.Query().Get(txnIDQueryParam)

	if txnID == "" {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest, "failed to get txnID from the url",
			validateConnectResponseEndpoint, logger)

		return
	}

	// validate the response
	connectResp := &WalletConnect{}

	if err := json.NewDecoder(req.Body).Decode(&connectResp); err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			fmt.Sprintf("invalid request: %s", err.Error()), validateConnectResponseEndpoint, logger)

		return
	}

	// get txnID data from the storage
	txnData, err := o.getTxn(txnID)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			fmt.Sprintf("txn data not found: %s", err.Error()), validateConnectResponseEndpoint, logger)

		return
	}

	connectData, err := issuervc.ParseWalletResponse(connectResp.Resp)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to validate presentation: %s", err.Error()), validateConnectResponseEndpoint, logger)

		return
	}

	conn, err := o.validateAndGetConnection(connectData)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to validate DIDComm connection: %s", err.Error()),
			validateConnectResponseEndpoint, logger)

		return
	}

	profile, err := o.profileStore.GetProfile(txnData.IssuerID)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			fmt.Sprintf("profile not found: %s", err.Error()), validateConnectResponseEndpoint, logger)

		return
	}

	token := uuid.New().String()

	userConnMap := &UserConnectionMapping{
		ConnectionID: conn.ConnectionID,
		IssuerID:     txnData.IssuerID,
		Token:        token,
	}

	err = o.storeUserConnectionMapping(userConnMap)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to store user connection mapping: %s", err.Error()),
			validateConnectResponseEndpoint, logger)

		return
	}

	redirectURL := fmt.Sprintf(redirectURLFmt, getCallBackURL(profile.URL), txnData.State, token)

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponseWithLog(rw,
		&ValidateConnectResp{RedirectURL: redirectURL}, validateConnectResponseEndpoint, logger)
}

func (o *Operation) getCHAPIRequestHandler(rw http.ResponseWriter, req *http.Request) {
	// get the txnID
	txnID := req.URL.Query().Get(txnIDQueryParam)

	if txnID == "" {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest, "failed to get txnID from the url",
			getCHAPIRequestEndpoint, logger)

		return
	}

	// get txnID data from the storage
	txnData, err := o.getTxn(txnID)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			fmt.Sprintf("txn data not found: %s", err.Error()), getCHAPIRequestEndpoint, logger)

		return
	}

	profile, err := o.profileStore.GetProfile(txnData.IssuerID)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			fmt.Sprintf("issuer not found: %s", err.Error()), getCHAPIRequestEndpoint, logger)

		return
	}

	manifestVC, err := issuervc.CreateManifestCredential(profile.Name, profile.SupportedVCContexts)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			fmt.Sprintf("error creating manifest vc : %s", err.Error()), getCHAPIRequestEndpoint, logger)

		return
	}

	commhttp.WriteResponseWithLog(rw, &CHAPIRequest{
		Query:             &CHAPIQuery{Type: DIDConnectCHAPIQueryType},
		DIDCommInvitation: txnData.DIDCommInvitation,
		Manifest:          manifestVC,
	}, getCHAPIRequestEndpoint, logger)
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
	invitation, err := o.oobClient.CreateInvitation(nil, outofband.WithLabel("issuer"))
	if err != nil {
		return "", fmt.Errorf("failed to create invitation : %w", err)
	}

	txnID := uuid.New().String()

	// store the txn data
	data := &txnData{
		IssuerID:          profile.ID,
		State:             state,
		DIDCommInvitation: invitation,
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
	dataBytes, err := o.txnStore.Get(id)
	if err != nil || dataBytes == nil {
		return nil, err
	}

	data := &txnData{}

	err = json.Unmarshal(dataBytes, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (o *Operation) storeUserConnectionMapping(userConnMap *UserConnectionMapping) error {
	userConnMapBytes, err := json.Marshal(userConnMap)
	if err != nil {
		return err
	}

	err = o.tokenStore.Put(userConnMap.ConnectionID, userConnMapBytes)
	if err != nil {
		return err
	}

	return nil
}

func (o *Operation) getUserConnectionMapping(connID string) (*UserConnectionMapping, error) {
	userConnMapBytes, err := o.tokenStore.Get(connID)
	if err != nil {
		return nil, err
	}

	userConnMap := &UserConnectionMapping{}

	err = json.Unmarshal(userConnMapBytes, userConnMap)
	if err != nil {
		return nil, fmt.Errorf("user conn map : %w", err)
	}

	return userConnMap, nil
}

func (o *Operation) didCommActionListener(ch <-chan service.DIDCommAction) {
	for msg := range ch {
		var err error

		var args interface{}

		switch msg.Message.Type() {
		case issuecredsvc.RequestCredentialMsgType:
			args, err = o.handleRequestCredential(msg)
		case presentproofsvc.RequestPresentationMsgType:
			args, err = o.handleRequestPresentation(msg)
		default:
			err = fmt.Errorf("unsupported message type : %s", msg.Message.Type())
		}

		if err != nil {
			logger.Errorf("msgType=[%s] id=[%s] errMsg=[%s]", msg.Message.Type(), msg.Message.ID(), err.Error())

			msg.Stop(fmt.Errorf("handle %s : %w", msg.Message.Type(), err))
		} else {
			logger.Infof("msgType=[%s] id=[%s] msg=[%s]", msg.Message.Type(), msg.Message.ID(), "success")

			msg.Continue(args)
		}
	}
}

func (o *Operation) handleRequestCredential(msg service.DIDCommAction) (interface{}, error) { // nolint: funlen, gocyclo
	connID, err := o.getConnectionIDFromEvent(msg)
	if err != nil {
		return nil, fmt.Errorf("connection using DIDs not found : %w", err)
	}

	authorizationCreReq, err := fetchAuthorizationCreReq(msg)
	if err != nil {
		return nil, err
	}

	newDidDoc, err := o.vdriRegistry.Create("peer", vdri.WithServiceEndpoint(o.serviceEndpoint))
	if err != nil {
		return nil, fmt.Errorf("create new issuer did : %w", err)
	}

	docJSON, err := newDidDoc.JSONBytes()
	if err != nil {
		return nil, err
	}

	rpDIDDoc, err := did.ParseDocument(authorizationCreReq.RPDIDDoc.Doc)
	if err != nil {
		return nil, fmt.Errorf("parse rp did doc : %w", err)
	}

	rpDIDDoc.ID = authorizationCreReq.RPDIDDoc.ID

	_, err = o.didExClient.CreateConnection(newDidDoc.ID, rpDIDDoc)
	if err != nil {
		return nil, fmt.Errorf("create connection with rp : %w", err)
	}

	userConnMap, err := o.getUserConnectionMapping(connID)
	if err != nil {
		return nil, fmt.Errorf("get token from the connectionID : %w", err)
	}

	profile, err := o.profileStore.GetProfile(userConnMap.IssuerID)
	if err != nil {
		return nil, fmt.Errorf("fetch issuer profile : %w", err)
	}

	vc := issuervc.CreateAuthorizationCredential(newDidDoc.ID, docJSON, authorizationCreReq.RPDIDDoc,
		authorizationCreReq.SubjectDID)

	vc, err = o.vccrypto.SignCredential(vc, profile.CredentialSigningKey)
	if err != nil {
		return nil, fmt.Errorf("sign authorization credential : %w", err)
	}

	handle := &AuthorizationCredentialHandle{
		ID:               vc.ID,
		IssuerDID:        newDidDoc.ID,
		SubjectDID:       authorizationCreReq.SubjectDID,
		RPDID:            authorizationCreReq.RPDIDDoc.ID,
		UserConnectionID: connID,
		Token:            userConnMap.Token,
		IssuerID:         userConnMap.IssuerID,
	}

	err = o.storeAuthorizationCredHandle(handle)
	if err != nil {
		return nil, fmt.Errorf("store authorization credential : %w", err)
	}

	return issuecredential.WithIssueCredential(&issuecredential.IssueCredential{
		CredentialsAttach: []decorator.Attachment{
			{Data: decorator.AttachmentData{JSON: vc}},
		},
	}), nil
}

func (o *Operation) handleRequestPresentation(msg service.DIDCommAction) (interface{}, error) {
	authorizationCred, err := fetchAuthorizationCred(msg, o.vdriRegistry)
	if err != nil {
		return nil, err
	}

	data, err := o.txnStore.Get(authorizationCred.ID)
	if err != nil {
		return nil, fmt.Errorf("authorization credential not found : %w", err)
	}

	authorizationCredHandle := &AuthorizationCredentialHandle{}

	err = json.Unmarshal(data, authorizationCredHandle)
	if err != nil {
		return nil, fmt.Errorf("authorization credential handle : %w", err)
	}

	profile, err := o.profileStore.GetProfile(authorizationCredHandle.IssuerID)
	if err != nil {
		return nil, fmt.Errorf("fetch issuer profile : %w", err)
	}

	vp, err := o.generateUserPresentation(authorizationCredHandle, profile.URL)
	if err != nil {
		return nil, err
	}

	vp, err = o.vccrypto.SignPresentation(vp, profile.PresentationSigningKey)
	if err != nil {
		return nil, fmt.Errorf("sign presentation : %w", err)
	}

	return presentproof.WithPresentation(&presentproof.Presentation{
		PresentationsAttach: []decorator.Attachment{{
			Data: decorator.AttachmentData{
				JSON: vp,
			},
		}},
	}), nil
}

func (o *Operation) generateUserPresentation(handle *AuthorizationCredentialHandle, url string) (*verifiable.Presentation, error) { // nolint: lll
	vcReq := &IssuerVCReq{Token: handle.Token}

	reqBytes, err := json.Marshal(vcReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, getUserCredentialURL(url), bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, err
	}

	vcBytes, err := sendHTTPRequest(req, o.httpClient, http.StatusOK, "")
	if err != nil {
		return nil, err
	}

	// TODO https://github.com/trustbloc/edge-adapter/issues/191 enable signature check
	vc, err := verifiable.ParseCredential(vcBytes, verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, fmt.Errorf("parse user data vc : %w", err)
	}

	return issuervc.CreatePresentation(vc)
}

func (o *Operation) getConnectionIDFromEvent(msg service.DIDCommAction) (string, error) {
	myDID, err := getStrPropFromEvent("myDID", msg)
	if err != nil {
		return "", err
	}

	theirDID, err := getStrPropFromEvent("theirDID", msg)
	if err != nil {
		return "", err
	}

	connID, err := o.connectionLookup.GetConnectionIDByDIDs(myDID, theirDID)
	if err != nil {
		return "", err
	}

	return connID, nil
}

func (o *Operation) storeAuthorizationCredHandle(handle *AuthorizationCredentialHandle) error {
	dataBytes, err := json.Marshal(handle)
	if err != nil {
		return err
	}

	err = o.txnStore.Put(handle.ID, dataBytes)
	if err != nil {
		return err
	}

	return nil
}

func outofbandClient(ariesCtx outofband.Provider) (*outofband.Client, error) {
	c, err := outofband.New(ariesCtx)
	if err != nil {
		return nil, err
	}

	return c, err
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

func fetchAuthorizationCreReq(msg service.DIDCommAction) (*AuthorizationCredentialReq, error) {
	credReq := &issuecredsvc.RequestCredential{}

	err := msg.Message.Decode(credReq)
	if err != nil {
		return nil, err
	}

	if len(credReq.RequestsAttach) != 1 {
		return nil, fmt.Errorf("credential request should have one attachment, but has %d",
			len(credReq.RequestsAttach))
	}

	reqJSON, err := credReq.RequestsAttach[0].Data.Fetch()
	if err != nil {
		return nil, fmt.Errorf("no data inside the credential request attachment : %w", err)
	}

	authorizationCreReq := &AuthorizationCredentialReq{}

	err = json.Unmarshal(reqJSON, authorizationCreReq)
	if err != nil {
		return nil, fmt.Errorf("invalid json data in credential request : %w", err)
	}

	if authorizationCreReq.SubjectDID == "" {
		return nil, errors.New("subject did is missing in authorization cred request")
	}

	if authorizationCreReq.RPDIDDoc == nil || authorizationCreReq.RPDIDDoc.ID == "" ||
		authorizationCreReq.RPDIDDoc.Doc == nil {
		return nil, errors.New("rp did data is missing in authorization cred request")
	}

	return authorizationCreReq, nil
}

func fetchAuthorizationCred(msg service.DIDCommAction, vdriRegistry vdri.Registry) (*verifiable.Credential, error) {
	credReq := &presentproofsvc.RequestPresentation{}

	err := msg.Message.Decode(credReq)
	if err != nil {
		return nil, fmt.Errorf("decode presentation request message : %w", err)
	}

	if len(credReq.RequestPresentationsAttach) != 1 {
		return nil, fmt.Errorf("presentation request should have one attachment, but contains %d",
			len(credReq.RequestPresentationsAttach))
	}

	reqJSON, err := credReq.RequestPresentationsAttach[0].Data.Fetch()
	if err != nil {
		return nil, fmt.Errorf("no data inside the presentation request attachment : %w", err)
	}

	vp, err := verifiable.ParsePresentation(
		reqJSON,
		verifiable.WithPresDisabledProofCheck(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse presentation : %w", err)
	}

	if len(vp.Credentials()) != 1 {
		return nil, fmt.Errorf("request presentation should have one credential, but contains %d",
			len(vp.Credentials()))
	}

	vcBytes, err := json.Marshal(vp.Credentials()[0])
	if err != nil {
		return nil, fmt.Errorf("marshal credential : %w", err)
	}

	vc, err := verifiable.ParseCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(verifiable.NewDIDKeyResolver(vdriRegistry).PublicKeyFetcher()),
	)
	if err != nil {
		return nil, fmt.Errorf("parse credential : %w", err)
	}

	return vc, nil
}

func getStrPropFromEvent(prop string, msg service.DIDCommAction) (string, error) {
	if len(msg.Properties.All()) == 0 {
		return "", errors.New("no properties in the event")
	}

	val, ok := msg.Properties.All()[prop]
	if !ok {
		return "", fmt.Errorf("%s not found", prop)
	}

	strVal, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("%s not a string", prop)
	}

	return strVal, nil
}

func getCallBackURL(issuerURL string) string {
	return fmt.Sprintf("%s/cb", issuerURL)
}

func getUserCredentialURL(issuerURL string) string {
	return fmt.Sprintf("%s/credential", issuerURL)
}

func sendHTTPRequest(req *http.Request, client httpClient, status int, bearerToken string) ([]byte, error) {
	if bearerToken != "" {
		req.Header.Add("Authorization", "Bearer "+bearerToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request : %w", err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Warnf("failed to close response body")
		}
	}()

	if resp.StatusCode != status {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Warnf("failed to read response body for status: %d", resp.StatusCode)
		}

		return nil, fmt.Errorf("http request: %d %s", resp.StatusCode, string(body))
	}

	return ioutil.ReadAll(resp.Body)
}
