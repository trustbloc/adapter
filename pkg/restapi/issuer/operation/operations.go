/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/trustbloc/edge-core/pkg/log"
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
	generateInvitationEndpoint      = didCommBasePath + "/invitation"
	validateConnectResponseEndpoint = "/connect/validate"

	// http params
	idPathParam     = "id"
	txnIDQueryParam = "txnID"

	storeName = "issuer_txn"
)

var logger = log.New("edge-adapter/issuer-operations")

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
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

	p, err := issuer.New(config.StoreProvider)
	if err != nil {
		return nil, err
	}

	txnStore, err := getTxnStore(config.StoreProvider)
	if err != nil {
		return nil, err
	}

	return &Operation{
		didExClient:  didExClient,
		uiEndpoint:   config.UIEndpoint,
		profileStore: p,
		txnStore:     txnStore,
	}, nil
}

// Operation defines handlers for rp operations.
type Operation struct {
	didExClient  *didexchange.Client
	uiEndpoint   string
	profileStore *issuer.Profile
	txnStore     storage.Store
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		// profile
		support.NewHTTPHandler(profileEndpoint, http.MethodPost, o.createIssuerProfileHandler),
		support.NewHTTPHandler(getProfileEndpoint, http.MethodGet, o.getIssuerProfileHandler),

		// didcomm
		support.NewHTTPHandler(walletConnectEndpoint, http.MethodGet, o.walletConnect),
		support.NewHTTPHandler(validateConnectResponseEndpoint, http.MethodPost, o.validateWalletResponse),
		support.NewHTTPHandler(generateInvitationEndpoint, http.MethodGet, o.generateInvitation),
	}
}

func (o *Operation) createIssuerProfileHandler(rw http.ResponseWriter, req *http.Request) {
	data := &issuer.ProfileData{}

	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err.Error()))

		return
	}

	err := o.profileStore.SaveProfile(data)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to create profile: %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(rw, data)
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

func (o *Operation) walletConnect(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)[idPathParam]

	_, err := o.profileStore.GetProfile(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	// store the txn data
	txnID, err := o.createTxn(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to create txn : %s", err.Error()))

		return
	}

	http.Redirect(rw, req, o.uiEndpoint+"?"+txnIDQueryParam+"="+txnID, http.StatusFound)
}

func (o *Operation) validateWalletResponse(rw http.ResponseWriter, req *http.Request) {
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
	txnData, err := o.txnStore.Get(txnID)
	if err != nil || txnData == nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("txn data not found: %s", err.Error()))

		return
	}

	connectData, err := issuervc.ParseWalletResponse(connectResp.Resp)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to validate presentation: %s", err.Error()))

		return
	}

	// TODO https://github.com/trustbloc/edge-adapter/issues/88 validate connection details
	logger.Debugf("connect data: %+v", connectData)

	rw.WriteHeader(http.StatusOK)
}

func (o *Operation) generateInvitation(rw http.ResponseWriter, _ *http.Request) {
	logger.Debugf("handling request to generate did-exchange invitation")

	invitation, err := o.didExClient.CreateInvitation("issuer")
	if err != nil {
		msg := fmt.Sprintf("failed to create invitation : %s", err.Error())
		logger.Errorf(msg)

		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, msg)

		return
	}

	commhttp.WriteResponse(rw, invitation)
	logger.Debugf("response: %+v", invitation)
}

func (o *Operation) createTxn(profileID string) (string, error) {
	txnID := uuid.New().String()

	// store the data on txn (issuerID, callbackURL, etc)
	data := &txnData{IssuerID: profileID}

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

	go service.AutoExecuteActionEvent(actionCh)

	return didExClient, nil
}

func getTxnStore(prov storage.Provider) (storage.Store, error) {
	err := prov.CreateStore(storeName)
	if err != nil && err != storage.ErrDuplicateStore {
		return nil, err
	}

	txnStore, err := prov.OpenStore(storeName)
	if err != nil {
		return nil, err
	}

	return txnStore, nil
}
