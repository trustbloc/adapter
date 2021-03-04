/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package operation provides wallet adapter REST features.
package operation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	didexchangesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
	"github.com/trustbloc/edge-adapter/pkg/restapi"
	commhttp "github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/http"
)

var logger = log.New("edge-adapter/wallet-bridge")

// constants for endpoints of wallet bridge controller.
const (
	operationID           = "/wallet-bridge"
	CreateInvitationPath  = operationID + "/create-invitation"
	RequestAppProfilePath = operationID + "/request-app-profile"
	SendCHAPIRequestPath  = operationID + "/send-chapi-request"
	SavePreferencesPath   = operationID + "/save-preferences"
	GetPreferencesPath    = operationID + "/get-preferences/{id}"

	invalidIDErr                = "invalid ID"
	invalidCHAPIRequestErr      = "invalid CHAPI request"
	failedToSendCHAPIRequestErr = "failed to send CHAPI request: %s"
	noConnectionFoundErr        = "failed to find connection with existing wallet profile"

	chapiRqstDIDCommMsgType = "https://trustbloc.dev/chapi/1.0/request"
	chapiRespDIDCommMsgType = "https://trustbloc.dev/chapi/1.0/response"

	defaultTimeout = 20 * time.Second
)

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation is REST service operation controller for wallet bridge features.
type Operation struct {
	agentLabel            string
	walletAppURL          string
	store                 *walletAppProfileStore
	outOfBand             *outofband.Client
	didExchange           *didexchange.Client
	messenger             *messaging.Client
	adapterTransientStore storage.Store
}

// Config defines configuration for wallet adapter operations.
type Config struct {
	AriesCtx              aries.CtxProvider
	MsgRegistrar          command.MessageHandler
	WalletAppURL          string
	DefaultLabel          string
	AdapterTransientStore storage.Store
}

type consentRequestCtx struct {
	InvitationID string
	UserDID      string
}

// WalletType supported wallet types
type WalletType string

const (
	// Browser wallet type
	Browser WalletType = "browser"
	// Remote wallet type
	Remote = "remote"
)

// IsValid checks if underlying wallet type is supported
func (lt WalletType) IsValid() error {
	switch lt {
	case Browser, Remote:
		return nil
	}

	return fmt.Errorf("invalid wallet type '%s', supported types are %s", lt, []WalletType{Browser, Remote})
}

// New returns new wallet bridge REST controller instance.
func New(config *Config) (*Operation, error) {
	store, err := newWalletAppProfileStore(config.AriesCtx.StorageProvider())
	if err != nil {
		return nil, fmt.Errorf("failed to open wallet profile store : %w", err)
	}

	messengerClient, err := messaging.New(config.AriesCtx, config.MsgRegistrar, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create messenger client : %w", err)
	}

	outOfBandClient, err := outofband.New(config.AriesCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create out-of-band client : %w", err)
	}

	didExchangeClient, err := didexchange.New(config.AriesCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create did-exchange client : %w", err)
	}

	o := &Operation{
		agentLabel:            config.DefaultLabel,
		walletAppURL:          config.WalletAppURL,
		store:                 store,
		outOfBand:             outOfBandClient,
		didExchange:           didExchangeClient,
		messenger:             messengerClient,
		adapterTransientStore: config.AdapterTransientStore,
	}

	err = o.setupEventHandlers()
	if err != nil {
		return nil, fmt.Errorf("failed to register events : %w", err)
	}

	return o, nil
}

// GetRESTHandlers get all controller API handler available for this protocol service.
func (o *Operation) GetRESTHandlers() []restapi.Handler {
	return []restapi.Handler{
		support.NewHTTPHandler(CreateInvitationPath, http.MethodPost, o.CreateInvitation),
		support.NewHTTPHandler(RequestAppProfilePath, http.MethodPost, o.RequestApplicationProfile),
		support.NewHTTPHandler(SendCHAPIRequestPath, http.MethodPost, o.SendCHAPIRequest),
		support.NewHTTPHandler(SavePreferencesPath, http.MethodPost, o.SaveWalletPreferences),
		support.NewHTTPHandler(GetPreferencesPath, http.MethodGet, o.GetWalletPreferences),
	}
}

// CreateInvitation swagger:route POST /wallet-bridge/create-invitation wallet-bridge createInvitation
//
// Creates out-of-band invitation to connect to this wallet server.
// Response contains URL to application with invitation to load during startup.
//
// Responses:
//    default: genericError
//    200: createInvitationResponse
func (o *Operation) CreateInvitation(rw http.ResponseWriter, req *http.Request) {
	var request CreateInvitationRequest

	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest, err.Error(), CreateInvitationPath, logger)

		return
	}

	if request.UserID == "" {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest, invalidIDErr, CreateInvitationPath, logger)

		return
	}

	// TODO : public DIDs in request parameters - [Issue#edge-agent:645]
	invitation, err := o.outOfBand.CreateInvitation([]string{didexchangesvc.PIURI},
		outofband.WithLabel(o.agentLabel))
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), CreateInvitationPath, logger)

		return
	}

	err = o.putInAdapterTransientStore(invitation.ID, &consentRequestCtx{
		InvitationID: invitation.ID, UserDID: request.UserID,
	})
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), CreateInvitationPath, logger)

		return
	}

	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), CreateInvitationPath, logger)

		return
	}

	err = o.store.SaveInvitation(invitation.ID, request.UserID)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), CreateInvitationPath, logger)

		return
	}

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponseWithLog(rw,
		&CreateInvitationResponse{
			URL: fmt.Sprintf("%s?oob=%s", o.walletAppURL, base64.StdEncoding.EncodeToString(invitationBytes)),
		}, CreateInvitationPath, logger)
}

// RequestApplicationProfile swagger:route POST /wallet-bridge/request-app-profile wallet-bridge applicationProfileRequest
//
// Requests wallet application profile of given user.
// Response contains wallet application profile of given user.
//
// Responses:
//    default: genericError
//    200: appProfileResponse
func (o *Operation) RequestApplicationProfile(rw http.ResponseWriter, req *http.Request) {
	request, err := prepareAppProfileRequest(req.Body)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest, err.Error(), RequestAppProfilePath, logger)

		return
	}

	profile, err := o.store.GetProfileByUserID(request.UserID)
	if err != nil && !request.WaitForConnection {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), RequestAppProfilePath, logger)

		return
	}

	if profile == nil {
		profile = &walletAppProfile{}
	}

	// if status is not completed or profile not found, then wait for completion if 'WaitForConnection=true'
	var status, invitationID string

	switch {
	case profile.ConnectionID != "":
		status = didexchangesvc.StateIDCompleted
		invitationID = profile.InvitationID
	case request.WaitForConnection:
		ctx, cancel := context.WithTimeout(context.Background(), request.Timeout)
		defer cancel()

		result, err := o.waitForConnectionCompletion(ctx, request.UserID)
		if err != nil {
			commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), RequestAppProfilePath, logger)

			return
		}

		status = didexchangesvc.StateIDCompleted
		invitationID = result

	default:
		status = ""
		invitationID = profile.InvitationID
	}

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponseWithLog(rw,
		&ApplicationProfileResponse{invitationID, status}, RequestAppProfilePath, logger)
}

// SendCHAPIRequest swagger:route POST /wallet-bridge/send-chapi-request wallet-bridge chapiRequest
//
// Sends CHAPI request to given wallet application ID.
// Response contains CHAPI request.
//
// Responses:
//    default: genericError
//    200: chapiResponse
func (o *Operation) SendCHAPIRequest(rw http.ResponseWriter, req *http.Request) {
	request, err := prepareCHAPIRequest(req.Body)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest, err.Error(), SendCHAPIRequestPath, logger)

		return
	}

	profile, err := o.store.GetProfileByUserID(request.UserID)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), SendCHAPIRequestPath, logger)

		return
	}

	if profile.ConnectionID == "" {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, noConnectionFoundErr,
			SendCHAPIRequestPath, logger)

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), request.Timeout)
	defer cancel()

	msgBytes, err := json.Marshal(map[string]interface{}{
		"@id":   uuid.New().String(),
		"@type": chapiRqstDIDCommMsgType,
		"data":  request.Payload,
	})
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), SendCHAPIRequestPath, logger)

		return
	}

	responseBytes, err := o.messenger.Send(msgBytes,
		messaging.SendByConnectionID(profile.ConnectionID),
		messaging.WaitForResponse(ctx, chapiRespDIDCommMsgType))
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			fmt.Sprintf(failedToSendCHAPIRequestErr, err), SendCHAPIRequestPath, logger)

		return
	}

	response, err := extractCHAPIResponse(responseBytes)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), SendCHAPIRequestPath, logger)

		return
	}

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponseWithLog(rw, &CHAPIResponse{response}, SendCHAPIRequestPath, logger)
}

// SaveWalletPreferences swagger:route POST /wallet-bridge/save-preferences wallet-bridge savePreferences
//
// 	Saves wallet preferences by user.
//
// Responses:
//    default: genericError
func (o *Operation) SaveWalletPreferences(rw http.ResponseWriter, req *http.Request) {
	request, err := prepareSavePreferencesRequest(req.Body)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest, err.Error(), SavePreferencesPath, logger)

		return
	}

	err = o.store.SavePreferences(request.UserID, []byte(request.WalletType))
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), SavePreferencesPath, logger)

		return
	}

	rw.WriteHeader(http.StatusOK)
	logger.Infof("endpoint=[%s] msg=[%s]", SavePreferencesPath, "success")
}

// GetWalletPreferences swagger:route GET /wallet-bridge/get-preferences/{id} wallet-bridge getPreferences
//
// Gets wallet preferences by user.
//
// Responses:
//    default: genericError
//    200: walletPreferencesResponse
func (o *Operation) GetWalletPreferences(rw http.ResponseWriter, req *http.Request) {
	id, found := getIDFromRequest(req)
	if !found {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest, invalidIDErr, GetPreferencesPath, logger)

		return
	}

	prefBytes, err := o.store.GetPreferences(id)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), GetPreferencesPath, logger)

		return
	}

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponseWithLog(rw,
		&WalletPreferencesResponse{WalletType: WalletType(prefBytes)}, SendCHAPIRequestPath, logger)
}

func (o *Operation) setupEventHandlers() error {
	// create state channel subscribers
	states := make(chan service.StateMsg)

	// registers state channels to listen for events
	if err := o.didExchange.RegisterMsgEvent(states); err != nil {
		return fmt.Errorf("register msg event: %w", err)
	}

	go o.stateMsgListener(states)

	return nil
}

func (o *Operation) stateMsgListener(ch <-chan service.StateMsg) {
	for msg := range ch {
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
			"Received connection complete event for invitationID=%s connectionID=%s",
			event.InvitationID(), event.ConnectionID())

		// everytime during adapter didexchange completion.
		err := o.store.SaveProfile(event.InvitationID(), event.ConnectionID())
		if err != nil {
			logger.Warnf("Failed to update wallet application profile: %s", err)
		}
	}
}

// nolint:gocyclo //can't split function further and maintain readability.
func (o *Operation) waitForConnectionCompletion(ctx context.Context, userID string) (string, error) {
	stateCh := make(chan service.StateMsg)

	if err := o.didExchange.RegisterMsgEvent(stateCh); err != nil {
		return "", fmt.Errorf("register msg event: %w", err)
	}

	defer func() {
		e := o.didExchange.UnregisterMsgEvent(stateCh)
		if e != nil {
			logger.Warnf("Failed to unregister msg event registered to wait for profile connection completion: %w", e)
		}
	}()

	for {
		select {
		case msg := <-stateCh:
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

			userIDBytes, e := o.store.GetUserByInvitationID(event.InvitationID())
			if e == nil && string(userIDBytes) == userID {
				logger.Debugf(
					"Received connection complete event for invitationID=%s & userID=%s", event.InvitationID(), userID)
				return event.InvitationID(), nil
			}
		case <-ctx.Done():
			return "", fmt.Errorf("time out waiting for state 'completed'")
		}
	}
}

func (o *Operation) putInAdapterTransientStore(k string, v interface{}) error {
	if o.adapterTransientStore != nil {
		vBytes, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal transient data: %w", err)
		}

		err = o.adapterTransientStore.Put(k, vBytes)
		if err != nil {
			return fmt.Errorf("failed to save in adapter transient store: %w", err)
		}
	}

	return nil
}

func prepareAppProfileRequest(r io.Reader) (*ApplicationProfileRequest, error) {
	var request ApplicationProfileRequest

	err := json.NewDecoder(r).Decode(&request)
	if err != nil {
		return nil, err
	}

	if request.UserID == "" {
		return nil, fmt.Errorf(invalidIDErr)
	}

	if request.WaitForConnection && request.Timeout == 0 {
		request.Timeout = defaultTimeout
	}

	return &request, nil
}

func prepareCHAPIRequest(r io.Reader) (*CHAPIRequest, error) {
	var request CHAPIRequest

	err := json.NewDecoder(r).Decode(&request)
	if err != nil {
		return nil, err
	}

	if request.UserID == "" {
		return nil, fmt.Errorf(invalidIDErr)
	}

	if len(request.Payload) == 0 {
		return nil, fmt.Errorf(invalidCHAPIRequestErr)
	}

	if request.Timeout == 0 {
		request.Timeout = defaultTimeout
	}

	return &request, nil
}

func prepareSavePreferencesRequest(r io.Reader) (*SaveWalletPreferencesRequest, error) {
	var request SaveWalletPreferencesRequest

	err := json.NewDecoder(r).Decode(&request)
	if err != nil {
		return nil, err
	}

	if request.UserID == "" {
		return nil, fmt.Errorf(invalidIDErr)
	}

	if err := request.WalletType.IsValid(); err != nil {
		return nil, err
	}

	return &request, nil
}

// getIDFromRequest returns ID from request.
func getIDFromRequest(req *http.Request) (string, bool) {
	id := mux.Vars(req)["id"]
	if id == "" {
		return "", false
	}

	return id, true
}

func extractCHAPIResponse(msgBytes []byte) (json.RawMessage, error) {
	var response struct {
		Message struct {
			Data json.RawMessage
		}
	}

	err := json.Unmarshal(msgBytes, &response)
	if err != nil {
		return nil, err
	}

	return response.Message.Data, nil
}
