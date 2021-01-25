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
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	didexchangesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
	commhttp "github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/http"
)

var logger = log.New("edge-adapter/wallet-bridge")

// constants for endpoints of wallet bridge controller.
const (
	commandName          = "/wallet"
	CreateInvitationPath = "/create-invitation"
	RequestAppProfile    = "/request-app-profile"
	SendCHAPIRequest     = "/send-chapi-request"

	invalidIDErr                = "invalid ID"
	invalidCHAPIRequestErr      = "invalid CHAPI request"
	failedToSendCHAPIRequestErr = "failed to send CHAPI request: %s"
	noConnectionFoundErr        = "failed to find connection with existing wallet profile"

	chapiRqstDIDCommMsgType = "https://trustbloc.dev/chapi/1.0/request"
	chapiRespDIDCommMsgType = "https://trustbloc.dev/chapi/1.0/response"

	defaultSendMsgTimeout = 20 * time.Second
)

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation is REST service operation controller for wallet bridge features.
type Operation struct {
	agentLabel   string
	walletAppURL string
	store        *walletAppProfileStore
	outOfBand    *outofband.Client
	didExchange  *didexchange.Client
	messenger    *messaging.Client
}

// Config defines configuration for wallet adapter operations.
type Config struct {
	AriesCtx     aries.CtxProvider
	MsgRegistrar command.MessageHandler
	WalletAppURL string
	DefaultLabel string
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
		agentLabel:   config.DefaultLabel,
		walletAppURL: config.WalletAppURL,
		store:        store,
		outOfBand:    outOfBandClient,
		didExchange:  didExchangeClient,
		messenger:    messengerClient,
	}

	err = o.setupEventHandlers()
	if err != nil {
		return nil, fmt.Errorf("failed to register events : %w", err)
	}

	return o, nil
}

// GetRESTHandlers get all controller API handler available for this protocol service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(CreateInvitationPath, http.MethodPost, o.CreateInvitation),
		support.NewHTTPHandler(RequestAppProfile, http.MethodPost, o.RequestApplicationProfile),
		support.NewHTTPHandler(SendCHAPIRequest, http.MethodPost, o.SendCHAPIRequest),
	}
}

// CreateInvitation swagger:route POST /wallet/create-invitation wallet-bridge createInvitation
//
// Creates out-of-band invitation to connect to this wallet server.
// Response contains URL to application with invitation to load during startup.
//
// Responses:
//    default: genericError
//    200: createInvitationResponse
func (o *Operation) CreateInvitation(rw http.ResponseWriter, req *http.Request) {
	var request createInvitationRequest

	err := json.NewDecoder(req.Body).Decode(&request.Body)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest, err.Error(), CreateInvitationPath, logger)

		return
	}

	if request.Body.UserID == "" {
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

	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), CreateInvitationPath, logger)

		return
	}

	err = o.store.SaveProfile(request.Body.UserID, &walletAppProfile{InvitationID: invitation.ID})
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), CreateInvitationPath, logger)

		return
	}

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponseWithLog(rw,
		&createInvitationResponse{
			URL: fmt.Sprintf("%s?oob=%s", o.walletAppURL, base64.StdEncoding.EncodeToString(invitationBytes)),
		}, CreateInvitationPath, logger)
}

// RequestApplicationProfile swagger:route POST /wallet/request-app-profile wallet-bridge applicationProfileRequest
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
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest, err.Error(), RequestAppProfile, logger)

		return
	}

	profile, err := o.store.GetProfileByUserID(request.Body.UserID)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), RequestAppProfile, logger)

		return
	}

	// if status is not completed, then wait for completion if 'WaitForConnection=true'
	var status string
	if profile.ConnectionID != "" {
		status = didexchangesvc.StateIDCompleted
	} else if request.Body.WaitForConnection {
		ctx, cancel := context.WithTimeout(context.Background(), request.Body.Timeout)
		defer cancel()

		err = o.waitForConnectionCompletion(ctx, profile)
		if err != nil {
			commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), RequestAppProfile, logger)

			return
		}

		status = didexchangesvc.StateIDCompleted
	}

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponseWithLog(rw,
		&applicationProfileResponse{profile.InvitationID, status}, RequestAppProfile, logger)
}

// SendCHAPIRequest swagger:route POST /wallet/send-chapi-request wallet-bridge chapiRequest
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
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest, err.Error(), SendCHAPIRequest, logger)

		return
	}

	profile, err := o.store.GetProfileByUserID(request.Body.UserID)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusBadRequest, err.Error(), SendCHAPIRequest, logger)

		return
	}

	if profile.ConnectionID == "" {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, noConnectionFoundErr, SendCHAPIRequest, logger)

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), request.Body.Timeout)
	defer cancel()

	msgBytes, err := json.Marshal(map[string]interface{}{
		"@id":   uuid.New().String(),
		"@type": chapiRqstDIDCommMsgType,
		"data":  request.Body.Request,
	})
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), SendCHAPIRequest, logger)

		return
	}

	responseBytes, err := o.messenger.Send(msgBytes,
		messaging.SendByConnectionID(profile.ConnectionID),
		messaging.WaitForResponse(ctx, chapiRespDIDCommMsgType))
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			fmt.Sprintf(failedToSendCHAPIRequestErr, err), SendCHAPIRequest, logger)

		return
	}

	response, err := extractCHAPIResponse(responseBytes)
	if err != nil {
		commhttp.WriteErrorResponseWithLog(rw, http.StatusInternalServerError, err.Error(), SendCHAPIRequest, logger)

		return
	}

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponseWithLog(rw, &chapiResponse{
		Body: struct {
			Response json.RawMessage `json:"chapiResponse"`
		}{Response: response},
	}, SendCHAPIRequest, logger)
}

func (o *Operation) setupEventHandlers() error {
	// creates action channel
	actions := make(chan service.DIDCommAction)
	// registers action channel to listen for events
	if err := o.didExchange.RegisterActionEvent(actions); err != nil {
		return fmt.Errorf("register action event: %w", err)
	}

	// create state channel subscribers
	states := make(chan service.StateMsg)

	// registers state channels to listen for events
	if err := o.didExchange.RegisterMsgEvent(states); err != nil {
		return fmt.Errorf("register msg event: %w", err)
	}

	go service.AutoExecuteActionEvent(actions)
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

		// TODO update profile only wallet bridge didexchange, in this solution below warning will show up
		// everytime during adapter didexchange completion.
		err := o.store.UpdateProfile(&walletAppProfile{
			InvitationID: event.InvitationID(),
			ConnectionID: event.ConnectionID(),
		})
		if err != nil {
			logger.Warnf("Failed to update wallet application profile: %w", err)
		}
	}
}

//nolint:gocyclo //can't split function further and maintain readability.
func (o *Operation) waitForConnectionCompletion(ctx context.Context, profile *walletAppProfile) error {
	stateCh := make(chan service.StateMsg)

	if err := o.didExchange.RegisterMsgEvent(stateCh); err != nil {
		return fmt.Errorf("register msg event: %w", err)
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

			if event.InvitationID() == profile.InvitationID {
				logger.Debugf(
					"Received connection complete event for invitationID=%s", event.InvitationID())

				return nil
			}
		case <-ctx.Done():
			return fmt.Errorf("time out waiting for state 'completed'")
		}
	}
}

func prepareAppProfileRequest(r io.Reader) (*applicationProfileRequest, error) {
	var request applicationProfileRequest

	err := json.NewDecoder(r).Decode(&request.Body)
	if err != nil {
		return nil, err
	}

	if request.Body.UserID == "" {
		return nil, fmt.Errorf(invalidIDErr)
	}

	if request.Body.WaitForConnection && request.Body.Timeout == 0 {
		request.Body.Timeout = defaultSendMsgTimeout
	}

	return &request, nil
}

func prepareCHAPIRequest(r io.Reader) (*chapiRequest, error) {
	var request chapiRequest

	err := json.NewDecoder(r).Decode(&request.Body)
	if err != nil {
		return nil, err
	}

	if request.Body.UserID == "" {
		return nil, fmt.Errorf(invalidIDErr)
	}

	if len(request.Body.Request) == 0 {
		return nil, fmt.Errorf(invalidCHAPIRequestErr)
	}

	if request.Body.Timeout == 0 {
		request.Body.Timeout = defaultSendMsgTimeout
	}

	return &request, nil
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
