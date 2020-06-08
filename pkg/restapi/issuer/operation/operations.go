/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
	commhttp "github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/http"
)

const (
	// API endpoints
	issuerBasePath  = "/issuer"
	didCommBasePath = issuerBasePath + "/didcomm"

	walletConnectEndpoint      = didCommBasePath + "/connect/wallet"
	generateInvitationEndpoint = didCommBasePath + "/invitation"
)

var logger = log.New("edge-adapter/issuer-operations")

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Config defines configuration for rp operations.
type Config struct {
	AriesCtx   aries.CtxProvider
	UIEndpoint string
}

// New returns issuer rest instance.
func New(config *Config) (*Operation, error) {
	didExClient, err := didExchangeClient(config.AriesCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create aries did exchange client : %s", err)
	}

	return &Operation{
		didExClient: didExClient,
		uiEndpoint:  config.UIEndpoint,
	}, nil
}

// Operation defines handlers for rp operations.
type Operation struct {
	didExClient *didexchange.Client
	uiEndpoint  string
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(walletConnectEndpoint, http.MethodGet, o.walletConnect),
		support.NewHTTPHandler(generateInvitationEndpoint, http.MethodGet, o.generateInvitation),
	}
}

func (o *Operation) walletConnect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, o.uiEndpoint, http.StatusFound)
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
