/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
	commhttp "github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/http"
)

const (
	// API endpoints
	generateInvitationEndpoint = "/didexchange/invitation"
)

var logger = log.New("edge-adapter/issuer-operations")

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// New returns issuer rest instance.
func New(ariesCtx aries.CtxProvider) (*Operation, error) {
	didExClient, err := didexchange.New(ariesCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create aries did exchange client : %s", err)
	}

	return &Operation{
		didExClient: didExClient,
	}, nil
}

// Operation defines handlers for rp operations.
type Operation struct {
	didExClient *didexchange.Client
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(generateInvitationEndpoint, http.MethodGet, o.generateInvitation),
	}
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
