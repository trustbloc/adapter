/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
	commhttp "github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/http"
)

const (
	// API endpoints
	generateInvitationEndpoint = "/didexchange/invitation"
)

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

func (o *Operation) generateInvitation(rw http.ResponseWriter, r *http.Request) {
	invitation, err := o.didExClient.CreateInvitation("issuer")
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to create invitation : %s", err.Error()))

		return
	}

	commhttp.WriteResponse(rw, invitation)
}
