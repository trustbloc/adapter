/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"

	"github.com/trustbloc/edge-adapter/pkg/presentationex"
)

// GetPresentationRequestResponse API response of getPresentationRequest.
type GetPresentationRequestResponse struct {
	PD  *presentationex.PresentationDefinitions `json:"pd"`
	Inv *didexchange.Invitation                 `json:"invitation"`
}

// CreateRPTenantRequest API request body to register an RP tenant.
type CreateRPTenantRequest struct {
	Label string `json:"label"`
}

// CreateRPTenantResponse API response body to register an RP tenant.
type CreateRPTenantResponse struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	PublicDID    string `json:"publicDID"`
}

// HandleCHAPIResponse is the input message to the chapiResponseHandler handler.
type HandleCHAPIResponse struct {
	InvitationID           string          `json:"invID"`
	VerifiablePresentation json.RawMessage `json:"vp"`
}

// HandleCHAPIResponseResult is the body of the response to a HandleCHAPIResponse request.
type HandleCHAPIResponseResult struct {
	RedirectURL string `json:"redirectURL"`
}
