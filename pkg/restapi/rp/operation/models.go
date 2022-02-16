/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// gprrPartialMarshal is a GetPresentationRequestResponse, but with the invitation marshalled already,
// for more efficient sending logic.
type gprrPartialMarshal struct {
	PD             *presexch.PresentationDefinition `json:"pd,omitempty"`
	Inv            json.RawMessage                  `json:"invitation"`
	Credentials    []json.RawMessage                `json:"credentials,omitempty"`
	WACI           bool                             `json:"waci,omitempty"`
	WalletRedirect string                           `json:"walletRedirect,omitempty"`
}

// GetPresentationRequestResponse API response of getPresentationRequest.
type GetPresentationRequestResponse struct {
	PD             *presexch.PresentationDefinition `json:"pd,omitempty"`
	Inv            *wallet.GenericInvitation        `json:"invitation"`
	Credentials    []json.RawMessage                `json:"credentials,omitempty"`
	WACI           bool                             `json:"waci,omitempty"`
	WalletRedirect string                           `json:"walletRedirect,omitempty"`
}

// CreateRPTenantRequest API request body to register an RP tenant.
type CreateRPTenantRequest struct {
	Label                string   `json:"label"`
	Callback             string   `json:"callback"`
	Scopes               []string `json:"scopes"`
	RequiresBlindedRoute bool     `json:"requiresBlindedRoute"`
	SupportsWACI         bool     `json:"supportsWACI"`
	LinkedWalletURL      string   `json:"linkedWalletURL"`
	IsDIDCommV1          bool     `json:"isDIDCommV1"`
}

// CreateRPTenantResponse API response body to register an RP tenant.
type CreateRPTenantResponse struct {
	ClientID             string   `json:"clientID"`
	ClientSecret         string   `json:"clientSecret"`
	PublicDID            string   `json:"publicDID"`
	Scopes               []string `json:"scopes"`
	RequiresBlindedRoute bool     `json:"requiresBlindedRoute"`
	SupportsWACI         bool     `json:"supportsWACI"`
	LinkedWalletURL      string   `json:"linkedWalletURL"`
	IsDIDCommV1          bool     `json:"isDIDCommV1"`
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

// DIDDocReq model.
type DIDDocReq struct {
	ID   string `json:"@id,omitempty"`
	Type string `json:"@type,omitempty"`
}

// DIDDocResp model.
type DIDDocResp struct {
	ID   string          `json:"@id,omitempty"`
	Type string          `json:"@type,omitempty"`
	Data *DIDDocRespData `json:"data,omitempty"`
}

// DIDDocRespData model for error data in DIDDocResp.
type DIDDocRespData struct {
	ErrorMsg string          `json:"errorMsg,omitempty"`
	DIDDoc   json.RawMessage `json:"didDoc,omitempty"`
}

// ErrorResp model.
type ErrorResp struct {
	ID   string         `json:"@id,omitempty"`
	Type string         `json:"@type,omitempty"`
	Data *ErrorRespData `json:"data,omitempty"`
}

// ErrorRespData model for error data in ErrorResp.
type ErrorRespData struct {
	ErrorMsg string `json:"errorMsg,omitempty"`
}
