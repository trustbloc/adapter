/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"

	adaptervc "github.com/trustbloc/edge-adapter/pkg/vc"
)

// ProfileDataRequest req for profile creation.
type ProfileDataRequest struct {
	ID                          string   `json:"id,omitempty"`
	Name                        string   `json:"name"`
	SupportedVCContexts         []string `json:"supportedVCContexts"`
	SupportsAssuranceCredential bool     `json:"SupportsAssuranceCredential"`
	URL                         string   `json:"url"`
}

// WalletConnect response from wallet.
type WalletConnect struct {
	Resp json.RawMessage `json:"walletResp,omitempty"`
}

// txnData contains session data.
type txnData struct {
	IssuerID          string                `json:"issuerID,omitempty"`
	State             string                `json:"state,omitempty"`
	DIDCommInvitation *outofband.Invitation `json:"didCommInvitation,omitempty"`
	Token             string                `json:"token,omitempty"`
}

// CHAPIRequest wallet chapi request.
type CHAPIRequest struct {
	Query                *CHAPIQuery           `json:"query,omitempty"`
	DIDCommInvitation    *outofband.Invitation `json:"invitation,omitempty"`
	Credentials          []json.RawMessage     `json:"credentials,omitempty"`
	CredentialGovernance json.RawMessage       `json:"credentialGovernance,omitempty"`
}

// CHAPIQuery chapi query type data.
type CHAPIQuery struct {
	Type string `json:"type,omitempty"`
}

// ValidateConnectResp response from validate connect api.
type ValidateConnectResp struct {
	RedirectURL string `json:"redirectURL,omitempty"`
}

// AuthorizationCredentialReq authorization credential request from wallet.
type AuthorizationCredentialReq struct {
	SubjectDID string            `json:"subjectDID,omitempty"`
	RPDIDDoc   *adaptervc.DIDDoc `json:"requestingPartyDIDDoc,omitempty"`
}

// AuthorizationCredentialHandle stores authorization credential related data.
type AuthorizationCredentialHandle struct {
	ID               string `json:"id,omitempty"`
	IssuerDID        string `json:"issuerDID,omitempty"`
	SubjectDID       string `json:"subjectDID,omitempty"`
	RPDID            string `json:"rpDID,omitempty"`
	UserConnectionID string `json:"userConnectionID,omitempty"`
	RPConnectionID   string `json:"rpConnectionID,omitempty"`
	Token            string `json:"token,omitempty"`
	IssuerID         string `json:"issuerID,omitempty"`
}

// UserConnectionMapping stores mapping between the connectionID and issuer.
type UserConnectionMapping struct {
	ConnectionID string `json:"connectionID,omitempty"`
	IssuerID     string `json:"issuerID,omitempty"`
	Token        string `json:"token,omitempty"`
}

// UserDataReq request to issuer for the user data.
type UserDataReq struct {
	Token string `json:"token,omitempty"`
}

// UserDataRes response from the issuer for user data.
type UserDataRes struct {
	Data     json.RawMessage `json:"data,omitempty"`
	Metadata *UserMetadata   `json:"metadata,omitempty"`
}

// UserMetadata contains metadata associated with user data.
type UserMetadata struct {
	Contexts []string `json:"contexts,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
}

// IssuerTokenReq issuer user data token request.
type IssuerTokenReq struct {
	State string `json:"state,omitempty"`
}

// IssuerTokenResp issuer user data token response.
type IssuerTokenResp struct {
	Token string `json:"token,omitempty"`
}

// ReferenceCredentialData reference credential data.
type ReferenceCredentialData struct {
	ID string `json:"id,omitempty"`
}
