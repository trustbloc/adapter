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
	ID                          string            `json:"id,omitempty"`
	Name                        string            `json:"name"`
	SupportedVCContexts         []string          `json:"supportedVCContexts"`
	SupportsAssuranceCredential bool              `json:"supportsAssuranceCredential"`
	RequiresBlindedRoute        bool              `json:"requiresBlindedRoute"`
	URL                         string            `json:"url"`
	SupportsWACI                bool              `json:"supportsWACI"`
	OIDCProviderURL             string            `json:"oidcProvider"`
	OIDCClientParams            *OIDCClientParams `json:"oidcParams,omitempty"`
	CredentialScopes            []string          `json:"scopes,omitempty"`
	LinkedWalletURL             string            `json:"linkedWallet,omitempty"`
}

// OIDCClientParams optional parameters for setting the adapter's oidc client parameters statically.
type OIDCClientParams struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	SecretExpiry int    `json:"client_secret_expires_at"`
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
	CredScope         string                `json:"cred,omitempty"`
}

// CredentialHandlerRequest wallet chapi request.
type CredentialHandlerRequest struct {
	Query             *CHAPIQuery           `json:"query,omitempty"`
	DIDCommInvitation *outofband.Invitation `json:"invitation,omitempty"`
	Credentials       []json.RawMessage     `json:"credentials,omitempty"`
	WACI              bool                  `json:"waci,omitempty"`
	WalletRedirect    string                `json:"walletRedirect,omitempty"`
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
	SubjectDIDDoc *adaptervc.DIDDoc `json:"subjectDIDDoc,omitempty"`
	RPDIDDoc      *adaptervc.DIDDoc `json:"requestingPartyDIDDoc,omitempty"`
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
	OauthID          string `json:"oauthid,omitempty"`
}

// UserConnectionMapping stores mapping between the connectionID and issuer.
type UserConnectionMapping struct {
	ConnectionID string `json:"connectionID,omitempty"`
	IssuerID     string `json:"issuerID,omitempty"`
	Token        string `json:"token,omitempty"`
	OauthID      string `json:"oauthid,omitempty"`
	State        string `json:"state,omitempty"`
}

// UserInvitationMapping stores mapping between the inviationID and issuer.
type UserInvitationMapping struct {
	InvitationID string `json:"invitationID,omitempty"`
	IssuerID     string `json:"issuerID,omitempty"`
	TxID         string `json:"txID,omitempty"`
	TxToken      string `json:"txtoken,omitempty"`
	State        string `json:"state,omitempty"`
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
	Contexts    []string `json:"contexts,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
}

// IssuerTokenReq issuer user data token request.
type IssuerTokenReq struct {
	State string `json:"state,omitempty"`
}

// IssuerTokenResp issuer user data token response.
type IssuerTokenResp struct {
	Token  string `json:"token,omitempty"`
	UserID string `json:"userid,omitempty"`
}

// ReferenceCredentialData reference credential data.
type ReferenceCredentialData struct {
	ID string `json:"id,omitempty"`
}
