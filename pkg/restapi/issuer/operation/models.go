/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"

	adaptervc "github.com/trustbloc/edge-adapter/pkg/vc"
)

// ProfileDataRequest req for profile creation.
type ProfileDataRequest struct {
	ID                  string   `json:"id,omitempty"`
	Name                string   `json:"name"`
	SupportedVCContexts []string `json:"supportedVCContexts"`
	CallbackURL         string   `json:"callbackURL"`
}

// WalletConnect response from wallet.
type WalletConnect struct {
	Resp json.RawMessage `json:"walletResp,omitempty"`
}

// txnData contains session data.
type txnData struct {
	IssuerID            string                  `json:"issuerID,omitempty"`
	State               string                  `json:"state,omitempty"`
	DIDCommInvitation   *didexchange.Invitation `json:"didCommInvitation,omitempty"`
	SupportedVCContexts []string                `json:"supportedVCContexts,omitempty"`
}

// CHAPIRequest wallet chapi request.
type CHAPIRequest struct {
	Query             *CHAPIQuery             `json:"query,omitempty"`
	DIDCommInvitation *didexchange.Invitation `json:"invitation,omitempty"`
	Manifest          json.RawMessage         `json:"manifest,omitempty"`
}

// CHAPIQuery chapi query type data.
type CHAPIQuery struct {
	Type string `json:"type,omitempty"`
}

// ValidateConnectResp response from validate connect api.
type ValidateConnectResp struct {
	RedirectURL string `json:"redirectURL,omitempty"`
}

// ConsentCredentialReq consent credential request from wallet.
type ConsentCredentialReq struct {
	UserDID  string            `json:"userDID,omitempty"`
	RPDIDDoc *adaptervc.DIDDoc `json:"rpDIDDoc,omitempty"`
}
