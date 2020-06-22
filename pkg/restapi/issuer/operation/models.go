/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
)

// ProfileDataRequest req for profile creation.
type ProfileDataRequest struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	CallbackURL string `json:"callbackURL"`
}

// WalletConnect response from wallet.
type WalletConnect struct {
	Resp json.RawMessage `json:"walletResp,omitempty"`
}

// txnData contains session data.
type txnData struct {
	IssuerID          string                  `json:"issuerID,omitempty"`
	State             string                  `json:"state,omitempty"`
	DIDCommInvitation *didexchange.Invitation `json:"didCommInvitation,omitempty"`
}

// ValidateConnectResp response from validate connect api.
type ValidateConnectResp struct {
	RedirectURL string `json:"redirectURL,omitempty"`
}
