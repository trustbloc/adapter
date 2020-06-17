/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "encoding/json"

// WalletConnect response from wallet.
type WalletConnect struct {
	Resp json.RawMessage `json:"walletResp,omitempty"`
}

// txnData contains session data.
type txnData struct {
	IssuerID string `json:"issuerID,omitempty"`
}
