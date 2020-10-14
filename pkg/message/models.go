/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package message

import "encoding/json"

// DIDDocReq model.
type DIDDocReq struct {
	ID   string `json:"@id"`
	Type string `json:"@type"`
}

// DIDDocResp model.
type DIDDocResp struct {
	ID   string          `json:"@id"`
	Type string          `json:"@type"`
	Data *DIDDocRespData `json:"data"`
}

// DIDDocRespData model for error data in DIDDocResp.
type DIDDocRespData struct {
	ErrorMsg string          `json:"errorMsg"`
	DIDDoc   json.RawMessage `json:"didDoc"`
}
