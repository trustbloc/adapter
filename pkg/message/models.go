/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package message

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
)

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

// ConnReq model.
type ConnReq struct {
	ID     string            `json:"@id,omitempty"`
	Type   string            `json:"@type,omitempty"`
	Thread *decorator.Thread `json:"~thread,omitempty"`
	Data   *ConnReqData      `json:"data,omitempty"`
}

// ConnReqData model for error data in ConnReq.
type ConnReqData struct {
	DIDDoc json.RawMessage `json:"didDoc,omitempty"`
}

// ConnResp model.
type ConnResp struct {
	ID   string `json:"@id,omitempty"`
	Type string `json:"@type,omitempty"`
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
