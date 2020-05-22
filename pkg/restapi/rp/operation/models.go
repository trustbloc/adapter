/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

// CreatePresentationDefinitionReq create presentation definition request.
type CreatePresentationDefinitionReq struct {
	// TODO remove scopes and use handle after this task https://github.com/trustbloc/edge-adapter/issues/14
	Scopes []string `json:"scopes,omitempty"`
}
