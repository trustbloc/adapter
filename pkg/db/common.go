/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

// TODO implement schema migrations https://github.com/trustbloc/edge-adapter/issues/25
func schemas() []string {
	return []string{
		ddlCreateEndUser,
		ddlCreateIndexOnSub,
		ddlCreateRelyingParty,
		ddlRelyingPartyClientIDIndex,
		ddlCreateOidcRequest,
		ddlOidcRequestRelyingPartyIDIndex,
	}
}
