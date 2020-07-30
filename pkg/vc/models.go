/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"encoding/json"
)

const (
	// AuthorizationCredentialType vc type.
	AuthorizationCredentialType = "AuthorizationCredential"
)

// AuthorizationCredential is a VC that contains the issuer/rp/user did docs.
type AuthorizationCredential struct {
	Subject *AuthorizationCredentialSubject `json:"credentialSubject"`
}

// AuthorizationCredentialSubject struct for sending the issuer IssuerDIDDoc to wallet.
type AuthorizationCredentialSubject struct {
	ID           string  `json:"id,omitempty"`
	IssuerDIDDoc *DIDDoc `json:"issuerDIDDoc,omitempty"`
	RPDIDDoc     *DIDDoc `json:"requestingPartyDIDDoc,omitempty"`
	SubjectDID   string  `json:"subjectDID,omitempty"`
}

// DIDDoc is how a DID document is transported over the wire.
// The ID is separate from the contents because of the self-certifying properties of some
// DID methods (eg. did:peer and did:key) where the ID is derived from the rest of the contents of the document.
type DIDDoc struct {
	ID  string          `json:"id,omitempty"`
	Doc json.RawMessage `json:"doc,omitempty"`
}
