/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

const (
	// UserConsentCredentialType is the UserConsentCredential's JSON-LD type.
	UserConsentCredentialType = "UserConsentCredential"
)

// TODO - Remove/merge these models once RP adapter is refactored(Doc inside RP/Issuer did is
//  of json type rather than base64)

// UserConsentCredential represents the user's consent as a Verifiable Credential.
type UserConsentCredential struct {
	Base    *verifiable.Credential        `json:"-"`
	Subject *UserConsentCredentialSubject `json:"credentialSubject"`
}

// UserConsentCredentialSubject is the custom credentialSubject of a UserConsentCredential.
type UserConsentCredentialSubject struct {
	ID        string       `json:"id"`
	RPDID     *DIDDocument `json:"rpDID"`
	IssuerDID *DIDDocument `json:"issuerDID"`
	PresDef   string       `json:"presDef"`
}

// DIDDocument is how a DID document is transported over the wire.
// The ID is separate from the contents (DocB64URL) because of the self-certifying properties of some
// DID methods (eg. did:peer and did:key) where the ID is derived from the rest of the contents of the document.
type DIDDocument struct {
	ID        string `json:"id"`
	DocB64URL string `json:"docB64Url"`
}

// ConsentCredential is a VC that contains the issuer/rp/user did docs.
type ConsentCredential struct {
	Subject *ConsentCredentialSubject `json:"credentialSubject"`
}

// ConsentCredentialSubject struct for sending the issuer IssuerDIDDoc to wallet.
type ConsentCredentialSubject struct {
	ID           string  `json:"id"`
	IssuerDIDDoc *DIDDoc `json:"issuerDIDDoc"`
	RPDIDDoc     *DIDDoc `json:"rpDIDDoc"`
	UserDID      string  `json:"userDID"`
}

// DIDDoc is how a DID document is transported over the wire.
// The ID is separate from the contents (DocB64URL) because of the self-certifying properties of some
// DID methods (eg. did:peer and did:key) where the ID is derived from the rest of the contents of the document.
type DIDDoc struct {
	ID  string          `json:"id"`
	Doc json.RawMessage `json:"doc"`
}
