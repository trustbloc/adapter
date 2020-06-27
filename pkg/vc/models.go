/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

const (
	// UserConsentCredentialType is the UserConsentCredential's JSON-LD type.
	UserConsentCredentialType = "UserConsentCredential"
)

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
