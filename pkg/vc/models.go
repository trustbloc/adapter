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
	ID        string `json:"id"`
	RPDID     string `json:"rpDID"`
	IssuerDID string `json:"issuerDID"`
	PresDef   string `json:"presDef"`
}
