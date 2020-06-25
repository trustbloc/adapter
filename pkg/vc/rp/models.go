/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rp

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/edge-adapter/pkg/presentationex"
)

const (
	// DIDDocumentCredentialType is the DIDDocumentCredential's JSON-LD type.
	DIDDocumentCredentialType = "DIDDocumentCredential"
)

// DIDDocumentCredential is a VC that contains a DID document.
type DIDDocumentCredential struct {
	Base    *verifiable.Credential   `json:"-"`
	Subject *DIDDocCredentialSubject `json:"credentialSubject"`
}

// DIDDocCredentialSubject is the custom credentialSubject of a DIDDocumentCredential.
type DIDDocCredentialSubject struct {
	ID     string `json:"id"`
	DIDDoc string `json:"didDoc"`
}

// PresentationSubmissionPresentation is the PresentationSubmission VerifiablePresentation.
// https://identity.foundation/presentation-exchange/#presentation-submission.
type PresentationSubmissionPresentation struct {
	Base                   *verifiable.Presentation               `json:"-"`
	PresentationSubmission *presentationex.PresentationSubmission `json:"presentation_submission,omitempty"`
}
