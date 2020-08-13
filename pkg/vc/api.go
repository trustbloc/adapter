/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

const (
	// VerifiableCredential vc type.
	VerifiableCredential = "VerifiableCredential"

	// VerifiableCredentialContext vc base context.
	VerifiableCredentialContext = "https://www.w3.org/2018/credentials/v1"
)

// Crypto vc/vp signing apis.
type Crypto interface {
	SignCredential(*verifiable.Credential, string) (*verifiable.Credential, error)

	SignPresentation(*verifiable.Presentation, string) (*verifiable.Presentation, error)
}
