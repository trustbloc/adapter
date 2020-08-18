/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/edge-adapter/pkg/internal/common/adapterutil"
)

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

// AuthZSubject returns the AuthorizationCredentialSubject from the verifiable credential.
func AuthZSubject(vc json.Marshaler) (*AuthorizationCredentialSubject, error) {
	authz := &AuthorizationCredential{}

	return authz.Subject, adapterutil.DecodeJSONMarshaller(vc, authz)
}
