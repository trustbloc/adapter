/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"fmt"
	"strings"

	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	// Ed25519Signature2018 ed25519 signature suite
	Ed25519Signature2018 = "Ed25519Signature2018"

	// Ed25519VerificationKey2018 ed25119 verification key
	Ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
)

const (
	// supported proof purpose

	// AssertionMethod assertionMethod
	AssertionMethod = "assertionMethod"

	// Authentication authentication
	Authentication = "authentication"
)

// New returns new instance of vc crypto.
func New(keyManager kms.KeyManager, c ariescrypto.Crypto, vdri vdriapi.Registry) *Crypto {
	return &Crypto{keyManager: keyManager, crypto: c, vdri: vdri}
}

// Crypto vc crypto.
type Crypto struct {
	keyManager kms.KeyManager
	crypto     ariescrypto.Crypto
	vdri       vdriapi.Registry
}

// SignCredential signs a credential.
func (c *Crypto) SignCredential(vc *verifiable.Credential, signingKeyID string) (*verifiable.Credential, error) {
	signingCtx, err := c.getLinkedDataProofContext(signingKeyID, Ed25519Signature2018, AssertionMethod)
	if err != nil {
		return nil, fmt.Errorf("sign credential : %w", err)
	}

	err = vc.AddLinkedDataProof(signingCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}

	return vc, nil
}

// SignPresentation signs a presentation.
// TODO should inject jsonld document loader: https://github.com/trustbloc/edge-adapter/issues/306
func (c *Crypto) SignPresentation(vp *verifiable.Presentation, signingKeyID string) (*verifiable.Presentation, error) {
	signingCtx, err := c.getLinkedDataProofContext(signingKeyID, Ed25519Signature2018, Authentication)
	if err != nil {
		return nil, fmt.Errorf("sign presentation : %w", err)
	}

	err = vp.AddLinkedDataProof(signingCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign presentation: %w", err)
	}

	return vp, nil
}

func (c *Crypto) getLinkedDataProofContext(signingKeyID, signatureType, proofPurpose string) (*verifiable.LinkedDataProofContext, error) { // nolint: lll
	s, err := newKMSSigner(c.keyManager, c.crypto, signingKeyID)
	if err != nil {
		return nil, err
	}

	err = c.validateDIDDoc(signingKeyID, proofPurpose)
	if err != nil {
		return nil, fmt.Errorf("validate did doc : %w", err)
	}

	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      signingKeyID,
		SignatureRepresentation: verifiable.SignatureJWS,
		SignatureType:           signatureType,
		Suite:                   ed25519signature2018.New(suite.WithSigner(s)),
		Purpose:                 proofPurpose,
	}

	return signingCtx, nil
}

func (c *Crypto) validateDIDDoc(signingKeyID, proofPurpose string) error {
	didID, err := GetDIDFromVerificationMethod(signingKeyID)
	if err != nil {
		return err
	}

	didDoc, err := c.vdri.Resolve(didID)
	if err != nil {
		return err
	}

	err = validateProofPurpose(proofPurpose, signingKeyID, didDoc)
	if err != nil {
		return err
	}

	return nil
}

// validateProofPurpose validates the proof purpose.
func validateProofPurpose(proofPurpose, method string, didDoc *did.Doc) error {
	const idParts = 2

	vmMatched := false

	// TODO remove this workaround when we are working with did docs that have correct verification method IDs:
	//  - aries framework: https://github.com/hyperledger/aries-framework-go/issues/2145
	//  - trustbloc did method: https://github.com/trustbloc/trustbloc-did-method/issues/169
	if strings.HasPrefix(method, "did:peer") {
		parts := strings.Split(method, "#")

		if len(parts) != idParts {
			return fmt.Errorf("method [%s] expected to be in did#keyID format", method)
		}

		method = "#" + parts[1]
	}

	switch proofPurpose {
	case AssertionMethod:
		assertionMethods := didDoc.VerificationMethods(did.AssertionMethod)[did.AssertionMethod]

		vmMatched = isValidVerificationMethod(method, assertionMethods)
	case Authentication:
		authMethods := didDoc.VerificationMethods(did.Authentication)[did.Authentication]

		vmMatched = isValidVerificationMethod(method, authMethods)
	default:
		return fmt.Errorf("proof purpose %s not supported", proofPurpose)
	}

	if !vmMatched {
		return fmt.Errorf("unable to find matching %s key IDs for given verification method %s",
			proofPurpose, method)
	}

	return nil
}

func isValidVerificationMethod(method string, vms []did.VerificationMethod) bool {
	for _, vm := range vms {
		if method == vm.PublicKey.ID {
			return true
		}
	}

	return false
}

type kmsSigner struct {
	keyHandle interface{}
	crypto    ariescrypto.Crypto
}

func newKMSSigner(keyManager kms.KeyManager, c ariescrypto.Crypto, signingKeyID string) (*kmsSigner, error) {
	// signingKeyID will contain didID#keyID
	keyID, err := GetKeyIDFromVerificationMethod(signingKeyID)
	if err != nil {
		return nil, err
	}

	keyHandler, err := keyManager.Get(keyID)
	if err != nil {
		return nil, err
	}

	return &kmsSigner{keyHandle: keyHandler, crypto: c}, nil
}

func (s *kmsSigner) Sign(data []byte) ([]byte, error) {
	v, err := s.crypto.Sign(data, s.keyHandle)
	if err != nil {
		return nil, err
	}

	return v, nil
}
