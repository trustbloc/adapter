/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
)

// LegacyCrypto is designed to work with the Aries framework's legacy signer and did:peer vdri implementation.
type LegacyCrypto struct {
	ls      legacykms.Signer
	vdriReg vdri.Registry
}

// NewLegacy returns new LegacyCrypto.
func NewLegacy(s legacykms.Signer, v vdri.Registry) *LegacyCrypto {
	return &LegacyCrypto{
		ls:      s,
		vdriReg: v,
	}
}

// SignPresentation signs the presentation.
func (l *LegacyCrypto) SignPresentation(vp *verifiable.Presentation, signingDID *did.Doc) (*verifiable.Presentation, error) { //nolint: lll
	if len(signingDID.Authentication) == 0 || signingDID.Authentication[0].PublicKey.ID == "" {
		return nil, errors.New("signing DID missing 'authentication' or authentication key ID")
	}

	verKey := signingDID.Authentication[0].PublicKey.ID
	verMethod := fmt.Sprintf("%s%s", signingDID.ID, verKey)

	signer := &legacySigner{
		verkey: verKey,
		ks:     l.ls,
	}

	err := vp.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		VerificationMethod:      verMethod,
		SignatureRepresentation: verifiable.SignatureJWS,
		SignatureType:           Ed25519Signature2018,
		Suite:                   ed25519signature2018.New(suite.WithSigner(signer)),
		Purpose:                 Authentication,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to signed presentation : %w", err)
	}

	return vp, nil
}

type legacySigner struct {
	verkey string
	ks     legacykms.Signer
}

func (s *legacySigner) Sign(message []byte) ([]byte, error) {
	return s.ks.SignMessage(message, s.verkey)
}
