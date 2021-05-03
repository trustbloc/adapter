/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

type trustblocDIDClient interface {
	Create(did *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error)
}

// KeyManager creates keys.
type KeyManager interface {
	CreateAndExportPubKeyBytes(kt kms.KeyType) (string, []byte, error)
}

// TrustblocDIDCreator creates DIDs.
type TrustblocDIDCreator struct {
	blocDomain        string
	didAnchorOrigin   string
	didcommInboundURL string
	km                KeyManager
	tblocDIDs         trustblocDIDClient
}

// NewTrustblocDIDCreator returns a new TrustblocDIDCreator.
func NewTrustblocDIDCreator(blocDomain, didAnchorOrigin, didcommInboundURL string,
	km KeyManager, rootCAs *x509.CertPool) (*TrustblocDIDCreator, error) {
	blocVDR, err := orb.New(nil, orb.WithDomain(blocDomain), orb.WithTLSConfig(&tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to init orb VDR: %w", err)
	}

	return &TrustblocDIDCreator{
		blocDomain:        blocDomain,
		didcommInboundURL: didcommInboundURL,
		km:                km,
		tblocDIDs:         blocVDR,
		didAnchorOrigin:   didAnchorOrigin,
	}, nil
}

// Create a new did:trustbloc DID.
func (p *TrustblocDIDCreator) Create() (*did.Doc, error) {
	didDoc, err := p.newPublicKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to create public keys : %w", err)
	}

	recoverKey, err := p.newKey()
	if err != nil {
		return nil, fmt.Errorf("failed to create recover key : %w", err)
	}

	updateKey, err := p.newKey()
	if err != nil {
		return nil, fmt.Errorf("failed to update recover key : %w", err)
	}

	_, pubKeyBytes, err := p.km.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("kms failed to create keyset: %w", err)
	}

	didcommRecipientKey, _ := fingerprint.CreateDIDKey(pubKeyBytes)

	didDoc.Service = []did.Service{{
		ID:              "didcomm",
		Type:            "did-communication",
		Priority:        0,
		RecipientKeys:   []string{didcommRecipientKey},
		ServiceEndpoint: p.didcommInboundURL,
	}}

	docResolution, err := p.tblocDIDs.Create(didDoc,
		vdrapi.WithOption(orb.RecoveryPublicKeyOpt, recoverKey),
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdrapi.WithOption(orb.AnchorOriginOpt, p.didAnchorOrigin),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create trustbloc DID : %w", err)
	}

	return docResolution.DIDDocument, nil
}

func (p *TrustblocDIDCreator) newPublicKeys() (*did.Doc, error) {
	didDoc := &did.Doc{}

	keyID, bits, err := p.km.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create key : %w", err)
	}

	jwk, err := jose.JWKFromKey(ed25519.PublicKey(bits))
	if err != nil {
		return nil, fmt.Errorf("failed to convert key to JWK: %w", err)
	}

	vm, err := did.NewVerificationMethodFromJWK(keyID, doc.JWSVerificationKey2020, "", jwk)
	if err != nil {
		return nil, fmt.Errorf("failed to create new verification method from JWK: %w", err)
	}

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *did.NewReferencedVerification(vm, did.AssertionMethod))

	return didDoc, nil
}

func (p *TrustblocDIDCreator) newKey() (crypto.PublicKey, error) {
	_, bits, err := p.km.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create key : %w", err)
	}

	return ed25519.PublicKey(bits), nil
}
