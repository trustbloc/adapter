/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	trustblocdid "github.com/trustbloc/trustbloc-did-method/pkg/did"
)

type trustblocDIDClient interface {
	CreateDID(string, ...trustblocdid.CreateDIDOption) (*did.Doc, error)
}

// KeyManager creates keys.
type KeyManager interface {
	Create(kms.KeyType) (string, interface{}, error)
	ExportPubKeyBytes(string) ([]byte, error)
}

// LegacyKeyManager is the aries framework's legacy key manager.
type LegacyKeyManager interface {
	CreateKeySet() (string, string, error)
}

// TrustblocDIDCreator creates did:trustbloc DIDs.
type TrustblocDIDCreator struct {
	blocDomain        string
	didcommInboundURL string
	km                KeyManager
	legacyKMS         LegacyKeyManager
	tblocDIDs         trustblocDIDClient
}

// NewTrustblocDIDCreator returns a new TrustblocDIDCreator.
func NewTrustblocDIDCreator(blocDomain, didcommInboundURL string,
	km KeyManager, legacyKMS LegacyKeyManager, rootCAs *x509.CertPool) *TrustblocDIDCreator {
	return &TrustblocDIDCreator{
		blocDomain:        blocDomain,
		didcommInboundURL: didcommInboundURL,
		km:                km,
		legacyKMS:         legacyKMS,
		tblocDIDs:         trustblocdid.New(trustblocdid.WithTLSConfig(&tls.Config{RootCAs: rootCAs})),
	}
}

// Create a new did:trustbloc DID.
func (p *TrustblocDIDCreator) Create() (*did.Doc, error) {
	publicKeys, err := p.newPublicKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to create public keys : %w", err)
	}

	_, didcommRecipientKey, err := p.legacyKMS.CreateKeySet()
	if err != nil {
		return nil, fmt.Errorf("failed to create keyset with legacy kms : %w", err)
	}

	publicDID, err := p.tblocDIDs.CreateDID(
		p.blocDomain,
		trustblocdid.WithPublicKey(publicKeys[0]),
		trustblocdid.WithPublicKey(publicKeys[1]),
		trustblocdid.WithPublicKey(publicKeys[2]),
		trustblocdid.WithService(&did.Service{
			ID:              "didcomm",
			Type:            "did-communication",
			Priority:        0,
			RecipientKeys:   []string{didcommRecipientKey},
			ServiceEndpoint: p.didcommInboundURL,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create trustbloc DID : %w", err)
	}

	return publicDID, err
}

func (p *TrustblocDIDCreator) newPublicKeys() ([3]*trustblocdid.PublicKey, error) {
	var keys = [3]struct {
		keyID string
		bits  []byte
	}{}

	for i := range keys {
		var err error

		keys[i].keyID, _, err = p.km.Create(kms.ED25519Type)
		if err != nil {
			return [3]*trustblocdid.PublicKey{}, fmt.Errorf("failed to create key : %w", err)
		}

		keys[i].bits, err = p.km.ExportPubKeyBytes(keys[i].keyID)
		if err != nil {
			return [3]*trustblocdid.PublicKey{}, fmt.Errorf("failed to export public key bytes : %w", err)
		}
	}

	return [3]*trustblocdid.PublicKey{
		{
			ID:       keys[0].keyID,
			Type:     trustblocdid.JWSVerificationKey2020,
			Encoding: trustblocdid.PublicKeyEncodingJwk,
			KeyType:  trustblocdid.Ed25519KeyType,
			Purpose:  []string{trustblocdid.KeyPurposeGeneral, trustblocdid.KeyPurposeAuth, trustblocdid.KeyPurposeAssertion},
			Value:    keys[0].bits,
		},
		{
			ID:       keys[1].keyID,
			Encoding: trustblocdid.PublicKeyEncodingJwk,
			KeyType:  trustblocdid.Ed25519KeyType,
			Value:    keys[1].bits,
			Recovery: true,
		},
		{
			ID:       keys[2].keyID,
			Encoding: trustblocdid.PublicKeyEncodingJwk,
			KeyType:  trustblocdid.Ed25519KeyType,
			Value:    keys[2].bits,
			Update:   true,
		},
	}, nil
}
