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

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/mr-tron/base58"
	trustblocdid "github.com/trustbloc/trustbloc-did-method/pkg/did"
	"github.com/trustbloc/trustbloc-did-method/pkg/did/doc"
	"github.com/trustbloc/trustbloc-did-method/pkg/did/option/create"
)

type trustblocDIDClient interface {
	CreateDID(string, ...create.Option) (*did.Doc, error)
}

// KeyManager creates keys.
type KeyManager interface {
	CreateAndExportPubKeyBytes(kt kms.KeyType) (string, []byte, error)
}

// TrustblocDIDCreator creates did:trustbloc DIDs.
type TrustblocDIDCreator struct {
	blocDomain        string
	didcommInboundURL string
	km                KeyManager
	tblocDIDs         trustblocDIDClient
}

// NewTrustblocDIDCreator returns a new TrustblocDIDCreator.
func NewTrustblocDIDCreator(blocDomain, didcommInboundURL string,
	km KeyManager, rootCAs *x509.CertPool) *TrustblocDIDCreator {
	return &TrustblocDIDCreator{
		blocDomain:        blocDomain,
		didcommInboundURL: didcommInboundURL,
		km:                km,
		tblocDIDs: trustblocdid.New(trustblocdid.WithTLSConfig(&tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		})),
	}
}

// Create a new did:trustbloc DID.
func (p *TrustblocDIDCreator) Create() (*did.Doc, error) {
	publicKeys, err := p.newPublicKeys()
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

	_, didcommRecipientKey, err := p.km.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("kms failed to create keyset: %w", err)
	}

	publicDID, err := p.tblocDIDs.CreateDID(
		p.blocDomain,
		create.WithPublicKey(publicKeys[0]),
		create.WithRecoveryPublicKey(recoverKey),
		create.WithUpdatePublicKey(updateKey),
		create.WithService(&did.Service{
			ID:              "didcomm",
			Type:            "did-communication",
			Priority:        0,
			RecipientKeys:   []string{base58.Encode(didcommRecipientKey)},
			ServiceEndpoint: p.didcommInboundURL,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create trustbloc DID : %w", err)
	}

	return publicDID, err
}

func (p *TrustblocDIDCreator) newPublicKeys() ([1]*doc.PublicKey, error) {
	keyID, bits, err := p.km.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return [1]*doc.PublicKey{}, fmt.Errorf("failed to create key : %w", err)
	}

	return [1]*doc.PublicKey{
		{
			ID:       keyID,
			Type:     doc.JWSVerificationKey2020,
			Encoding: doc.PublicKeyEncodingJwk,
			KeyType:  doc.Ed25519KeyType,
			Purposes: []string{
				doc.KeyPurposeAuthentication,
				doc.KeyPurposeAssertionMethod},
			Value: bits,
		},
	}, nil
}

func (p *TrustblocDIDCreator) newKey() (crypto.PublicKey, error) {
	_, bits, err := p.km.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create key : %w", err)
	}

	return ed25519.PublicKey(bits), nil
}
