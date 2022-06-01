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

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

// JSONWebKey2020 type.
const JSONWebKey2020 = "JsonWebKey2020"

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
	keyType           kms.KeyType
	keyAgreementType  kms.KeyType
}

// NewTrustblocDIDCreator returns a new TrustblocDIDCreator.
func NewTrustblocDIDCreator(blocDomain, didAnchorOrigin, didcommInboundURL string,
	km KeyManager, rootCAs *x509.CertPool, token string, keyType, keyAgreementType kms.KeyType,
) (*TrustblocDIDCreator, error) {
	blocVDR, err := orb.New(nil, orb.WithDomain(blocDomain), orb.WithTLSConfig(&tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}), orb.WithAuthToken(token))
	if err != nil {
		return nil, fmt.Errorf("failed to init orb VDR: %w", err)
	}

	return &TrustblocDIDCreator{
		blocDomain:        blocDomain,
		didcommInboundURL: didcommInboundURL,
		km:                km,
		tblocDIDs:         blocVDR,
		didAnchorOrigin:   didAnchorOrigin,
		keyType:           keyType,
		keyAgreementType:  keyAgreementType,
	}, nil
}

// Create a new did:trustbloc DID.
func (p *TrustblocDIDCreator) Create() (*did.Doc, error) {
	didDoc, err := p.templateV1()
	if err != nil {
		return nil, fmt.Errorf("failed to create public keys : %w", err)
	}

	return p.orbCreate(didDoc)
}

// CreateV2 creates a did:orb DID for DIDComm V2.
func (p *TrustblocDIDCreator) CreateV2() (*did.Doc, error) {
	doc, err := p.templateV2()
	if err != nil {
		return nil, fmt.Errorf("creating didcomm v2 template did doc: %w", err)
	}

	return p.orbCreate(doc)
}

func (p *TrustblocDIDCreator) orbCreate(template *did.Doc) (*did.Doc, error) {
	recoverKey, err := p.newKey()
	if err != nil {
		return nil, fmt.Errorf("failed to create recover key : %w", err)
	}

	updateKey, err := p.newKey()
	if err != nil {
		return nil, fmt.Errorf("failed to create update key : %w", err)
	}

	docResolution, err := p.tblocDIDs.Create(template,
		vdrapi.WithOption(orb.RecoveryPublicKeyOpt, recoverKey),
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdrapi.WithOption(orb.AnchorOriginOpt, p.didAnchorOrigin),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create orb DID : %w", err)
	}

	return docResolution.DIDDocument, nil
}

func (p *TrustblocDIDCreator) templateV1() (*did.Doc, error) {
	_, pubKeyBytes, err := p.km.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("kms failed to create keyset: %w", err)
	}

	didcommRecipientKey, _ := fingerprint.CreateDIDKey(pubKeyBytes)

	vm, err := p.createVerificationMethod("", kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create new verification method from JWK: %w", err)
	}

	didDoc := &did.Doc{}

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *did.NewReferencedVerification(vm, did.AssertionMethod))

	didDoc.Service = []did.Service{{
		ID:              "didcomm",
		Type:            "did-communication",
		Priority:        0,
		RecipientKeys:   []string{didcommRecipientKey},
		ServiceEndpoint: model.NewDIDCommV1Endpoint(p.didcommInboundURL),
	}}

	return didDoc, nil
}

func (p *TrustblocDIDCreator) newKey() (crypto.PublicKey, error) {
	_, bits, err := p.km.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create key : %w", err)
	}

	return ed25519.PublicKey(bits), nil
}

func (p *TrustblocDIDCreator) templateV2() (*did.Doc, error) {
	didDoc := did.Doc{}

	auth, err := p.createVerification("", p.keyType, did.Authentication)
	if err != nil {
		return nil, fmt.Errorf("creating did doc Authentication: %w", err)
	}

	didDoc.Authentication = append(didDoc.Authentication, *auth)

	kagr, err := p.createVerification("#key-2", p.keyAgreementType, did.KeyAgreement)
	if err != nil {
		return nil, fmt.Errorf("creating did doc KeyAgreement: %w", err)
	}

	didDoc.KeyAgreement = append(didDoc.KeyAgreement, *kagr)

	assrt, err := p.createVerification("", p.keyType, did.AssertionMethod)
	if err != nil {
		return nil, fmt.Errorf("creating did doc AssertionMethod: %w", err)
	}

	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *assrt)

	didDoc.Service = []did.Service{{
		ID:              uuid.NewString(),
		ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{{URI: p.didcommInboundURL}}),
		Type:            "DIDCommMessaging",
	}}

	return &didDoc, nil
}

func (p *TrustblocDIDCreator) createVerification(id string, kt kms.KeyType, relationship did.VerificationRelationship,
) (*did.Verification, error) {
	vm, err := p.createVerificationMethod(id, kt)
	if err != nil {
		return nil, fmt.Errorf("creating verification: %w", err)
	}

	return did.NewReferencedVerification(vm, relationship), nil
}

func (p *TrustblocDIDCreator) createVerificationMethod(id string, kt kms.KeyType) (*did.VerificationMethod, error) {
	kid, pkBytes, err := p.km.CreateAndExportPubKeyBytes(kt)
	if err != nil {
		return nil, fmt.Errorf("creating public key: %w", err)
	}

	if id == "" {
		id = "#" + kid
	}

	var j *jwk.JWK

	if kt == kms.ED25519Type {
		j, err = jwksupport.JWKFromKey(ed25519.PublicKey(pkBytes))
		if err != nil {
			return nil, fmt.Errorf("converting ed25519 key to JWK: %w", err)
		}

		id = kid
	} else {
		j, err = jwkkid.BuildJWK(pkBytes, kt)
		if err != nil {
			return nil, fmt.Errorf("creating JWK: %w", err)
		}

		j.KeyID = kid
	}

	vm, err := did.NewVerificationMethodFromJWK(id, JSONWebKey2020, "", j)
	if err != nil {
		return nil, fmt.Errorf("creating verification method: %w", err)
	}

	return vm, nil
}
