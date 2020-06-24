/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/peer"
	"github.com/mr-tron/base58"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

const (
	didDocVC = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": [
    "VerifiableCredential",
    "DIDDocumentCredential"
  ],
  "credentialSubject": {
    "id": "%s",
    "didDoc": "%s"
  },
  "issuer": {
    "id": "did:peer:76e12ec712ebc6f1c221ebfeb1f"
  },
  "issuanceDate": "2010-01-01T19:23:24Z"
}`
	userConsentVC = `{
	"@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://trustbloc.github.io/context/vc/examples-v1.jsonld"
	],
	"type": [
		"VerifiableCredential",
		"UserConsentCredential"
	],
	"id": "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
	"issuanceDate": "2020-03-16T22:37:26.544Z",
	"issuer": {
		"id": "did:web:vc.transmute.world",
		"name": "University"
	},
	"credentialSubject": {
		"id": "did:peer:user",
		"rpDID": "did:peer:rp",
		"issuerDID": "did:peer:issuer",
		"presDef": "base64URLEncode(presDef)"
	}
}`
	validPresentationSubmissionVP = `{
  	"@context": [
    	"https://www.w3.org/2018/credentials/v1",
    	"https://trustbloc.github.io/context/vp/presentation-exchange-submission-v1.jsonld"
  	],
  	"type": [
    	"VerifiablePresentation",
    	"PresentationSubmission"
  	],
  	"presentation_submission": {
    	"descriptor_map": [{
    		"id": "banking_input_1",
    		"path": "$.verifiableCredential.[0]"
    	}]
  	},
  	"verifiableCredential": [{
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://trustbloc.github.io/context/vc/examples-v1.jsonld"
		],
		"type": [
			"VerifiableCredential",
			"CreditCardStatementCredential"
		],
		"id": "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
		"issuanceDate": "2020-03-16T22:37:26.544Z",
		"issuer": {
			"id": "did:peer:issuer"
		},
		"credentialSubject": {
			"id": "did:peer:user",
			"stmt": {
				"description": "June 2020 Credit Card Statement",
				"url": "http://acmebank.com/invoice.pdf",
				"accountId": "xxxx-xxxx-xxxx-1234",
				"customer": {
					"@type": "Person",
					"name": "Jane Doe"
				},
				"paymentDueDate": "2020-06-30T12:00:00",
				"minimumPaymentDue": {
					"@type": "PriceSpecification",
					"price": 15.00,
					"priceCurrency": "CAD"
				},
				"totalPaymentDue": {
					"@type": "PriceSpecification",
					"price": 200.00,
					"priceCurrency": "CAD"
				},
				"billingPeriod": "P30D",
				"paymentStatus": "http://schema.org/PaymentDue"			
			}
		}
    }]
}`
	invalidPresentationSubmissionVPNoCreds = `{
  	"@context": [
    	"https://www.w3.org/2018/credentials/v1",
    	"https://trustbloc.github.io/context/vp/presentation-exchange-submission-v1.jsonld"
  	],
  	"type": [
    	"VerifiablePresentation",
    	"PresentationSubmission"
  	],
  	"presentation_submission": {
    	"descriptor_map": [{
    		"id": "banking_input_1",
    		"path": "$.verifiableCredential.[0]"
    	}]
  	},
  	"verifiableCredential": []
}`
	presentationSubmissionVPCredsPlaceholder = `{
  	"@context": [
    	"https://www.w3.org/2018/credentials/v1",
    	"https://trustbloc.github.io/context/vp/presentation-exchange-submission-v1.jsonld"
  	],
  	"type": [
    	"VerifiablePresentation",
    	"PresentationSubmission"
  	],
  	"presentation_submission": {
    	"descriptor_map": [{
    		"id": "banking_input_1",
    		"path": "$.verifiableCredential.[0]"
    	}]
  	},
  	"verifiableCredential": [%s]
}`
	universityDegreeVC = `{
	"@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"
	],
	"type": [
		"VerifiableCredential",
		"UniversityDegreeCredential"
	],
	"id": "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
	"issuanceDate": "2020-03-16T22:37:26.544Z",
	"issuer": {
		"id": "did:web:vc.transmute.world",
		"name": "University"
	},
	"credentialSubject": {
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"degree": {
			"type": "BachelorDegree",
			"degree": "MIT"
		},
		"name": "Jayden Doe",
		"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
	}
}`
)

//nolint:gochecknoglobals
var testDocumentLoader = createTestJSONLDDocumentLoader()

func TestGetCustomCredentials(t *testing.T) {
	t.Run("valid vp", func(t *testing.T) {
		vp, _ := newCHAPIResponseVP(t)
		vpBytes, err := vp.MarshalJSON()
		require.NoError(t, err)
		_, _, err = getDIDDocAndUserConsentCredentials(vpBytes)
		require.NoError(t, err)
	})

	t.Run("errMalformedCredential on invalid vp", func(t *testing.T) {
		consentVC := newUserConsentVC(t)
		vp, err := consentVC.Presentation()
		require.NoError(t, err)
		vpBytes, err := vp.MarshalJSON()
		require.NoError(t, err)
		_, _, err = getDIDDocAndUserConsentCredentials(vpBytes)
		require.True(t, errors.Is(err, errMalformedCredential))
	})
}

func TestParseCredentials(t *testing.T) {
	t.Run("valid vp", func(t *testing.T) {
		vp, _ := newCHAPIResponseVP(t)
		vpBytes, err := vp.MarshalJSON()
		require.NoError(t, err)
		result, err := parseCredentials(vpBytes)
		require.NoError(t, err)
		for _, r := range result {
			require.NotNil(t, r)
		}
	})

	t.Run("errMalformedCredential if vp format is wrong", func(t *testing.T) {
		_, err := parseCredentials([]byte("invalid"))
		require.True(t, errors.Is(err, errMalformedCredential))
	})

	t.Run("errMalformedCredential if insufficient number of credentials", func(t *testing.T) {
		_, secretKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		userConsentVC := newUserConsentVC(t)
		vp, err := userConsentVC.Presentation()
		require.NoError(t, err)

		now := time.Now()
		err = vp.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			VerificationMethod:      "did:example:123",
			SignatureRepresentation: verifiable.SignatureJWS,
			SignatureType:           "Ed25519Signature2018",
			Suite:                   ed25519signature2018.New(suite.WithSigner(&testSigner{privKey: secretKey})),
			Created:                 &now,
			Domain:                  "user.example.com",
			Challenge:               uuid.New().String(),
			Purpose:                 "authentication",
		}, jsonld.WithDocumentLoader(testDocumentLoader))
		require.NoError(t, err)
		vpBytes, err := vp.MarshalJSON()
		require.NoError(t, err)
		_, err = parseCredentials(vpBytes)
		require.True(t, errors.Is(err, errMalformedCredential))
	})
}

func TestParseCustomCredentials(t *testing.T) {
	t.Run("valid credentials", func(t *testing.T) {
		vp, peerDID := newCHAPIResponseVP(t)
		peerDIDBytes, err := peerDID.JSONBytes()
		require.NoError(t, err)
		vpBytes, err := vp.MarshalJSON()
		require.NoError(t, err)
		creds, err := parseCredentials(vpBytes)
		require.NoError(t, err)
		didVC, consentVC, err := parseDIDDocAndUserConsentCredentials(creds)
		require.NoError(t, err)
		require.NotEmpty(t, didVC.Subject.DIDDoc)
		require.Equal(t, peerDID.ID, didVC.Subject.ID)
		require.Equal(t, base64.URLEncoding.EncodeToString(peerDIDBytes), didVC.Subject.DIDDoc)
		require.Equal(t, "did:peer:user", consentVC.Subject.ID)
		require.Equal(t, "did:peer:issuer", consentVC.Subject.IssuerDID)
		require.Equal(t, "did:peer:rp", consentVC.Subject.RPDID)
		require.Equal(t, "base64URLEncode(presDef)", consentVC.Subject.PresDef)
	})

	t.Run("errMalformedCredential on duplicate diddoc vc", func(t *testing.T) {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		didDocVC, _ := newDIDDocVC(t, publicKey)
		_, _, err = parseDIDDocAndUserConsentCredentials([2]*verifiable.Credential{didDocVC, didDocVC})
		require.True(t, errors.Is(err, errMalformedCredential))
	})

	t.Run("errMalformedCredential on duplicate consent VC", func(t *testing.T) {
		consentVC := newUserConsentVC(t)
		_, _, err := parseDIDDocAndUserConsentCredentials([2]*verifiable.Credential{consentVC, consentVC})
		require.True(t, errors.Is(err, errMalformedCredential))
	})

	t.Run("errMalformedCredential on unrecognized cred types", func(t *testing.T) {
		consentVC := newUserConsentVC(t)
		universityVC := newUniversityDegreeVC(t) // unrecognized
		_, _, err := parseDIDDocAndUserConsentCredentials([2]*verifiable.Credential{consentVC, universityVC})
		require.True(t, errors.Is(err, errMalformedCredential))
	})
}

func newCHAPIResponseVP(t *testing.T) (*verifiable.Presentation, *did.Doc) {
	publicKey, secretKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didDocVC, peerDID := newDIDDocVC(t, publicKey)
	vp := newCHAPIResponseVPWithDIDVC(t, secretKey, didDocVC)

	return vp, peerDID
}

func newCHAPIResponseVPWithDIDVC(
	t *testing.T, secretKey []byte, didDocVC *verifiable.Credential) *verifiable.Presentation {
	userConsentVC := newUserConsentVC(t)
	vp, err := userConsentVC.Presentation()
	require.NoError(t, err)

	err = vp.SetCredentials(didDocVC, userConsentVC)
	require.NoError(t, err)

	now := time.Now()
	err = vp.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		VerificationMethod:      "did:example:123",
		SignatureRepresentation: verifiable.SignatureJWS,
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519signature2018.New(suite.WithSigner(&testSigner{privKey: secretKey})),
		Created:                 &now,
		Domain:                  "user.example.com",
		Challenge:               uuid.New().String(),
		Purpose:                 "authentication",
	}, jsonld.WithDocumentLoader(testDocumentLoader))
	require.NoError(t, err)

	return vp
}

func newUserConsentVC(t *testing.T) *verifiable.Credential {
	vc, err := verifiable.ParseCredential(
		[]byte(userConsentVC), verifiable.WithJSONLDDocumentLoader(testDocumentLoader))
	require.NoError(t, err)

	return vc
}

func newDIDDocVC(t *testing.T, pubKey []byte) (*verifiable.Credential, *did.Doc) {
	doc := newPeerDID(t, pubKey)
	return newDIDDocVCWithDID(t, doc)
}

func newDIDDocVCWithDID(t *testing.T, doc *did.Doc) (*verifiable.Credential, *did.Doc) {
	docBytes, err := doc.JSONBytes()
	require.NoError(t, err)

	docVCString := fmt.Sprintf(didDocVC, doc.ID, base64.URLEncoding.EncodeToString(docBytes))
	vc, err := verifiable.ParseCredential([]byte(docVCString))
	require.NoError(t, err)

	return vc, doc
}

func newUniversityDegreeVC(t *testing.T) *verifiable.Credential {
	vc, err := verifiable.ParseCredential([]byte(universityDegreeVC))
	require.NoError(t, err)

	return vc
}

func newIssuerResponseVP(t *testing.T, template string) *verifiable.Presentation {
	vp, err := verifiable.ParseUnverifiedPresentation([]byte(template))
	require.NoError(t, err)

	_, secretKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	now := time.Now()
	err = vp.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		VerificationMethod:      "did:example:123",
		SignatureRepresentation: verifiable.SignatureJWS,
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519signature2018.New(suite.WithSigner(&testSigner{privKey: secretKey})),
		Created:                 &now,
		Domain:                  "user.example.com",
		Challenge:               uuid.New().String(),
		Purpose:                 "authentication",
	}, jsonld.WithDocumentLoader(testDocumentLoader))
	require.NoError(t, err)

	return vp
}

func newPeerDID(t *testing.T, pubKey []byte) *did.Doc {
	key := did.PublicKey{
		ID:         uuid.New().String(),
		Type:       "Ed25519VerificationKey2018",
		Controller: "did:example:123",
		Value:      pubKey,
	}
	doc, err := peer.NewDoc(
		[]did.PublicKey{key},
		[]did.VerificationMethod{{
			PublicKey:    key,
			Relationship: 0,
			Embedded:     true,
			RelativeURL:  false,
		}},
		did.WithService([]did.Service{{
			ID:              "didcomm",
			Type:            "did-communication",
			Priority:        0,
			RecipientKeys:   []string{base58.Encode(pubKey)},
			ServiceEndpoint: "http://example.com",
		}}),
	)
	require.NoError(t, err)

	return doc
}

type testSigner struct {
	privKey []byte
}

func (t *testSigner) Sign(plaintext []byte) ([]byte, error) {
	return ed25519.Sign(t.privKey, plaintext), nil
}

func createTestJSONLDDocumentLoader() *ld.CachingDocumentLoader {
	loader := verifiable.CachingJSONLDLoader()

	contexts := []struct {
		vocab    string
		filename string
	}{
		{
			vocab:    "https://www.w3.org/2018/credentials/v1",
			filename: "verifiable_credentials_v1.0.jsonld",
		},
		{
			vocab:    "http://schema.org/",
			filename: "schema.org.jsonld",
		},
		{
			vocab:    "https://trustbloc.github.io/context/vc/examples-v1.jsonld",
			filename: "trustbloc_example.jsonld",
		},
		{
			vocab:    "https://trustbloc.github.io/context/vp/presentation-exchange-submission-v1.jsonld",
			filename: "presentation_exchange.jsonld",
		},
	}

	for i := range contexts {
		addJSONLDCachedContextFromFile(loader, contexts[i].vocab, contexts[i].filename)
	}

	return loader
}

func addJSONLDCachedContextFromFile(loader *ld.CachingDocumentLoader, contextURL, contextFile string) {
	contextContent, err := ioutil.ReadFile(filepath.Clean(filepath.Join(
		"testdata/context", contextFile)))
	if err != nil {
		panic(err)
	}

	addJSONLDCachedContext(loader, contextURL, string(contextContent))
}

func addJSONLDCachedContext(loader *ld.CachingDocumentLoader, contextURL, contextContent string) {
	reader, err := ld.DocumentFromReader(strings.NewReader(contextContent))
	if err != nil {
		panic(err)
	}

	loader.AddDocument(contextURL, reader)
}
