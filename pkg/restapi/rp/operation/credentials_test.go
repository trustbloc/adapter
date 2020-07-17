/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
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

//nolint:gochecknoglobals
var testDocumentLoader = createTestJSONLDDocumentLoader()

func TestParseWalletResponse(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		userDID := newPeerDID(t)
		rpDID := newPeerDID(t)
		issuerDID := newPeerDID(t)
		origConsentVC := newUserConsentVC(t, userDID.ID, rpDID, issuerDID)
		vp := newPresentationSubmissionVP(t, origConsentVC)
		customConsentVC, resultOrigConsentVC, err := parseWalletResponse(nil, &mockvdri.MockVDRIRegistry{}, marshalVP(t, vp))
		require.NoError(t, err)
		require.Equal(t, origConsentVC.Subject, resultOrigConsentVC.Subject)
		require.NotNil(t, customConsentVC.Subject)
		// check user's DID
		require.Equal(t, userDID.ID, customConsentVC.Subject.ID)
		// check issuer's DID
		require.NotNil(t, customConsentVC.Subject.IssuerDIDDoc)
		require.Equal(t, issuerDID.ID, customConsentVC.Subject.IssuerDIDDoc.ID)
		require.Equal(t, issuerDID.ID, parseDIDDoc(t, customConsentVC.Subject.IssuerDIDDoc.Doc).ID)
		// check rp's DID
		require.NotNil(t, customConsentVC.Subject.RPDIDDoc)
		require.Equal(t, rpDID.ID, customConsentVC.Subject.RPDIDDoc.ID)
		require.Equal(t, rpDID.ID, parseDIDDoc(t, customConsentVC.Subject.RPDIDDoc.Doc).ID)
	})

	t.Run("ignores credentials not of the expected type", func(t *testing.T) {
		vp := newPresentationSubmissionVP(t,
			newUniversityDegreeVC(t), // ignored
			newUserConsentVC(t, newPeerDID(t).ID, newPeerDID(t), newPeerDID(t)),
		)
		customConsentVC, origConsentVC, err := parseWalletResponse(nil, &mockvdri.MockVDRIRegistry{}, marshalVP(t, vp))
		require.NoError(t, err)
		require.NotNil(t, customConsentVC)
		require.NotNil(t, origConsentVC)
	})

	t.Run("errInvalidCredential if vp cannot be parsed", func(t *testing.T) {
		consentVC := newUserConsentVC(t, newPeerDID(t).ID, newPeerDID(t), newPeerDID(t))
		vp, err := consentVC.Presentation()
		require.NoError(t, err)
		_, _, err = parseWalletResponse(nil, &mockvdri.MockVDRIRegistry{}, marshalVP(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential on no credentials", func(t *testing.T) {
		vp := newPresentationSubmissionVP(t)
		_, _, err := parseWalletResponse(nil, &mockvdri.MockVDRIRegistry{}, marshalVP(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential if issuer's did doc is missing", func(t *testing.T) {
		vp := newPresentationSubmissionVP(t, newUserConsentVCMissingIssuerDIDDoc(t, newPeerDID(t).ID, newPeerDID(t)))
		_, _, err := parseWalletResponse(nil, &mockvdri.MockVDRIRegistry{}, marshalVP(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential if vc cannot be parsed", func(t *testing.T) {
		vp := newPresentationSubmissionVPUnparseableVC(t)
		_, _, err := parseWalletResponse(nil, &mockvdri.MockVDRIRegistry{}, marshalVP(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})
}

func TestParseIssuerResponse(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		expectedVC := newCreditCardStatementVC(t)
		expectedVP := newPresentationSubmissionVP(t, expectedVC)
		result, err := parseIssuerResponse(nil, &presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					JSON: expectedVP,
				},
			}},
		})
		require.NoError(t, err)
		require.Equal(t, expectedVP, result.Base)
		raw, err := result.Base.MarshalledCredentials()
		require.NoError(t, err)
		require.Len(t, raw, 1)
		resultVC := parseVC(t, string(raw[0]))
		require.Equal(t, expectedVC.Subject, resultVC.Subject)
	})

	t.Run("error if no attachments were provided", func(t *testing.T) {
		_, err := parseIssuerResponse(nil, &presentproof.Presentation{})
		require.Error(t, err)
	})

	t.Run("error if attachment's contents are malformed", func(t *testing.T) {
		_, err := parseIssuerResponse(nil, &presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					Base64: "MALFORMED",
				},
			}},
		})
		require.Error(t, err)
	})

	t.Run("errInvalidCredential is VP cannot be parsed", func(t *testing.T) {
		_, err := parseIssuerResponse(nil, &presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					JSON: map[string]interface{}{},
				},
			}},
		})
		require.True(t, errors.Is(err, errInvalidCredential))
	})
}

func newPresentationSubmissionVP(t *testing.T, credentials ...*verifiable.Credential) *verifiable.Presentation {
	template := `{
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

	var contents string

	switch len(credentials) > 0 {
	case true:
		rawCreds := make([]string, len(credentials))

		for i := range credentials {
			raw, err := credentials[i].MarshalJSON()
			require.NoError(t, err)

			rawCreds[i] = string(raw)
		}

		contents = fmt.Sprintf(template, strings.Join(rawCreds, ", "))
	default:
		contents = strings.ReplaceAll(template, "%s", "")
	}

	vp, err := verifiable.ParseUnverifiedPresentation([]byte(contents))
	require.NoError(t, err)

	addLDProof(t, vp)

	return vp
}

func newPresentationSubmissionVPUnparseableVC(t *testing.T) *verifiable.Presentation {
	template := `{
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
  	"verifiableCredential": [{}]
}`

	vp, err := verifiable.ParseUnverifiedPresentation([]byte(template))
	require.NoError(t, err)

	addLDProof(t, vp)

	return vp
}

func newUserConsentVC(t *testing.T, userDID string, rpDID, issuerDID *did.Doc) *verifiable.Credential {
	const (
		userConsentVCTemplate = `{
	"@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://trustbloc.github.io/context/vc/consent-credential-v1.jsonld"
	],
	"type": [
		"VerifiableCredential",
		"ConsentCredential"
	],
	"id": "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
	"issuanceDate": "2020-03-16T22:37:26.544Z",
	"issuer": {
		"id": "%s"
	},
	"credentialSubject": {
		"id": "%s",
		"rpDIDDoc": %s,
		"issuerDIDDoc": %s,
		"userDID": "%s"
	}
}`
		didDocTemplate = `{
	"id": "%s",
	"doc": %s
}`
	)

	bits, err := rpDID.JSONBytes()
	require.NoError(t, err)

	rpDIDClaim := fmt.Sprintf(didDocTemplate, rpDID.ID, bits)

	bits, err = issuerDID.JSONBytes()
	require.NoError(t, err)

	issuerDIDClaim := fmt.Sprintf(didDocTemplate, issuerDID.ID, bits)
	contents := fmt.Sprintf(
		userConsentVCTemplate,
		userDID, userDID, rpDIDClaim, issuerDIDClaim, userDID)

	return parseVC(t, contents)
}

func newUserConsentVCMissingIssuerDIDDoc(t *testing.T, userDID string, rpDID *did.Doc) *verifiable.Credential {
	const (
		userConsentVCTemplate = `{
	"@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://trustbloc.github.io/context/vc/consent-credential-v1.jsonld"
	],
	"type": [
		"VerifiableCredential",
		"ConsentCredential"
	],
	"id": "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
	"issuanceDate": "2020-03-16T22:37:26.544Z",
	"issuer": {
		"id": "%s"
	},
	"credentialSubject": {
		"id": "%s",
		"rpDIDDoc": %s,
		"userDID": "%s"
	}
}`
		didDocTemplate = `{
	"id": "%s",
	"doc": %s
}`
	)

	bits, err := rpDID.JSONBytes()
	require.NoError(t, err)

	rpDIDClaim := fmt.Sprintf(didDocTemplate, rpDID.ID, bits)

	contents := fmt.Sprintf(
		userConsentVCTemplate,
		userDID, userDID, rpDIDClaim, userDID)

	return parseVC(t, contents)
}

func newCreditCardStatementVC(t *testing.T) *verifiable.Credential {
	const template = `{
	"@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld"
	],
	"type": [
		"VerifiableCredential",
		"CreditCardStatement"
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
}`

	return parseVC(t, template)
}

func newUniversityDegreeVC(t *testing.T) *verifiable.Credential {
	const contents = `{
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

	return parseVC(t, contents)
}

func parseVC(t *testing.T, contents string) *verifiable.Credential {
	vc, err := verifiable.ParseCredential([]byte(contents), verifiable.WithJSONLDDocumentLoader(testDocumentLoader))
	require.NoError(t, err)

	return vc
}

func newPeerDID(t *testing.T) *did.Doc {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

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

func addLDProof(t *testing.T, vp *verifiable.Presentation) {
	t.Helper()

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
			vocab:    "https://trustbloc.github.io/context/vc/consent-credential-v1.jsonld",
			filename: "consent-credential-v1.jsonld",
		},
		{
			vocab:    "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
			filename: "examples-ext-v1.jsonld",
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
