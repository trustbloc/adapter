/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/peer"
	"github.com/mr-tron/base58"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-adapter/pkg/presexch"
	vc2 "github.com/trustbloc/edge-adapter/pkg/vc"
)

//nolint:gochecknoglobals
var testDocumentLoader = createTestJSONLDDocumentLoader()

func TestParseWalletResponse(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		subjectDID := newPeerDID(t)
		rpDID := newPeerDID(t)
		issuerDID := newPeerDID(t)
		localID := uuid.New().String()
		expectedLocal := map[string]*verifiable.Credential{
			localID: newUniversityDegreeVC(t),
		}
		remoteID := uuid.New().String()
		expectedRemote := map[string]*verifiable.Credential{
			remoteID: newUserAuthorizationVC(t, subjectDID.ID, rpDID, issuerDID),
		}
		vp := newPresentationSubmissionVP(t,
			&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{
				{
					ID:   localID,
					Path: "$.verifiableCredential[0]",
				},
				{
					ID:   remoteID,
					Path: "$.verifiableCredential[1]",
				},
			}},
			expectedLocal[localID], expectedRemote[remoteID])
		actualLocal, actualRemote, err := parseWalletResponse(
			&presexch.PresentationDefinitions{
				InputDescriptors: []*presexch.InputDescriptor{
					{
						ID: localID,
						Schema: &presexch.Schema{
							URI: []string{"https://www.w3.org/2018/credentials/examples/v1"},
						},
					},
					{
						ID: remoteID,
						Schema: &presexch.Schema{
							URI: []string{vc2.AuthorizationCredentialContext},
						},
					},
				},
			},
			nil,
			marshal(t, vp))
		require.NoError(t, err)
		require.Contains(t, actualLocal, localID)
		require.Equal(t, expectedLocal[localID], actualLocal[localID])
		require.Equal(t, expectedLocal, actualLocal)
		sub, ok := actualRemote[remoteID].Subject.([]verifiable.Subject)
		require.True(t, ok)
		require.NotEmpty(t, sub)
		require.Equal(t, expectedRemote[remoteID].Subject, &sub[0])
	})

	t.Run("errInvalidCredential if vp cannot be parsed", func(t *testing.T) {
		authorizationVC := newUserAuthorizationVC(t, newPeerDID(t).ID, newPeerDID(t), newPeerDID(t))
		vp, err := authorizationVC.Presentation()
		require.NoError(t, err)
		_, _, err = parseWalletResponse(nil, nil, marshal(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential on no credentials", func(t *testing.T) {
		vp := newPresentationSubmissionVP(t, nil)
		_, _, err := parseWalletResponse(
			&presexch.PresentationDefinitions{
				InputDescriptors: []*presexch.InputDescriptor{{
					ID: uuid.New().String(),
					Schema: &presexch.Schema{
						URI: []string{vc2.AuthorizationCredentialContext},
					},
				}},
			},
			nil,
			marshal(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential if issuer's did doc is missing", func(t *testing.T) {
		definitions := &presexch.PresentationDefinitions{
			InputDescriptors: []*presexch.InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &presexch.Schema{
					URI: []string{vc2.AuthorizationCredentialContext},
				},
			}},
		}
		vp := newPresentationSubmissionVP(t,
			&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{{
				ID:   definitions.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newUserAuthorizationVCMissingIssuerDIDDoc(t, newPeerDID(t).ID, newPeerDID(t)))
		_, _, err := parseWalletResponse(
			definitions,
			nil,
			marshal(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential if vc cannot be parsed", func(t *testing.T) {
		definitions := &presexch.PresentationDefinitions{
			InputDescriptors: []*presexch.InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &presexch.Schema{
					URI: []string{vc2.AuthorizationCredentialContext},
				},
			}},
		}
		vp := newPresentationSubmissionVP(t,
			&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{{
				ID:   definitions.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newUserAuthorizationVCMissingIssuerDIDDoc(t, newPeerDID(t).ID, newPeerDID(t)))
		_, _, err := parseWalletResponse(definitions, nil, marshal(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})
}

func TestParseIssuerResponse(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		expectedVC := newCreditCardStatementVC(t)
		expectedVP := newPresentationSubmissionVP(t, nil, expectedVC)
		actualVC, err := parseIssuerResponse(&presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					JSON: expectedVP,
				},
			}},
		}, nil)
		require.NoError(t, err)
		require.Equal(t, expectedVC.Subject, actualVC.Subject)
	})

	t.Run("error if no attachments were provided", func(t *testing.T) {
		_, err := parseIssuerResponse(&presentproof.Presentation{}, nil)
		require.Error(t, err)
	})

	t.Run("error if attachment's contents are malformed", func(t *testing.T) {
		_, err := parseIssuerResponse(&presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					Base64: "MALFORMED",
				},
			}},
		}, nil)
		require.Error(t, err)
	})

	t.Run("errInvalidCredential if VP cannot be parsed", func(t *testing.T) {
		_, err := parseIssuerResponse(&presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					JSON: map[string]interface{}{},
				},
			}},
		}, nil)
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential if VP has no credentials", func(t *testing.T) {
		_, err := parseIssuerResponse(&presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					JSON: newPresentationSubmissionVP(t, nil),
				},
			}},
		}, nil)
		require.True(t, errors.Is(err, errInvalidCredential))
	})
}

func newPresentationSubmissionVP(t *testing.T, submission *presexch.PresentationSubmission,
	credentials ...*verifiable.Credential) *verifiable.Presentation {
	vp := &verifiable.Presentation{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://trustbloc.github.io/context/vp/presentation-exchange-submission-v1.jsonld",
		},
		Type: []string{
			"VerifiablePresentation",
			"PresentationSubmission",
		},
		CustomFields: map[string]interface{}{
			"presentation_submission": submission,
		},
	}

	if len(credentials) > 0 {
		allCreds := make([]interface{}, len(credentials))

		for i := range credentials {
			allCreds[i] = credentials[i]
		}

		err := vp.SetCredentials(allCreds...)
		require.NoError(t, err)
	}

	addLDProof(t, vp)

	return vp
}

func newUserAuthorizationVC(t *testing.T, subjectDID string, rpDID, issuerDID *did.Doc) *verifiable.Credential {
	rpDocBits, err := rpDID.JSONBytes()
	require.NoError(t, err)

	rpDoc := make(map[string]interface{})

	err = json.Unmarshal(rpDocBits, &rpDoc)
	require.NoError(t, err)

	issuerDocBits, err := issuerDID.JSONBytes()
	require.NoError(t, err)

	issuerDoc := make(map[string]interface{})

	err = json.Unmarshal(issuerDocBits, &issuerDoc)
	require.NoError(t, err)

	return &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			vc2.AuthorizationCredentialContext,
		},
		Types: []string{
			"VerifiableCredential",
			"AuthorizationCredential",
		},
		ID: "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
		Issuer: verifiable.Issuer{
			ID: issuerDID.ID,
		},
		Issued: util.NewTimeWithTrailingZeroMsec(time.Now(), 0),
		Subject: &verifiable.Subject{
			ID: subjectDID,
			CustomFields: map[string]interface{}{
				"subjectDID": subjectDID,
				"requestingPartyDIDDoc": map[string]interface{}{
					"id":  rpDID.ID,
					"doc": rpDoc,
				},
				"issuerDIDDoc": map[string]interface{}{
					"id":  issuerDID.ID,
					"doc": issuerDoc,
				},
			},
		},
	}
}

func newUserAuthorizationVCMissingIssuerDIDDoc(t *testing.T, subjectDID string, rpDID *did.Doc) *verifiable.Credential {
	const (
		userAuthorizationVCTemplate = `{
	"@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld"
	],
	"type": [
		"VerifiableCredential",
		"AuthorizationCredential"
	],
	"id": "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
	"issuanceDate": "2020-03-16T22:37:26.544Z",
	"issuer": {
		"id": "%s"
	},
	"credentialSubject": {
		"id": "%s",
		"requestingPartyDIDDoc": %s,
		"subjectDID": "%s"
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
		userAuthorizationVCTemplate,
		subjectDID, subjectDID, rpDIDClaim, subjectDID)

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
			vocab:    "https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld",
			filename: "authorization-credential-v1.jsonld",
		},
		{
			vocab:    "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
			filename: "examples-ext-v1.jsonld",
		},
		{
			vocab:    "https://trustbloc.github.io/context/vp/presentation-exchange-submission-v1.jsonld",
			filename: "presentation_exchange.jsonld",
		},
		{
			vocab:    "https://trustbloc.github.io/context/vp/examples/mdl-v1.jsonld",
			filename: "mdl-v1.jsonld",
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
