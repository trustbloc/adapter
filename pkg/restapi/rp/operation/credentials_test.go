/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"

	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"

	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

//nolint:gochecknoglobals
var testDocumentLoader = createTestJSONLDDocumentLoader()

func TestParseWalletResponse(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		subject, requestingParty, issuer := gang(t)

		subjectDID := newPeerDID(t, subject)
		rpDID := newPeerDID(t, requestingParty)
		issuerDID := newPeerDID(t, issuer)

		err := requestingParty.VDRIRegistry().Store(subjectDID)
		require.NoError(t, err)

		origAuthorizationVC := newUserAuthZVC(t, issuer, subjectDID, rpDID, issuerDID)
		walletVP := newPresentationSubmissionVP(t, subject, subjectDID, origAuthorizationVC)
		customAuthorizationVC, _, err := parseWalletResponse(nil,
			requestingParty.VDRIRegistry(), marshal(t, walletVP))
		require.NoError(t, err)
		require.NotNil(t, customAuthorizationVC.Subject)
		// check user's DID
		require.Equal(t, subjectDID.ID, customAuthorizationVC.Subject.ID)
		// check issuer's DID
		require.NotNil(t, customAuthorizationVC.Subject.IssuerDIDDoc)
		require.Equal(t, issuerDID.ID, customAuthorizationVC.Subject.IssuerDIDDoc.ID)
		require.Equal(t, issuerDID.ID, parseDIDDoc(t, customAuthorizationVC.Subject.IssuerDIDDoc.Doc).ID)
		// check rp's DID
		require.NotNil(t, customAuthorizationVC.Subject.RPDIDDoc)
		require.Equal(t, rpDID.ID, customAuthorizationVC.Subject.RPDIDDoc.ID)
		require.Equal(t, rpDID.ID, parseDIDDoc(t, customAuthorizationVC.Subject.RPDIDDoc.Doc).ID)
	})

	t.Run("ignores credentials not of the expected type", func(t *testing.T) {
		subject, issuer, requestingParty := gang(t)
		subjectDID := newPeerDID(t, subject)
		issuerDID := newPeerDID(t, issuer)

		err := requestingParty.VDRIRegistry().Store(subjectDID)
		require.NoError(t, err)

		vp := newPresentationSubmissionVP(t,
			subject,
			subjectDID,
			newUniversityDegreeVC(t, issuer, issuerDID, subjectDID), // ignored
			newUserAuthZVC(t, issuer, subjectDID, newPeerDID(t, requestingParty), issuerDID),
		)
		customAuthorizationVC, origAuthorizationVC, err := parseWalletResponse(nil,
			requestingParty.VDRIRegistry(), marshal(t, vp))
		require.NoError(t, err)
		require.NotNil(t, customAuthorizationVC)
		require.NotNil(t, origAuthorizationVC)
	})

	t.Run("errInvalidCredential if vp cannot be parsed", func(t *testing.T) {
		subject, issuer, requestingParty := gang(t)
		authorizationVC := newUserAuthZVC(t,
			issuer, newPeerDID(t, subject), newPeerDID(t, requestingParty), newPeerDID(t, issuer))
		vp, err := authorizationVC.Presentation()
		require.NoError(t, err)
		vp.Type = nil
		_, _, err = parseWalletResponse(nil, requestingParty.VDRIRegistry(), marshal(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential on no credentials", func(t *testing.T) {
		subject := agent(t)
		vp := newPresentationSubmissionVP(t,subject, newPeerDID(t, subject))
		_, _, err := parseWalletResponse(nil, &mockvdri.MockVDRIRegistry{}, marshal(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential if issuer's did doc is missing", func(t *testing.T) {
		subject, requestingParty, issuer := gang(t)
		subjectDID := newPeerDID(t, subject)
		rpDID := newPeerDID(t, requestingParty)
		vp := newPresentationSubmissionVP(t,
			subject,
			subjectDID,
			newUserAuthZVC(t, issuer, subjectDID, rpDID, nil))
		_, _, err := parseWalletResponse(nil, &mockvdri.MockVDRIRegistry{}, marshal(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential if vc cannot be parsed", func(t *testing.T) {
		requestingParty, issuer, subject := gang(t)
		subjectDID := newPeerDID(t, subject)

		invalidVC := newUserAuthZVC(t, issuer, subjectDID, newPeerDID(t, requestingParty), newPeerDID(t, issuer))
		invalidVC.Subject = nil
		vp := newPresentationSubmissionVP(t,
			subject,
			subjectDID,
			invalidVC)
		_, _, err := parseWalletResponse(nil, requestingParty.VDRIRegistry(), marshal(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})
}

func TestParseIssuerResponse(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		issuer, requestingParty, _ := gang(t)
		issuerDID := newPeerDID(t, issuer)

		err := requestingParty.VDRIRegistry().Store(issuerDID)
		require.NoError(t, err)

		expectedVC := newCreditCardStatementVC(t, newPeerDID(t, agent(t)), issuer, issuerDID)
		expectedVP := newPresentationSubmissionVP(t, issuer, issuerDID, expectedVC)
		result, err := parseIssuerResponse(requestingParty.VDRIRegistry(), nil, &presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					JSON: expectedVP,
				},
			}},
		})
		require.NoError(t, err)
		require.Equal(t, expectedVP.Type, result.Base.Type)
		raw, err := result.Base.MarshalledCredentials()
		require.NoError(t, err)
		require.Len(t, raw, 1)
		resultVC, err := verifiable.ParseCredential(
			raw[0],
			verifiable.WithPublicKeyFetcher(
				verifiable.NewDIDKeyResolver(requestingParty.VDRIRegistry()).PublicKeyFetcher()))
		require.NoError(t, err)
		resultSub, ok := resultVC.Subject.([]verifiable.Subject)
		require.True(t, ok)
		require.NotEmpty(t, resultSub)
		require.Equal(t, expectedVC.Subject.(*verifiable.Subject).ID, resultSub[0].ID)
	})

	t.Run("error if no attachments were provided", func(t *testing.T) {
		_, err := parseIssuerResponse(nil, nil, &presentproof.Presentation{})
		require.Error(t, err)
	})

	t.Run("error if attachment's contents are malformed", func(t *testing.T) {
		_, err := parseIssuerResponse(nil, nil, &presentproof.Presentation{
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
		_, err := parseIssuerResponse(nil, nil, &presentproof.Presentation{
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

func newPresentationSubmissionVP(t *testing.T, holder *context.Provider, holderDID *did.Doc, credentials ...*verifiable.Credential) *verifiable.Presentation {
	descriptorMap := make([]map[string]string, len(credentials))

	for i := range credentials {
		descriptorMap[i] = map[string]string{
			"id":   uuid.New().String(),
			"path": fmt.Sprintf("$.verifiableCredential.[%d]", i),
		}
	}

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
			"presentation_submission": map[string]interface{}{
				"descriptor_map": descriptorMap,
			},
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

	addLDProof(t, vp, holder, holderDID)

	return vp
}

func newUserAuthZVC(t *testing.T, issuer *context.Provider, subjectDID, rpDID, issuerDID *did.Doc) *verifiable.Credential {
	vc := &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld",
		},
		ID: "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
		Types: []string{
			"VerifiableCredential",
			"AuthorizationCredential",
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
	}

	subject := &verifiable.Subject{
		ID:           subjectDID.ID,
		CustomFields: make(map[string]interface{}),
	}

	if issuerDID != nil {
		vc.Issuer = verifiable.Issuer{
			ID: issuerDID.ID,
		}

		subject.CustomFields["issuerDIDDoc"] = map[string]interface{}{
			"id":  issuerDID.ID,
			"doc": docToMap(t, issuerDID),
		}
	}

	if rpDID != nil {
		subject.CustomFields["requestingPartyDIDDoc"] = map[string]interface{}{
			"id":  rpDID.ID,
			"doc": docToMap(t, rpDID),
		}
	}

	vc.Subject = subject

	if issuerDID != nil {
		addLDProof(t, vc, issuer, issuerDID)
	}

	return vc
}

func newCreditCardStatementVC(t *testing.T, subjectDID *did.Doc, issuer *context.Provider, issuerDID *did.Doc) *verifiable.Credential {
	vc := &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
		},
		Types: []string{
			"VerifiableCredential",
			"CreditCardStatement",
		},
		ID: "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
		Issuer: verifiable.Issuer{
			ID: issuerDID.ID,
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
		Subject: &verifiable.Subject{
			ID: subjectDID.ID,
			CustomFields: map[string]interface{}{
				"stmt": map[string]interface{}{
					"description": "June 2020 Credit Card Statement",
					"url":         "http://acmebank.com/invoice.pdf",
					"accountId":   "xxxx-xxxx-xxxx-1234",
					"customer": map[string]string{
						"@type": "Person",
						"name":  "Jane Doe",
					},
					"paymentDueDate": "2020-06-30T12:00:00",
					"minimumPaymentDue": map[string]interface{}{
						"@type":         "PriceSpecification",
						"price":         15.00,
						"priceCurrency": "CAD",
					},
					"totalPaymentDue": map[string]interface{}{
						"@type":         "PriceSpecification",
						"price":         200.00,
						"priceCurrency": "CAD",
					},
					"billingPeriod": "P30D",
					"paymentStatus": "http://schema.org/PaymentDue",
				},
			},
		},
	}

	addLDProof(t, vc, issuer, issuerDID)

	return vc
}

func newUniversityDegreeVC(t *testing.T, issuer *context.Provider, issuerDID *did.Doc, subjectDID *did.Doc) *verifiable.Credential {
	vc := &verifiable.Credential{
		Context:        []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		ID:             "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
		Types:          []string{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
		Issuer: verifiable.Issuer{
			ID: issuerDID.ID,
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
		Subject: &verifiable.Subject{
			ID:           subjectDID.ID,
			CustomFields: map[string]interface{} {
				"degree": map[string]string {
					"type": "BachelorDegree",
					"degree": "MIT",
				},
				"name": "Jayden Doe",
				"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
			},
		},
	}

	addLDProof(t, vc, issuer, issuerDID)

	return vc
}

func newPeerDID(t *testing.T, agent *context.Provider) *did.Doc {
	doc, err := agent.VDRIRegistry().Create(
		"peer",
		vdri.WithServiceEndpoint("http://didcomm.test.com"),
		vdri.WithServiceType("did-communication"),
	)
	require.NoError(t, err)

	return doc
}

type ldProver interface {
	AddLinkedDataProof(*verifiable.LinkedDataProofContext, ...jsonld.ProcessorOpts) error
}

func addLDProof(t *testing.T, p ldProver, prover *context.Provider, proverDID *did.Doc) {
	t.Helper()

	now := time.Now()
	err := p.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType: ed25519signature2018.SignatureType,
		Suite: ed25519signature2018.New(suite.WithSigner(&legacySigner{
			verkey: proverDID.Authentication[0].PublicKey.ID,
			ks:     prover.Signer(),
		})),
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &now,
		VerificationMethod:      verMethod(proverDID),
		Challenge:               uuid.New().String(),
		Domain:                  uuid.New().String(),
		Purpose:                 "authentication",
	}, jsonld.WithDocumentLoader(testDocumentLoader))
	require.NoError(t, err)
}

type legacySigner struct {
	verkey string
	ks     legacykms.Signer
}

func (s *legacySigner) Sign(message []byte) ([]byte, error) {
	return s.ks.SignMessage(message, s.verkey)
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
