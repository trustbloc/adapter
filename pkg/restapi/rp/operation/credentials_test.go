/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
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
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ariesctx "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-adapter/pkg/presexch"
	vc2 "github.com/trustbloc/edge-adapter/pkg/vc"
)

// TODO - crypto.Crypto should support injection of document loader:
//  https://github.com/trustbloc/edge-adapter/issues/306
// nolint:gochecknoglobals,deadcode,varcheck,unused
var testDocumentLoader = createTestJSONLDDocumentLoader()

func TestParseWalletResponse(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		relyingParty, issuer, subject := trio(t)
		subjectDID := newPeerDID(t, subject)
		rpDID := newPeerDID(t, relyingParty)
		issuerDID := newPeerDID(t, issuer)

		simulateDIDExchange(t, relyingParty, rpDID, subject, subjectDID)

		localID := uuid.New().String()
		expectedLocal := map[string]*verifiable.Credential{
			localID: newUniversityDegreeVC(t, issuer, issuerDID),
		}
		remoteID := uuid.New().String()
		expectedRemote := map[string]*verifiable.Credential{
			remoteID: newAuthorizationVC(t, subjectDID.ID, rpDID, issuerDID),
		}
		vp := newPresentationSubmissionVP(t,
			subject,
			subjectDID,
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
			relyingParty.VDRegistry(),
			marshal(t, vp))
		require.NoError(t, err)
		require.Contains(t, actualLocal, localID)
		require.Equal(t, expectedLocal[localID].Subject, actualLocal[localID].Subject)
		sub, ok := actualRemote[remoteID].Subject.([]verifiable.Subject)
		require.True(t, ok)
		require.NotEmpty(t, sub)
		require.Equal(t, expectedRemote[remoteID].Subject, &sub[0])
	})

	t.Run("errInvalidCredential if vp cannot be parsed", func(t *testing.T) {
		relyingParty, issuer, subject := trio(t)
		authorizationVC := newAuthorizationVC(t,
			newPeerDID(t, subject).ID, newPeerDID(t, relyingParty), newPeerDID(t, issuer))
		vp, err := authorizationVC.Presentation()
		require.NoError(t, err)
		_, _, err = parseWalletResponse(nil, nil, marshal(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential on no credentials", func(t *testing.T) {
		relyingParty, subject, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		subjectDID := newPeerDID(t, subject)

		simulateDIDExchange(t, relyingParty, rpDID, subject, subjectDID)

		vp := newPresentationSubmissionVP(t, subject, subjectDID, nil)
		_, _, err := parseWalletResponse(
			&presexch.PresentationDefinitions{
				InputDescriptors: []*presexch.InputDescriptor{{
					ID: uuid.New().String(),
					Schema: &presexch.Schema{
						URI: []string{vc2.AuthorizationCredentialContext},
					},
				}},
			},
			relyingParty.VDRegistry(),
			marshal(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential if issuer's did doc is missing", func(t *testing.T) {
		relyingParty, subject, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		subjectDID := newPeerDID(t, subject)

		simulateDIDExchange(t, relyingParty, rpDID, subject, subjectDID)

		definitions := &presexch.PresentationDefinitions{
			InputDescriptors: []*presexch.InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &presexch.Schema{
					URI: []string{vc2.AuthorizationCredentialContext},
				},
			}},
		}
		vp := newPresentationSubmissionVP(t,
			subject,
			subjectDID,
			&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{{
				ID:   definitions.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newUserAuthorizationVCMissingIssuerDIDDoc(t, subjectDID.ID, rpDID))
		_, _, err := parseWalletResponse(
			definitions,
			relyingParty.VDRegistry(),
			marshal(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential if vc cannot be parsed", func(t *testing.T) {
		relyingParty, subject, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		subjectDID := newPeerDID(t, subject)

		simulateDIDExchange(t, relyingParty, rpDID, subject, subjectDID)

		definitions := &presexch.PresentationDefinitions{
			InputDescriptors: []*presexch.InputDescriptor{{
				ID: uuid.New().String(),
				Schema: &presexch.Schema{
					URI: []string{vc2.AuthorizationCredentialContext},
				},
			}},
		}
		vp := newPresentationSubmissionVP(t,
			subject,
			subjectDID,
			&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{{
				ID:   definitions.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newUserAuthorizationVCMissingIssuerDIDDoc(t, subjectDID.ID, rpDID))
		_, _, err := parseWalletResponse(definitions, relyingParty.VDRegistry(), marshal(t, vp))
		require.True(t, errors.Is(err, errInvalidCredential))
	})
}

func TestParseIssuerResponse(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		relyingParty, issuer, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		issuerDID := newPeerDID(t, issuer)

		simulateDIDExchange(t, relyingParty, rpDID, issuer, issuerDID)

		expectedVC := newCreditCardStatementVC(t, issuer, issuerDID)
		expectedVP := newPresentationSubmissionVP(t, issuer, issuerDID, nil, expectedVC)
		actualVC, err := parseIssuerResponse(&presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					JSON: expectedVP,
				},
			}},
		}, relyingParty.VDRegistry())
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
		relyingParty, issuer, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		issuerDID := newPeerDID(t, issuer)

		simulateDIDExchange(t, relyingParty, rpDID, issuer, issuerDID)

		_, err := parseIssuerResponse(&presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					JSON: newPresentationSubmissionVP(t, issuer, issuerDID, nil),
				},
			}},
		}, relyingParty.VDRegistry())
		require.True(t, errors.Is(err, errInvalidCredential))
	})
}

func newPresentationSubmissionVP(t *testing.T, holder *ariesctx.Provider, signingDID *did.Doc,
	submission *presexch.PresentationSubmission,
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

	return signVP(t, holder, signingDID, vp)
}

// TODO need to sign VCs in tests: https://github.com/trustbloc/edge-adapter/issues/304
func newAuthorizationVC(t *testing.T, subjectDID string, rpDID, issuerDID *did.Doc) *verifiable.Credential {
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
	bits, err := rpDID.JSONBytes()
	require.NoError(t, err)

	return &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld",
		},
		Types: []string{
			"VerifiableCredential",
			"AuthorizationCredential",
		},
		ID:     fmt.Sprintf("http://example.gov/credentials/%s", uuid.New().String()),
		Issued: util.NewTime(time.Now()),
		Issuer: verifiable.Issuer{
			ID: subjectDID,
		},
		Subject: []verifiable.Subject{{
			ID: subjectDID,
			CustomFields: map[string]interface{}{
				"subjectDID": subjectDID,
				"requestingPartyDIDDoc": map[string]interface{}{
					"id":  rpDID.ID,
					"doc": bits,
				},
			},
		}},
	}
}

func newCreditCardStatementVC(_ *testing.T, _ *ariesctx.Provider, signingDID *did.Doc) *verifiable.Credential {
	vc := &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
		},
		Types: []string{
			"VerifiableCredential",
			"CreditCardStatement",
		},
		ID: fmt.Sprintf("http://example.gov/credentials/%s", uuid.New().String()),
		Issuer: verifiable.Issuer{
			ID: signingDID.ID,
		},
		Issued: util.NewTime(time.Now()),
		Subject: []verifiable.Subject{{
			ID: "did:peer:user",
			CustomFields: map[string]interface{}{
				"stmt": map[string]interface{}{
					"description": "June 2020 Credit Card Statement",
					"url":         "http://acmebank.com/invoice.pdf",
					"accountId":   "xxxx-xxxx-xxxx-1234",
					"customer": map[string]interface{}{
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
		}},
	}

	return vc
}

func newUniversityDegreeVC(_ *testing.T, _ *ariesctx.Provider, signingDID *did.Doc) *verifiable.Credential {
	vc := &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		Types: []string{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
		ID: fmt.Sprintf("http://example.gov/credentials/%s", uuid.New().String()),
		Issuer: verifiable.Issuer{
			ID: signingDID.ID,
		},
		Issued: util.NewTime(time.Now()),
		Subject: []verifiable.Subject{{
			ID: "did:peer:user",
			CustomFields: map[string]interface{}{
				"degree": map[string]interface{}{
					"type":   "BachelorDegree",
					"degree": "MIT",
				},
				"name":   "Jayden Doe",
				"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
			},
		}},
		Schemas:      []verifiable.TypedID{},
		CustomFields: verifiable.CustomFields{},
	}

	return vc
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
		"testdata/context", contextFile))) // nolint: gocritic
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
