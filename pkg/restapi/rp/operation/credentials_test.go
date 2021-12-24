/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ariesctx "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-adapter/pkg/internal/testutil"
	vc2 "github.com/trustbloc/edge-adapter/pkg/vc"
)

func TestParseWalletResponse(t *testing.T) {
	t.Parallel()

	t.Run("valid response", func(t *testing.T) {
		t.Parallel()

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
			&presexch.PresentationDefinition{
				InputDescriptors: []*presexch.InputDescriptor{
					{
						ID: localID,
						Schema: []*presexch.Schema{{
							URI: "https://example.org/examples#UniversityDegreeCredential",
						}},
					},
					{
						ID: remoteID,
						Schema: []*presexch.Schema{{
							URI: "https://example.org/examples#AuthorizationCredential",
						}},
					},
				},
			},
			relyingParty.VDRegistry(),
			marshal(t, vp),
			testutil.DocumentLoader(t))
		require.NoError(t, err)
		require.Contains(t, actualLocal, localID)
		require.Equal(t, expectedLocal[localID].Subject, actualLocal[localID].Subject)
		sub, ok := actualRemote[remoteID].Subject.([]verifiable.Subject)
		require.True(t, ok)
		require.NotEmpty(t, sub)
		require.Equal(t, expectedRemote[remoteID].Subject, &sub[0])
	})

	t.Run("errInvalidCredential if vp cannot be parsed", func(t *testing.T) {
		t.Parallel()

		relyingParty, issuer, subject := trio(t)
		authorizationVC := newAuthorizationVC(t,
			newPeerDID(t, subject).ID, newPeerDID(t, relyingParty), newPeerDID(t, issuer))
		vp, err := verifiable.NewPresentation(verifiable.WithCredentials(authorizationVC))
		require.NoError(t, err)
		_, _, err = parseWalletResponse(nil, nil, marshal(t, vp), testutil.DocumentLoader(t))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential on no credentials", func(t *testing.T) {
		t.Parallel()

		relyingParty, subject, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		subjectDID := newPeerDID(t, subject)

		simulateDIDExchange(t, relyingParty, rpDID, subject, subjectDID)

		vp := newPresentationSubmissionVP(t, subject, subjectDID, nil)
		_, _, err := parseWalletResponse(
			&presexch.PresentationDefinition{
				InputDescriptors: []*presexch.InputDescriptor{{
					ID: uuid.New().String(),
					Schema: []*presexch.Schema{{
						URI: vc2.AuthorizationCredentialContext,
					}},
				}},
			},
			relyingParty.VDRegistry(),
			marshal(t, vp),
			testutil.DocumentLoader(t))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential if issuer's did doc is missing", func(t *testing.T) {
		t.Parallel()

		relyingParty, subject, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		subjectDID := newPeerDID(t, subject)

		simulateDIDExchange(t, relyingParty, rpDID, subject, subjectDID)

		definitions := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*presexch.Schema{{
					URI: vc2.AuthorizationCredentialContext,
				}},
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
			marshal(t, vp),
			testutil.DocumentLoader(t))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential if vc cannot be parsed", func(t *testing.T) {
		t.Parallel()

		relyingParty, subject, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		subjectDID := newPeerDID(t, subject)

		simulateDIDExchange(t, relyingParty, rpDID, subject, subjectDID)

		definitions := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*presexch.Schema{{
					URI: vc2.AuthorizationCredentialContext,
				}},
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
		_, _, err := parseWalletResponse(definitions, relyingParty.VDRegistry(), marshal(t, vp), testutil.DocumentLoader(t))
		require.True(t, errors.Is(err, errInvalidCredential))
	})
}

func TestParseIssuerResponse(t *testing.T) {
	t.Parallel()

	t.Run("valid response", func(t *testing.T) {
		t.Parallel()

		relyingParty, issuer, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		issuerDID := newPeerDID(t, issuer)

		simulateDIDExchange(t, relyingParty, rpDID, issuer, issuerDID)

		expectedVC := newCreditCardStatementVC(t, issuer, issuerDID)
		expectedVP := newPresentationSubmissionVP(t, issuer, issuerDID, nil, expectedVC)
		actualVC, err := parseIssuerResponse(&presentproof.PresentationV2{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					JSON: expectedVP,
				},
			}},
		}, relyingParty.VDRegistry(), testutil.DocumentLoader(t))
		require.NoError(t, err)
		require.Equal(t, expectedVC.Subject, actualVC.Subject)
	})

	t.Run("error if no attachments were provided", func(t *testing.T) {
		t.Parallel()

		_, err := parseIssuerResponse(&presentproof.PresentationV2{}, nil, testutil.DocumentLoader(t))
		require.Error(t, err)
	})

	t.Run("error if attachment's contents are malformed", func(t *testing.T) {
		t.Parallel()

		_, err := parseIssuerResponse(&presentproof.PresentationV2{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					Base64: "MALFORMED",
				},
			}},
		}, nil, testutil.DocumentLoader(t))
		require.Error(t, err)
	})

	t.Run("errInvalidCredential if VP cannot be parsed", func(t *testing.T) {
		t.Parallel()

		_, err := parseIssuerResponse(&presentproof.PresentationV2{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					JSON: map[string]interface{}{},
				},
			}},
		}, nil, testutil.DocumentLoader(t))
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("errInvalidCredential if VP has no credentials", func(t *testing.T) {
		t.Parallel()

		relyingParty, issuer, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		issuerDID := newPeerDID(t, issuer)

		simulateDIDExchange(t, relyingParty, rpDID, issuer, issuerDID)

		_, err := parseIssuerResponse(&presentproof.PresentationV2{
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
				Data: decorator.AttachmentData{
					JSON: newPresentationSubmissionVP(t, issuer, issuerDID, nil),
				},
			}},
		}, relyingParty.VDRegistry(), testutil.DocumentLoader(t))
		require.True(t, errors.Is(err, errInvalidCredential))
	})
}

func TestGetPresentationSubmissionCredentials(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		relyingParty, subject, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		subjectDID := newPeerDID(t, subject)

		simulateDIDExchange(t, relyingParty, rpDID, subject, subjectDID)

		pd := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*presexch.Schema{{
					URI: "https://example.org/examples#CreditCardStatement",
				}},
			}},
		}

		expectedVC := newCreditCardStatementVC(t, subject, subjectDID)
		expectedVP := newPresentationSubmissionVP(t, subject, subjectDID,
			&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{{
				ID:   pd.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			expectedVC,
		)

		pres := &presentproof.PresentationV2{
			Type: presentproofsvc.PresentationMsgTypeV2,
			PresentationsAttach: []decorator.Attachment{{
				ID:       "123",
				MimeType: "application/ld+json",
				Data: decorator.AttachmentData{
					JSON: expectedVP,
				},
			}},
		}

		credMap, err := getPresentationSubmissionCredentials(
			pres,
			pd,
			agent(t).VDRegistry(),
			testutil.DocumentLoader(t),
		)

		require.NoError(t, err)
		require.NotNil(t, credMap)
		require.Equal(t, 1, len(credMap))
	})

	t.Run("no presentation attachment", func(t *testing.T) {
		t.Parallel()

		_, err := getPresentationSubmissionCredentials(
			&presentproof.PresentationV2{
				Type: presentproofsvc.PresentationMsgTypeV2,
			}, nil, nil, nil,
		)

		require.Error(t, err)
		require.Contains(t, err.Error(), "no presentation attachments")
	})
}

func newPresentationSubmissionVP(t *testing.T, holder *ariesctx.Provider, signingDID *did.Doc,
	submission *presexch.PresentationSubmission,
	credentials ...*verifiable.Credential) *verifiable.Presentation {
	t.Helper()

	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(credentials...))
	require.NoError(t, err)

	vp.Context = append(vp.Context, presexch.PresentationSubmissionJSONLDContextIRI)
	vp.Type = append(vp.Type, presexch.PresentationSubmissionJSONLDType)
	vp.CustomFields = map[string]interface{}{
		"presentation_submission": submission,
	}

	return signVP(t, holder, signingDID, vp)
}

// TODO need to sign VCs in tests: https://github.com/trustbloc/edge-adapter/issues/304
func newAuthorizationVC(t *testing.T, subjectDID string, rpDID, issuerDID *did.Doc) *verifiable.Credential {
	t.Helper()

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
		Issued: util.NewTime(time.Now()),
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
	t.Helper()

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

func newCreditCardStatementVC(t *testing.T, _ *ariesctx.Provider, signingDID *did.Doc) *verifiable.Credential {
	t.Helper()

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

func newUniversityDegreeVC(t *testing.T, _ *ariesctx.Provider, signingDID *did.Doc) *verifiable.Credential {
	t.Helper()

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
