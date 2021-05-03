package rp

import (
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/edge-adapter/pkg/jsonld"
)

func newPresentationSubmissionVP(submission *presexch.PresentationSubmission,
	credentials ...*verifiable.Credential) (*verifiable.Presentation, error) {
	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(credentials...))
	if err != nil {
		return nil, fmt.Errorf("failed to create vp: %w", err)
	}

	vp.Context = append(vp.Context, presexch.PresentationSubmissionJSONLDContextIRI)
	vp.Type = append(vp.Type, presexch.PresentationSubmissionJSONLDType)
	vp.CustomFields = map[string]interface{}{
		"presentation_submission": submission,
	}

	return vp, nil
}

func newUserAuthorizationVC(subjectDID, rpDID, issuerDID *did.Doc) (*verifiable.Credential, error) {
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
		"issuerDIDDoc": %s,
		"subjectDIDDoc": %s
	}
}`
		didDocTemplate = `{
	"id": "%s",
	"doc": %s
}`
	)

	bits, err := rpDID.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal rp did: %w", err)
	}

	rpDIDClaim := fmt.Sprintf(didDocTemplate, rpDID.ID, bits)

	bits, err = issuerDID.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal issuer did: %w", err)
	}

	issuerDIDClaim := fmt.Sprintf(didDocTemplate, issuerDID.ID, bits)

	bits, err = subjectDID.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject did: %w", err)
	}

	subjectDIDClaim := fmt.Sprintf(didDocTemplate, subjectDID.ID, bits)

	contents := fmt.Sprintf(
		userAuthorizationVCTemplate,
		subjectDID.ID, subjectDID.ID, rpDIDClaim, issuerDIDClaim, subjectDIDClaim)

	docLoader, err := jsonld.DocumentLoader(mem.NewProvider())
	if err != nil {
		return nil, fmt.Errorf("failed to init document loader: %w", err)
	}

	// nolint:wrapcheck // ignore
	return verifiable.ParseCredential([]byte(contents), verifiable.WithJSONLDDocumentLoader(docLoader))
}

func newCreditCardStatementVC() *verifiable.Credential {
	return &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
		},
		ID: "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
		Types: []string{
			"VerifiableCredential",
			"CreditCardStatement",
		},
		Issuer: verifiable.Issuer{
			ID: "did:peer:issuer",
		},
		Issued: util.NewTimeWithTrailingZeroMsec(time.Now(), 0),
		Subject: &verifiable.Subject{
			ID: "did:peer:user",
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
						"price":         15.00, // nolint:gomnd
						"priceCurrency": "CAD",
					},
					"totalPaymentDue": map[string]interface{}{
						"@type":         "PriceSpecification",
						"price":         200.00, // nolint:gomnd
						"priceCurrency": "CAD",
					},
					"billingPeriod": "P30D",
					"paymentStatus": "http://schema.org/PaymentDue",
				},
			},
		},
	}
}

func newDriversLicenseVC() *verifiable.Credential {
	return &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://trustbloc.github.io/context/vc/examples/mdl-v1.jsonld",
		},
		ID: "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
		Types: []string{
			"VerifiableCredential",
			"mDL",
		},
		Issuer: verifiable.Issuer{
			ID: "did:peer:issuer",
		},
		Issued: util.NewTimeWithTrailingZeroMsec(time.Now(), 0),
		Subject: &verifiable.Subject{
			ID: "did:peer:user",
			CustomFields: map[string]interface{}{
				"given_name":      "John",
				"family_name":     "Smith",
				"document_number": "123-456-789",
			},
		},
	}
}
