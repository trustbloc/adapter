package rp

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/edge-adapter/pkg/presexch"
)

//nolint:gochecknoglobals
var testDocumentLoader = createTestJSONLDDocumentLoader()

func newPresentationSubmissionVP(submission *presexch.PresentationSubmission,
	credentials ...*verifiable.Credential) (*verifiable.Presentation, error) {
	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(credentials...))
	if err != nil {
		return nil, err
	}

	vp.Context = append(vp.Context, "https://trustbloc.github.io/context/vp/presentation-exchange-submission-v1.jsonld")
	vp.Type = append(vp.Type, "PresentationSubmission")
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
		return nil, err
	}

	rpDIDClaim := fmt.Sprintf(didDocTemplate, rpDID.ID, bits)

	bits, err = issuerDID.JSONBytes()
	if err != nil {
		return nil, err
	}

	issuerDIDClaim := fmt.Sprintf(didDocTemplate, issuerDID.ID, bits)

	bits, err = subjectDID.JSONBytes()
	if err != nil {
		return nil, err
	}

	subjectDIDClaim := fmt.Sprintf(didDocTemplate, subjectDID.ID, bits)

	contents := fmt.Sprintf(
		userAuthorizationVCTemplate,
		subjectDID.ID, subjectDID.ID, rpDIDClaim, issuerDIDClaim, subjectDIDClaim)

	return verifiable.ParseCredential([]byte(contents), verifiable.WithJSONLDDocumentLoader(testDocumentLoader))
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

func createTestJSONLDDocumentLoader() *jsonld.CachingDocumentLoader {
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

func addJSONLDCachedContextFromFile(loader *jsonld.CachingDocumentLoader, contextURL, contextFile string) {
	contextContent, err := ioutil.ReadFile(filepath.Clean(filepath.Join(
		"pkg/rp/testdata/context", contextFile))) // nolint: gocritic
	if err != nil {
		panic(err)
	}

	addJSONLDCachedContext(loader, contextURL, string(contextContent))
}

func addJSONLDCachedContext(loader *jsonld.CachingDocumentLoader, contextURL, contextContent string) {
	reader, err := ld.DocumentFromReader(strings.NewReader(contextContent))
	if err != nil {
		panic(err)
	}

	loader.AddDocument(contextURL, reader)
}
