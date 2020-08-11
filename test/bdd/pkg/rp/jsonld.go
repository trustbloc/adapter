package rp

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
)

//nolint:gochecknoglobals
var testDocumentLoader = createTestJSONLDDocumentLoader()

func newVerifiablePresentation(credentials ...*verifiable.Credential) (*verifiable.Presentation, error) {
	template := `{
  	"@context": [
    	"https://www.w3.org/2018/credentials/v1"
  	],
  	"type": [
    	"VerifiablePresentation"
  	],
  	"verifiableCredential": [%s]
}`

	var contents string

	switch len(credentials) > 0 {
	case true:
		rawCreds := make([]string, len(credentials))

		for i := range credentials {
			raw, err := credentials[i].MarshalJSON()
			if err != nil {
				return nil, err
			}

			rawCreds[i] = string(raw)
		}

		contents = fmt.Sprintf(template, strings.Join(rawCreds, ", "))
	default:
		contents = strings.ReplaceAll(template, "%s", "")
	}

	vp, err := verifiable.ParseUnverifiedPresentation([]byte(contents))
	if err != nil {
		return nil, err
	}

	return vp, addLDProof(vp)
}

func newUserAuthorizationVC(subjectDID string, rpDID, issuerDID *did.Doc) (*verifiable.Credential, error) {
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
		"subjectDID": "%s"
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
	contents := fmt.Sprintf(
		userAuthorizationVCTemplate,
		subjectDID, subjectDID, rpDIDClaim, issuerDIDClaim, subjectDID)

	return verifiable.ParseCredential([]byte(contents), verifiable.WithJSONLDDocumentLoader(testDocumentLoader))
}

func newUnverifiableCreditCardStatementVC(issuerDID string) *verifiable.Credential {
	return &verifiable.Credential{
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
			ID: issuerDID,
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
		Subject: &verifiable.Subject{
			ID: "did:peer:bdd_tests_example_123",
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
}

func addLDProof(vp *verifiable.Presentation) error {
	_, secretKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	now := time.Now()

	return vp.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		VerificationMethod:      "did:example:123",
		SignatureRepresentation: verifiable.SignatureJWS,
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519signature2018.New(suite.WithSigner(&testSigner{privKey: secretKey})),
		Created:                 &now,
		Domain:                  "user.example.com",
		Challenge:               uuid.New().String(),
		Purpose:                 "authentication",
	}, jsonld.WithDocumentLoader(testDocumentLoader))
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
	}

	for i := range contexts {
		addJSONLDCachedContextFromFile(loader, contexts[i].vocab, contexts[i].filename)
	}

	return loader
}

func addJSONLDCachedContextFromFile(loader *ld.CachingDocumentLoader, contextURL, contextFile string) {
	contextContent, err := ioutil.ReadFile(filepath.Clean(filepath.Join(
		"pkg/rp/testdata/context", contextFile)))
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
