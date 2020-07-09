package rp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

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

func newUserConsentVC(userDID string, rpDID, issuerDID *did.Doc) (*verifiable.Credential, error) {
	const (
		userConsentVCTemplate = `{
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
		"id": "%s"
	},
	"credentialSubject": {
		"id": "%s",
		"rpDID": %s,
		"issuerDID": %s,
		"presDef": "base64URLEncode(presDef)"
	}
}`
		didDocTemplate = `{
	"id": "%s",
	"docB64Url": "%s"
}`
	)

	bits, err := rpDID.JSONBytes()
	if err != nil {
		return nil, err
	}

	rpDIDClaim := fmt.Sprintf(didDocTemplate, rpDID.ID, base64.URLEncoding.EncodeToString(bits))

	bits, err = issuerDID.JSONBytes()
	if err != nil {
		return nil, err
	}

	issuerDIDClaim := fmt.Sprintf(didDocTemplate, issuerDID.ID, base64.URLEncoding.EncodeToString(bits))
	contents := fmt.Sprintf(
		userConsentVCTemplate,
		userDID, userDID, rpDIDClaim, issuerDIDClaim)

	return verifiable.ParseCredential([]byte(contents), verifiable.WithJSONLDDocumentLoader(testDocumentLoader))
}

func newCreditCardStatementVC() (*verifiable.Credential, error) {
	const template = `{
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
}`

	return verifiable.ParseCredential([]byte(template), verifiable.WithJSONLDDocumentLoader(testDocumentLoader))
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
