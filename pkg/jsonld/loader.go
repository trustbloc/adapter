/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	_ "embed" // nolint:gci // required for go:embed
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
)

var (
	//go:embed contexts/citizenship-v1.jsonld
	citizenshipV1Vocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/authorization-credential-v1.jsonld
	authorizationV1Vocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/assurance-credential-v1.jsonld
	assuranceV1Vocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/verifiable_credentials_v1.0.jsonld
	verifiableCredentialsV1Vocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/schema.org.jsonld
	schemaDotOrgVocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/examples-ext-v1.jsonld
	trustblocExamplesV1Vocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/mdl-v1.jsonld
	mdlV1Vocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/issuer-manifest-credential-v1.jsonld
	issuerManifestV1Vocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/governance.jsonld
	governanceVocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/credit-card-v1.jsonld
	creditCardV1Vocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/driver-license-evidence-v1.jsonld
	driverLicenseEvidenceV1Vocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/booking-reference-v1.jsonld
	bookingRefV1Vocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/w3id-citizenship-v1.jsonld
	w3idCitizenshipV1Vocab []byte // nolint:gochecknoglobals // required for go:embed
	//go:embed contexts/w3id-vaccination-v1.jsonld
	w3idVaccinationV1Vocab []byte // nolint:gochecknoglobals // required for go:embed
)

// nolint:gochecknoglobals // preset
var contextDocuments = []jsonld.ContextDocument{
	{
		URL:     "https://www.w3.org/2018/credentials/v1",
		Content: verifiableCredentialsV1Vocab,
	},
	{
		URL:     "http://schema.org/",
		Content: schemaDotOrgVocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld",
		Content: authorizationV1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
		Content: trustblocExamplesV1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples/mdl-v1.jsonld",
		Content: mdlV1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples/citizenship-v1.jsonld",
		Content: citizenshipV1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/assurance-credential-v1.jsonld",
		Content: assuranceV1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/issuer-manifest-credential-v1.jsonld",
		Content: issuerManifestV1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/governance/context.jsonld",
		Content: governanceVocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples/credit-card-v1.jsonld",
		Content: creditCardV1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples/driver-license-evidence-v1.jsonld",
		Content: driverLicenseEvidenceV1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples/booking-ref-v1.jsonld",
		Content: bookingRefV1Vocab,
	},
	{
		URL:         "https://w3id.org/citizenship/v1",
		DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld",
		Content:     w3idCitizenshipV1Vocab,
	},
	{
		URL:         "https://w3id.org/vaccination/v1",
		DocumentURL: "https://w3c-ccg.github.io/vaccination-vocab/context/v1/index.json",
		Content:     w3idVaccinationV1Vocab,
	},
}

// DocumentLoader returns an ld.DocumentLoader with all relevant contexts preloaded.
func DocumentLoader(s storage.Provider) (ld.DocumentLoader, error) {
	l, err := jsonld.NewDocumentLoader(s, jsonld.WithExtraContexts(contextDocuments...))
	if err != nil {
		return nil, fmt.Errorf("failed to init jsonld document loader: %w", err)
	}

	return l, nil
}
