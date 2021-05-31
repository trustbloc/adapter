/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	_ "embed" //nolint:gci // required for go:embed
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// nolint:gochecknoglobals //embedded contexts
var (
	//go:embed contexts/assurance-credential-v1.jsonld
	assuranceV1Vocab []byte
	//go:embed contexts/authorization-credential-v1.jsonld
	authorizationV1Vocab []byte
	//go:embed contexts/issuer-manifest-credential-v1.jsonld
	issuerManifestV1Vocab []byte
)

var embedContexts = []jsonld.ContextDocument{ //nolint:gochecknoglobals
	{
		URL:     "https://trustbloc.github.io/context/vc/assurance-credential-v1.jsonld",
		Content: assuranceV1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld",
		Content: authorizationV1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/issuer-manifest-credential-v1.jsonld",
		Content: issuerManifestV1Vocab,
	},
}

// DocumentLoader returns a JSON-LD document loader with preloaded contexts.
func DocumentLoader(storageProvider storage.Provider) (*jsonld.DocumentLoader, error) {
	loader, err := jsonld.NewDocumentLoader(storageProvider, jsonld.WithExtraContexts(embedContexts...))
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return loader, nil
}
