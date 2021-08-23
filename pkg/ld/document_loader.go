/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	_ "embed" //nolint:gci // required for go:embed
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	jsonld "github.com/piprate/json-gold/ld"
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

var embedContexts = []ldcontext.Document{ //nolint:gochecknoglobals
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

// provider contains dependencies for the JSON-LD document loader.
type provider interface {
	JSONLDContextStore() ldstore.ContextStore
	JSONLDRemoteProviderStore() ldstore.RemoteProviderStore
}

// NewDocumentLoader returns a JSON-LD document loader with preloaded contexts.
func NewDocumentLoader(p provider, opts ...ld.DocumentLoaderOpts) (jsonld.DocumentLoader, error) {
	loader, err := ld.NewDocumentLoader(p, append(opts, ld.WithExtraContexts(embedContexts...))...)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	return loader, nil
}
