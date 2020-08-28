/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"crypto/tls"
	"fmt"

	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	vdripkg "github.com/hyperledger/aries-framework-go/pkg/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/httpbinding"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"
)

const (
	didResolverURL = "http://localhost:8072/1.0/identifiers"
)

// BDDContext is a global context shared between different test suites in bddtests.
type BDDContext struct {
	Store     map[string]string
	tlsConfig *tls.Config
	VDRI      vdriapi.Registry
}

// NewBDDContext create new BDDContext.
func NewBDDContext(caCertPath string) (*BDDContext, error) {
	rootCAs, err := tlsutils.GetCertPool(false, []string{caCertPath})
	if err != nil {
		return nil, err
	}

	vdri, err := createVDRI(didResolverURL)
	if err != nil {
		return nil, err
	}

	return &BDDContext{
		Store:     make(map[string]string),
		tlsConfig: &tls.Config{RootCAs: rootCAs},
		VDRI:      vdri,
	}, nil
}

// TLSConfig return tls config.
func (b *BDDContext) TLSConfig() *tls.Config {
	return b.tlsConfig
}

func createVDRI(didResolverURL string) (vdriapi.Registry, error) {
	didResolverVDRI, err := httpbinding.New(didResolverURL,
		httpbinding.WithAccept(func(method string) bool {
			return method == "trustbloc"
		}))
	if err != nil {
		return nil, fmt.Errorf("failed to create new universal resolver vdri: %w", err)
	}

	vdriProvider, err := context.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create new vdri provider: %w", err)
	}

	return vdripkg.New(vdriProvider, vdripkg.WithVDRI(trustbloc.New(trustbloc.WithResolverURL(didResolverURL))),
		vdripkg.WithVDRI(didResolverVDRI)), nil
}
