/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"crypto/tls"
	"fmt"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdripkg "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
)

const (
	didResolverURL = "http://localhost:8072/1.0/identifiers"
)

// BDDContext is a global context shared between different test suites in bddtests.
type BDDContext struct {
	Store     map[string]interface{}
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
		Store:     make(map[string]interface{}),
		tlsConfig: &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
		VDRI:      vdri,
	}, nil
}

// TLSConfig return tls config.
func (b *BDDContext) TLSConfig() *tls.Config {
	return b.tlsConfig
}

// GetString returns string value by key from bddcontext store
func (b *BDDContext) GetString(key string) (string, bool) {
	val, found := b.Store[key]
	if !found {
		return "", false
	}

	return fmt.Sprintf("%v", val), true
}

// Get returns value by key from bddcontext store
func (b *BDDContext) Get(key string) (interface{}, bool) {
	val, found := b.Store[key]

	return val, found
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

	p, err := peer.New(mockstore.NewMockStoreProvider())
	if err != nil {
		return nil, fmt.Errorf("create new vdri peer failed: %w", err)
	}

	return vdripkg.New(
		vdriProvider,
		vdripkg.WithVDR(p),
		vdripkg.WithVDR(trustbloc.New(nil, trustbloc.WithResolverURL(didResolverURL),
			trustbloc.WithDomain("testnet.trustbloc.local"))),
		vdripkg.WithVDR(didResolverVDRI),
	), nil
}
