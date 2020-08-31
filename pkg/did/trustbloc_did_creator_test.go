/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
	trustblocdid "github.com/trustbloc/trustbloc-did-method/pkg/did"
)

func TestNewTrustblocDIDCreator(t *testing.T) {
	t.Run("returns did creator", func(t *testing.T) {
		c := NewTrustblocDIDCreator("", "", &mockKeyManager{}, nil)
		require.NotNil(t, c)
	})
}

func TestTrustblocDIDCreator_Create(t *testing.T) {
	t.Run("creates trustbloc DID", func(t *testing.T) {
		domain := "http://example.trustbloc.com"
		expected := newDIDDoc()
		didcommURL := "http://example.didcomm.com"
		c := NewTrustblocDIDCreator(domain, didcommURL, &mockKeyManager{}, nil)
		c.tblocDIDs = &stubTrustblocClient{
			createFunc: func(d string, options ...trustblocdid.CreateDIDOption) (*did.Doc, error) {
				require.Equal(t, domain, d)
				return expected, nil
			},
		}
		result, err := c.Create()
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("error creating keys", func(t *testing.T) {
		expected := errors.New("test")
		c := NewTrustblocDIDCreator("", "", &mockKeyManager{err: expected}, nil)
		_, err := c.Create()
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("error creating didcomm keys", func(t *testing.T) {
		expected := errors.New("test")
		c := NewTrustblocDIDCreator("", "", &mockKeyManager{err: expected}, nil)
		_, err := c.Create()
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("error exporting public key bytes", func(t *testing.T) {
		expected := errors.New("test")
		c := NewTrustblocDIDCreator("", "", &mockKeyManager{err: expected}, nil)
		_, err := c.Create()
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("error creating trustbloc DID", func(t *testing.T) {
		expected := errors.New("test")
		c := NewTrustblocDIDCreator("", "", &mockKeyManager{}, nil)
		c.tblocDIDs = &stubTrustblocClient{
			createFunc: func(string, ...trustblocdid.CreateDIDOption) (*did.Doc, error) {
				return nil, expected
			},
		}
		_, err := c.Create()
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

type stubTrustblocClient struct {
	createFunc func(string, ...trustblocdid.CreateDIDOption) (*did.Doc, error)
}

func (s *stubTrustblocClient) CreateDID(domain string, options ...trustblocdid.CreateDIDOption) (*did.Doc, error) {
	return s.createFunc(domain, options...)
}

type mockKeyManager struct {
	err error
}

func (s *mockKeyManager) CreateAndExportPubKeyBytes(kt kms.KeyType) (string, []byte, error) {
	return "", nil, s.err
}

func newDIDDoc() *did.Doc {
	return &did.Doc{
		ID: "did:example:12345676",
		Service: []did.Service{{
			ID:              "didcomm",
			Type:            "did-communication",
			Priority:        0,
			RecipientKeys:   []string{},
			ServiceEndpoint: "http://example.com",
		}},
	}
}
