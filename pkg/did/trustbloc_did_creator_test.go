/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
	trustblocdid "github.com/trustbloc/trustbloc-did-method/pkg/did"
)

func TestNewTrustblocDIDCreator(t *testing.T) {
	t.Run("returns did creator", func(t *testing.T) {
		c := NewTrustblocDIDCreator("", "", &stubKeyManager{}, nil)
		require.NotNil(t, c)
	})
}

func TestTrustblocDIDCreator_Create(t *testing.T) {
	t.Run("creates trustbloc DID", func(t *testing.T) {
		domain := "http://example.trustbloc.com"
		expected := newDIDDoc()
		didcommURL := "http://example.didcomm.com"
		c := NewTrustblocDIDCreator(domain, didcommURL, &stubKeyManager{}, nil)
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
		c := NewTrustblocDIDCreator("", "", &stubKeyManager{createErr: expected}, nil)
		_, err := c.Create()
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("error exporting public key bytes", func(t *testing.T) {
		expected := errors.New("test")
		c := NewTrustblocDIDCreator("", "", &stubKeyManager{exportErr: expected}, nil)
		_, err := c.Create()
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("error creating trustbloc DID", func(t *testing.T) {
		expected := errors.New("test")
		c := NewTrustblocDIDCreator("", "", &stubKeyManager{}, nil)
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

type stubKeyManager struct {
	createErr error
	exportErr error
}

func (s *stubKeyManager) Create(keyType kms.KeyType) (string, interface{}, error) {
	return uuid.New().String(), nil, s.createErr
}

func (s *stubKeyManager) ExportPubKeyBytes(s2 string) ([]byte, error) {
	return []byte{}, s.exportErr
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
