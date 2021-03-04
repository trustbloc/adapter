/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
)

func TestNewTrustblocDIDCreator(t *testing.T) {
	t.Run("returns did creator", func(t *testing.T) {
		c, err := NewTrustblocDIDCreator("", "", &mockKeyManager{}, nil)
		require.NoError(t, err)
		require.NotNil(t, c)
	})
}

func TestTrustblocDIDCreator_Create(t *testing.T) {
	t.Run("creates trustbloc DID", func(t *testing.T) {
		domain := "http://example.trustbloc.com"
		expected := newDIDDoc()
		didcommURL := "http://example.didcomm.com"
		_, pubKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		c, err := NewTrustblocDIDCreator(domain, didcommURL, &mockKeyManager{v: pubKey}, nil)
		require.NoError(t, err)
		c.tblocDIDs = &stubTrustblocClient{
			createFunc: func(keyManager kms.KeyManager, didDoc *did.Doc,
				opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return &did.DocResolution{DIDDocument: expected}, nil
			},
		}
		result, err := c.Create()
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("error creating keys", func(t *testing.T) {
		expected := errors.New("test")
		c, err := NewTrustblocDIDCreator("", "", &mockKeyManager{err: expected}, nil)
		require.NoError(t, err)
		_, err = c.Create()
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("error creating didcomm keys", func(t *testing.T) {
		expected := errors.New("test")
		c, err := NewTrustblocDIDCreator("", "", &mockKeyManager{err: expected}, nil)
		require.NoError(t, err)
		_, err = c.Create()
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("error exporting public key bytes", func(t *testing.T) {
		expected := errors.New("test")
		c, err := NewTrustblocDIDCreator("", "", &mockKeyManager{err: expected}, nil)
		require.NoError(t, err)
		_, err = c.Create()
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("error creating trustbloc DID", func(t *testing.T) {
		_, pubKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		expected := errors.New("test")
		c, err := NewTrustblocDIDCreator("", "", &mockKeyManager{v: pubKey}, nil)
		require.NoError(t, err)
		c.tblocDIDs = &stubTrustblocClient{
			createFunc: func(keyManager kms.KeyManager, did *did.Doc,
				opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return nil, expected
			},
		}
		_, err = c.Create()
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

type stubTrustblocClient struct {
	createFunc func(keyManager kms.KeyManager, did *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error)
}

func (s *stubTrustblocClient) Create(keyManager kms.KeyManager, didDoc *did.Doc,
	opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return s.createFunc(keyManager, didDoc, opts...)
}

type mockKeyManager struct {
	v   []byte
	err error
}

func (s *mockKeyManager) CreateAndExportPubKeyBytes(kt kms.KeyType) (string, []byte, error) {
	return "", s.v, s.err
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
