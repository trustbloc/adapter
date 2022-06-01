/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
)

func TestNewTrustblocDIDCreator(t *testing.T) {
	t.Parallel()

	t.Run("returns did creator", func(t *testing.T) {
		t.Parallel()

		c, err := NewTrustblocDIDCreator("", "", "", &mockKeyManager{}, nil, "", "", "")
		require.NoError(t, err)
		require.NotNil(t, c)
	})
}

func TestTrustblocDIDCreator_Create(t *testing.T) {
	t.Parallel()

	t.Run("creates trustbloc DID", func(t *testing.T) {
		t.Parallel()

		domain := "http://example.trustbloc.com"
		expected := newDIDDoc()
		didcommURL := "http://example.didcomm.com"
		_, pubKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		c, err := NewTrustblocDIDCreator(domain, "", didcommURL, &mockKeyManager{v: pubKey}, nil, "", "", "")
		require.NoError(t, err)
		c.tblocDIDs = &stubTrustblocClient{
			createFunc: func(didDoc *did.Doc,
				opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return &did.DocResolution{DIDDocument: expected}, nil
			},
		}
		result, err := c.Create()
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("error creating keys", func(t *testing.T) {
		t.Parallel()

		expected := errors.New("test")
		c, err := NewTrustblocDIDCreator("", "", "", &mockKeyManager{err: expected}, nil, "", "", "")
		require.NoError(t, err)
		_, err = c.Create()
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestTrustblocDIDCreator_CreateV2(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		domain := "http://example.trustbloc.com"
		expected := newDIDDoc()
		didcommURL := "http://example.didcomm.com"
		_, pubKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		c, err := NewTrustblocDIDCreator(
			domain,
			"",
			didcommURL,
			&mockKeyManager{v: pubKey},
			nil,
			"",
			kms.ED25519Type,
			kms.ED25519Type,
		)
		require.NoError(t, err)
		c.tblocDIDs = &stubTrustblocClient{
			createFunc: func(didDoc *did.Doc,
				opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return &did.DocResolution{DIDDocument: expected}, nil
			},
		}
		result, err := c.CreateV2()
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("error creating keys", func(t *testing.T) {
		t.Parallel()

		expected := errors.New("test")
		c, err := NewTrustblocDIDCreator("", "", "", &mockKeyManager{err: expected}, nil, "", "", "")
		require.NoError(t, err)
		_, err = c.CreateV2()
		require.Error(t, err)
		require.ErrorIs(t, err, expected)
	})
}

func TestTrustblocDIDCreator_orbCreate(t *testing.T) {
	t.Parallel()

	t.Run("fail: create recover key", func(t *testing.T) {
		t.Parallel()

		expected := errors.New("test")
		c, err := NewTrustblocDIDCreator("", "", "", &mockKeyManager{err: expected}, nil, "", "", "")
		require.NoError(t, err)

		_, err = c.orbCreate(newDIDDoc())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create recover key")
		require.ErrorIs(t, err, expected)
	})

	t.Run("fail: create update key", func(t *testing.T) {
		t.Parallel()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		c, err := NewTrustblocDIDCreator("", "", "", &mockKeyManager{v: pubKey, succeedFor: 1}, nil, "", "", "")
		require.NoError(t, err)

		_, err = c.orbCreate(newDIDDoc())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create update key")
	})

	t.Run("fail: sending create request", func(t *testing.T) {
		t.Parallel()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		expected := errors.New("test")
		c, err := NewTrustblocDIDCreator("", "", "", &mockKeyManager{v: pubKey}, nil, "", "", "")
		require.NoError(t, err)
		c.tblocDIDs = &stubTrustblocClient{
			createFunc: func(did *did.Doc,
				opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return nil, expected
			},
		}
		_, err = c.orbCreate(newDIDDoc())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create orb DID")
		require.ErrorIs(t, err, expected)
	})
}

func TestTrustblocDIDCreator_templateV1(t *testing.T) {
	t.Parallel()

	t.Run("fail: creating recipient key", func(t *testing.T) {
		t.Parallel()

		expected := errors.New("test")
		c, err := NewTrustblocDIDCreator("", "", "", &mockKeyManager{err: expected}, nil, "", "", "")
		require.NoError(t, err)
		_, err = c.templateV1()
		require.Error(t, err)
		require.ErrorIs(t, err, expected)
		require.Contains(t, err.Error(), "kms failed to create keyset")
	})

	t.Run("fail: creating verification method", func(t *testing.T) {
		t.Parallel()

		c, err := NewTrustblocDIDCreator("", "", "", &mockKeyManager{v: nil}, nil, "", "", "")
		require.NoError(t, err)
		_, err = c.templateV1()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new verification method")
	})
}

func TestTrustblocDIDCreator_templateV2(t *testing.T) {
	t.Parallel()

	const mockType = "mockType"

	const validType = kms.ED25519Type

	validKey, _, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)

	km := &mockKeyManager{v: validKey, rejectType: mockType}

	t.Run("fail: creating authentication vm", func(t *testing.T) {
		t.Parallel()

		c, err := NewTrustblocDIDCreator("", "", "", km, nil, "", mockType, validType)
		require.NoError(t, err)
		_, err = c.templateV2()
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating did doc Authentication")
	})

	t.Run("fail: creating keyagreement vm", func(t *testing.T) {
		t.Parallel()

		c, err := NewTrustblocDIDCreator("", "", "", km, nil, "", validType, mockType)
		require.NoError(t, err)
		_, err = c.templateV2()
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating did doc KeyAgreement")
	})
}

func TestTrustblocDIDCreator_createVerificationMethod(t *testing.T) {
	t.Parallel()

	t.Run("fail: creating recipient key", func(t *testing.T) {
		t.Parallel()

		expected := errors.New("test")
		c, err := NewTrustblocDIDCreator("", "", "", &mockKeyManager{err: expected}, nil, "", "", "")
		require.NoError(t, err)
		_, err = c.createVerificationMethod("", "")
		require.Error(t, err)
		require.ErrorIs(t, err, expected)
		require.Contains(t, err.Error(), "creating public key")
	})

	t.Run("fail: creating ed25519 jwk", func(t *testing.T) {
		t.Parallel()

		c, err := NewTrustblocDIDCreator("", "", "", &mockKeyManager{v: nil}, nil, "", "", "")
		require.NoError(t, err)
		_, err = c.createVerificationMethod("", kms.ED25519Type)
		require.Error(t, err)
		require.Contains(t, err.Error(), "converting ed25519 key to JWK")
	})

	t.Run("fail: creating non-ed25519 jwk", func(t *testing.T) {
		t.Parallel()

		c, err := NewTrustblocDIDCreator("", "", "", &mockKeyManager{v: nil}, nil, "", "", "")
		require.NoError(t, err)
		_, err = c.createVerificationMethod("", kms.NISTP256ECDHKWType)
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating JWK")
	})
}

type stubTrustblocClient struct {
	createFunc func(did *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error)
}

func (s *stubTrustblocClient) Create(didDoc *did.Doc,
	opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return s.createFunc(didDoc, opts...)
}

type mockKeyManager struct {
	v          []byte
	err        error
	rejectType kms.KeyType
	succeedFor int
	count      int
}

func (s *mockKeyManager) CreateAndExportPubKeyBytes(kt kms.KeyType) (string, []byte, error) {
	if s.rejectType != "" && s.rejectType == kt {
		return "", nil, fmt.Errorf("reject KeyType")
	}

	if s.succeedFor > 0 {
		s.count++

		if s.count > s.succeedFor {
			return "", nil, fmt.Errorf("failing after %d successes", s.succeedFor)
		}
	}

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
			ServiceEndpoint: model.NewDIDCommV1Endpoint("http://example.com"),
		}},
	}
}
