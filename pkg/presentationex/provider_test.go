/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package presentationex

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-adapter/pkg/internal/common/adapterutil"
	"github.com/trustbloc/edge-adapter/pkg/presexch"
)

func TestProvider_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		p, err := New(reader(t, map[string]*presexch.InputDescriptor{}))
		require.NoError(t, err)
		require.NotNil(t, p)
	})

	t.Run("test failed to read input descriptors file", func(t *testing.T) {
		_, err := New(&mockReader{err: errors.New("test")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read input descriptors file")
	})

	t.Run("test failed unmarshal to input descriptors", func(t *testing.T) {
		_, err := New(bytes.NewReader([]byte("{")))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed unmarshal to input descriptors")
	})
}

func TestProvider_Create(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		scopes := []string{"CreditCardStatement", "Address", "CreditScore", "Email"}
		expected := map[string]*presexch.InputDescriptor{}

		for _, scope := range scopes {
			expected[scope] = &presexch.InputDescriptor{
				Schema: &presexch.Schema{
					Name:    uuid.New().String(),
					Purpose: uuid.New().String(),
					URI:     []string{uuid.New().String()},
				},
			}
		}

		p, err := New(reader(t, expected))
		require.NoError(t, err)

		actual, err := p.Create(scopes)
		require.NoError(t, err)
		require.NotNil(t, actual)
		require.Len(t, actual.InputDescriptors, len(expected))

		for _, e := range expected {
			d := descriptor(t, e.Schema.URI, actual.InputDescriptors)
			require.Equal(t, e.Schema, d.Schema)
			require.NotEmpty(t, d.ID)
		}
	})

	t.Run("invalid scope", func(t *testing.T) {
		p, err := New(reader(t, map[string]*presexch.InputDescriptor{
			"CreditCardStatement": {
				Schema: &presexch.Schema{},
			},
		}))
		require.NoError(t, err)

		_, err = p.Create([]string{"INVALID"})
		require.Error(t, err)
	})
}

func reader(t *testing.T, jsn interface{}) io.Reader {
	bits, err := json.Marshal(jsn)
	require.NoError(t, err)

	return bytes.NewReader(bits)
}

type mockReader struct {
	err error
}

func (m *mockReader) Read([]byte) (int, error) {
	return 0, m.err
}

func descriptor(t *testing.T, uri []string, descriptors []*presexch.InputDescriptor) *presexch.InputDescriptor {
	for i := range descriptors {
		if adapterutil.StringsIntersect(descriptors[i].Schema.URI, uri) {
			return descriptors[i]
		}
	}

	require.Fail(t, "no descriptor found for schema uri %+v", uri)

	return nil
}
