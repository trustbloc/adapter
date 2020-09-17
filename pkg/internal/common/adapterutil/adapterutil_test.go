/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package adapterutil

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
)

func TestStringsContains(t *testing.T) {
	words := []string{"Hello", "World"}

	require.True(t, StringsContains("World", words))
	require.False(t, StringsContains("Hi", words))
}

func TestDecodeUnmarshaller(t *testing.T) {
	t.Run("test decode - failure", func(t *testing.T) {
		v := &struct {
			field1 string
		}{}

		err := DecodeJSONMarshaller(&verifiable.Credential{}, v)
		require.NoError(t, err)
	})

	t.Run("test decode - failure", func(t *testing.T) {
		v := 32

		err := DecodeJSONMarshaller(&verifiable.Credential{}, v)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode custom jsonmarshaller")
	})
}

func TestValidHTTPURL(t *testing.T) {
	require.True(t, ValidHTTPURL("http://example.com"))
	require.True(t, ValidHTTPURL("https://example.com"))
	require.True(t, ValidHTTPURL("https://example.com/test"))

	require.False(t, ValidHTTPURL("http:/example.com"))
	require.False(t, ValidHTTPURL("ws://example.com"))
}
