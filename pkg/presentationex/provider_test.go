/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package presentationex

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// nolint: gochecknoglobals
var inputDescriptors = `{
 "input_descriptors": [
  {
    "id": "banking_input_1",
    "group": ["A"],
    "schema": {
      "uri": "https://bank-standards.com/customer.json",
      "name": "Bank Account Information",
      "purpose": "We need your bank and account information."
    },
    "constraints": {
      "fields": [
        {
          "path": ["$.issuer", "$.vc.issuer", "$.iss"],
          "purpose": "The credential must be from one of the specified issuers",
          "filter": {
            "type": "string",
            "pattern": "did:example:123|did:example:456"
          }
        },
        { 
          "path": ["$.credentialSubject.account[*].id", "$.vc.credentialSubject.account[*].id"],
          "purpose": "We need your bank account number for processing purposes",
          "filter": {
            "type": "string",
            "minLength": 10,
            "maxLength": 12
          }
        },
        {
          "path": ["$.credentialSubject.account[*].route", "$.vc.credentialSubject.account[*].route"],
          "purpose": "You must have an account with a German, US, or Japanese bank account",
          "filter": {
            "type": "string",
            "pattern": "^DE|^US|^JP"
          }
        }
      ]
    }
  }
]
}`

func TestProvider_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(inputDescriptors)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		p, err := New(file.Name())
		require.NoError(t, err)
		require.NotNil(t, p)
	})

	t.Run("test failed to read input descriptors file", func(t *testing.T) {
		p, err := New("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read input descriptors file")
		require.Nil(t, p)
	})

	t.Run("test failed unmarshal to input descriptors", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		p, err := New(file.Name())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed unmarshal to input descriptors")
		require.Nil(t, p)
	})
}

func TestProvider_Create(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(inputDescriptors)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		p, err := New(file.Name())
		require.NoError(t, err)
		require.NotNil(t, p)

		presentationDefinitions, err := p.Create([]string{"scope1", "scope2"})
		require.NoError(t, err)
		require.NotNil(t, presentationDefinitions)

		require.Equal(t, 1, len(presentationDefinitions.SubmissionRequirements))
		require.Equal(t, 2, len(presentationDefinitions.SubmissionRequirements[0].Rule.From))
		require.Equal(t, "scope1", presentationDefinitions.SubmissionRequirements[0].Rule.From[0])
		require.Equal(t, "scope2", presentationDefinitions.SubmissionRequirements[0].Rule.From[1])
	})
}
