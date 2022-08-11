/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package memcmdescriptor

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// nolint:gochecknoglobals
var cmOutDescData = `{
  "udc-scope": {
    "output_descriptor": [{
      "uri": "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld"
    }]
  }
}`

// nolint:gochecknoglobals
var cmDescData = `
{
   "prc":{
     "output_descriptor":[
		{
            "id":"udc_output",
             "display": {
        "title": {
          "path": [
            "$.name",
            "$.vc.name"
          ],
          "schema": {
            "type": "string"
          },
          "fallback": "Permanent Resident Card"
        },
        "subtitle": {
          "path": [
            "$.description",
            "$.vc.description"
          ],
          "schema": {
            "type": "string"
          },
          "fallback": ""
        },
        "description": {
          "text": "PR card of John Smith."
        },
        "properties": [
          {
            "path": [
              "$.credentialSubject.givenName"
            ],
            "schema": {
              "type": "string"
            },
            "fallback": "Not Applicable",
            "label": "Card Holder's first name"
          },
          {
            "path": [
              "$.credentialSubject.familyName"
            ],
            "schema": {
              "type": "string"
            },
            "fallback": "Unknown",
            "label": "Card Holder's family name"
          }
        ]
      },
            "schema":"https://www.w3.org/2018/credentials/examples/v1"
		}
      ],
      "presentation_definition":{
         "id":"8246867e-fdce-48de-a825-9d84ec16c6c9",
         "input_descriptors":[
            {
               "id":"prc_input",
               "schema":[
                 {
                  "uri":"https://w3id.org/citizenship#PermanentResidentCard"
                 }
               ]
            }
         ]
      }
   }
}
`

// nolint:gochecknoglobals
var invalidCMDescData = `
  {
   "prc":{
      "output_descriptor":[
         {
            "id":"udc_output",
             "display": {
        "title": {
          "path": [
            "$.name",
            "$.vc.name"
          ],
          "schema": {
            "type": "string"
          },
          "fallback": "Permanent Resident Card"
        },
        "subtitle": {
          "path": [
            "$.description",
            "$.vc.description"
          ],
          "schema": {
            "type": "string"
          },
          "fallback": ""
        },
        "description": {
          "text": "PR card of John Smith."
        },
        "properties": [
          {
            "path": [
              "$.credentialSubject.givenName"
            ],
            "schema": {
              "type": "string"
            },
            "fallback": "Not Applicable",
            "label": "Card Holder's first name"
          },
          {
            "path": [
              "$.credentialSubject.familyName"
            ],
            "schema": {
              "type": "string"
            },
            "fallback": "Unknown",
            "label": "Card Holder's family name"
          }
        ]
      },
            "schema":"https://www.w3.org/2018/credentials/examples/v1"
          }
      ],
     "presentation_definition": {
      "input_descriptor":[
         {
            "id":"prc_input"
         }
      ]
    }
   }
}
`

func TestProvider_New(t *testing.T) {
	t.Parallel()

	t.Run("test success", func(t *testing.T) {
		t.Parallel()

		p, err := New(reader(t, map[string]*Provider{}))
		require.NoError(t, err)
		require.NotNil(t, p)
	})

	t.Run("test failed to decode credential manifest descriptors file", func(t *testing.T) {
		t.Parallel()

		_, err := New(bytes.NewReader([]byte("{")))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode credential manifest descriptors file")
	})
	t.Run("aries-framework - failed to validate output descriptors", // nolint:paralleltest
		func(t *testing.T) {
			cmOutputdesc, err := New(bytes.NewReader([]byte(cmOutDescData)))
			require.Error(t, err)
			require.Contains(t, err.Error(), "aries-framework - failed to validate output descriptors: "+
				"missing ID for output descriptor")
			require.Nil(t, cmOutputdesc)
		})
	t.Run("aries-framework - failed to validate input descriptors", // nolint:paralleltest
		func(t *testing.T) {
			cmDesc, err := New(bytes.NewReader([]byte(invalidCMDescData)))
			require.Error(t, err)
			require.Contains(t, err.Error(), "aries-framework - failed to validate input descriptors")
			require.Nil(t, cmDesc)
		})
}

func TestFetchCMDescriptorsByScope(t *testing.T) {
	t.Parallel()

	t.Run("fetch cm descriptor success", func(t *testing.T) {
		t.Parallel()

		p, err := New(bytes.NewReader([]byte(cmDescData)))
		require.NoError(t, err)
		require.NotNil(t, p)

		val, found := p.FetchCMDescriptorsByScope("prc")
		require.True(t, found)
		require.NotNil(t, val)
	})
	t.Run("fetch cm descriptor not found", func(t *testing.T) {
		t.Parallel()

		p, err := New(reader(t, map[string]*Provider{}))
		require.NoError(t, err)
		require.NotNil(t, p)

		val, found := p.FetchCMDescriptorsByScope("prc")
		require.False(t, found)
		require.Nil(t, val)
	})
}

func reader(t *testing.T, jsn interface{}) io.Reader {
	t.Helper()

	bits, err := json.Marshal(jsn)
	require.NoError(t, err)

	return bytes.NewReader(bits)
}
