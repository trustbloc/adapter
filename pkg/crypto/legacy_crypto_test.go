/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	ariesctx "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
)

func TestLegacyCrypto_SignPresentation(t *testing.T) {
	t.Run("works with did:peer", func(t *testing.T) {
		alice := newAgent(t)
		aliceDID := createPeerDIDLikeFrameworkDIDExchange(t, alice)

		vc := newUniversityDegreeVC(t)
		vp, err := vc.Presentation()
		require.NoError(t, err)

		c := NewLegacy(alice.Signer(), alice.VDRIRegistry())
		signedVP, err := c.SignPresentation(vp, aliceDID)
		require.NoError(t, err)

		signedVPBytes := marshal(t, signedVP)

		_, err = verifiable.ParsePresentation(
			signedVPBytes,
			verifiable.WithPresPublicKeyFetcher(verifiable.NewDIDKeyResolver(alice.VDRIRegistry()).PublicKeyFetcher()))
		require.NoError(t, err)
	})

	t.Run("error invalid signingDID - empty authentication", func(t *testing.T) {
		alice := newAgent(t)
		aliceDID := createPeerDIDLikeFrameworkDIDExchange(t, alice)

		err := alice.VDRIRegistry().Store(aliceDID)
		require.NoError(t, err)

		aliceDID.Authentication = nil

		vc := newUniversityDegreeVC(t)
		vp, err := vc.Presentation()
		require.NoError(t, err)

		c := NewLegacy(alice.Signer(), alice.VDRIRegistry())
		_, err = c.SignPresentation(vp, aliceDID)
		require.Error(t, err)
	})

	t.Run("error invalid signingDID - empty authentication key ID", func(t *testing.T) {
		alice := newAgent(t)
		aliceDID := createPeerDIDLikeFrameworkDIDExchange(t, alice)

		err := alice.VDRIRegistry().Store(aliceDID)
		require.NoError(t, err)

		aliceDID.Authentication[0].PublicKey.ID = ""

		vc := newUniversityDegreeVC(t)
		vp, err := vc.Presentation()
		require.NoError(t, err)

		c := NewLegacy(alice.Signer(), alice.VDRIRegistry())
		_, err = c.SignPresentation(vp, aliceDID)
		require.Error(t, err)
	})
}

func newAgent(t *testing.T) *ariesctx.Provider {
	a, err := aries.New(
		aries.WithStoreProvider(storage.NewMockStoreProvider()),
		aries.WithProtocolStateStoreProvider(storage.NewMockStoreProvider()),
	)
	require.NoError(t, err)
	p, err := a.Context()
	require.NoError(t, err)

	return p
}

func createPeerDIDLikeFrameworkDIDExchange(t *testing.T, a *ariesctx.Provider) *did.Doc {
	peerDID, err := a.VDRIRegistry().Create(
		"peer",
		vdri.WithServiceEndpoint("http://example.com/didcomm"),
	)
	require.NoError(t, err)

	return peerDID
}

func newUniversityDegreeVC(t *testing.T) *verifiable.Credential {
	const contents = `{
	"@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"
	],
	"type": [
		"VerifiableCredential",
		"UniversityDegreeCredential"
	],
	"id": "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
	"issuanceDate": "2020-03-16T22:37:26.544Z",
	"issuer": {
		"id": "did:web:vc.transmute.world",
		"name": "University"
	},
	"credentialSubject": {
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"degree": {
			"type": "BachelorDegree",
			"degree": "MIT"
		},
		"name": "Jayden Doe",
		"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
	}
}`

	vc, err := verifiable.ParseCredential([]byte(contents))
	require.NoError(t, err)

	return vc
}

func marshal(t *testing.T, j json.Marshaler) []byte {
	bits, err := j.MarshalJSON()
	require.NoError(t, err)

	return bits
}
