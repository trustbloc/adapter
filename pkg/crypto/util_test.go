/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto_test

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-adapter/pkg/crypto"
)

func TestGetVerificationMethodFromDID(t *testing.T) {
	t.Run("returns ver method", func(t *testing.T) {
		doc := newPeerDID(t)
		actual, err := crypto.GetVerificationMethodFromDID(doc, did.Authentication)
		require.NoError(t, err)

		require.Equal(t, fmt.Sprintf("%s%s", doc.ID, doc.Authentication[0].VerificationMethod.ID), actual)
	})

	t.Run("error if doc does not have verification method", func(t *testing.T) {
		doc := newPeerDID(t)
		doc.Authentication = nil
		_, err := crypto.GetVerificationMethodFromDID(doc, did.Authentication)
		require.Error(t, err)
	})

	t.Run("error if verification method ID is empty", func(t *testing.T) {
		doc := newPeerDID(t)
		doc.Authentication[0].VerificationMethod.ID = ""
		_, err := crypto.GetVerificationMethodFromDID(doc, did.Authentication)
		require.Error(t, err)
	})
}

func newPeerDID(t *testing.T) *did.Doc {
	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	didDoc := &did.Doc{}

	didDoc.Service = []did.Service{{ServiceEndpoint: "http://agent.example.com/didcomm", Type: "did-communication"}}

	didDoc.VerificationMethod = []did.VerificationMethod{verMethod(t, ctx.KMS())}

	d, err := ctx.VDRegistry().Create(
		peer.DIDMethod,
		didDoc,
	)
	require.NoError(t, err)

	return d.DIDDocument
}

func verMethod(t *testing.T, k kms.KeyManager) did.VerificationMethod {
	t.Helper()

	keyID, keyBytes, err := k.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	return *did.NewVerificationMethodFromBytes(
		"#"+keyID,
		crypto.Ed25519VerificationKey2018,
		"",
		keyBytes,
	)
}
