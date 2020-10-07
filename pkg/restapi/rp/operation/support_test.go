/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	ariesctx "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/stretchr/testify/require"

	crypto2 "github.com/trustbloc/edge-adapter/pkg/crypto"
)

func trio(t *testing.T) (*ariesctx.Provider, *ariesctx.Provider, *ariesctx.Provider) {
	t.Helper()

	return agent(t), agent(t), agent(t)
}

func agent(t *testing.T) *ariesctx.Provider {
	t.Helper()

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
}

func signVP(t *testing.T,
	agent *ariesctx.Provider, signingDID *did.Doc, vp *verifiable.Presentation) *verifiable.Presentation {
	t.Helper()

	verificationMethod, err := crypto2.GetVerificationMethodFromDID(signingDID, did.Authentication)
	require.NoError(t, err)

	vp, err = crypto2.New(agent.KMS(), agent.Crypto(), agent.VDRIRegistry()).SignPresentation(vp, verificationMethod)
	require.NoError(t, err)

	return vp
}

// nolint:deadcode,unused // TODO these VCs should be signed: https://github.com/trustbloc/edge-adapter/issues/304
func signVC(t *testing.T,
	agent *ariesctx.Provider, signingDID *did.Doc, vc *verifiable.Credential) *verifiable.Credential {
	t.Helper()

	verificationMethod, err := crypto2.GetVerificationMethodFromDID(signingDID, did.AssertionMethod)
	require.NoError(t, err)

	vc, err = crypto2.New(agent.KMS(), agent.Crypto(), agent.VDRIRegistry()).SignCredential(vc, verificationMethod)
	require.NoError(t, err)

	return vc
}

func simulateDIDExchange(t *testing.T,
	agentA *ariesctx.Provider, didA *did.Doc, agentB *ariesctx.Provider, didB *did.Doc) {
	t.Helper()

	err := agentA.VDRIRegistry().Store(didB)
	require.NoError(t, err)

	err = agentB.VDRIRegistry().Store(didA)
	require.NoError(t, err)
}

func newPeerDID(t *testing.T, agent *ariesctx.Provider) *did.Doc {
	t.Helper()

	d, err := agent.VDRIRegistry().Create(
		"peer",
		vdriapi.WithServices(did.Service{ServiceEndpoint: "http://agent.example.com/didcomm", Type: "did-communication"}),
	)
	require.NoError(t, err)

	return d
}
