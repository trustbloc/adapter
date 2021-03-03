/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	ariesctx "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	"github.com/stretchr/testify/require"

	crypto2 "github.com/trustbloc/edge-adapter/pkg/crypto"
	mockdidexchange "github.com/trustbloc/edge-adapter/pkg/internal/mock/didexchange"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/messenger"
	mockpresentproof "github.com/trustbloc/edge-adapter/pkg/internal/mock/presentproof"
)

func config(t *testing.T) *Config {
	return &Config{
		DIDExchClient:        &mockdidexchange.MockClient{},
		Storage:              memStorage(),
		AriesContextProvider: agent(t),
		MsgRegistrar:         msghandler.NewRegistrar(),
		AriesMessenger:       &messenger.MockMessenger{},
		PresentProofClient:   &mockpresentproof.MockClient{},
	}
}

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

	vp, err = crypto2.New(agent.KMS(), agent.Crypto(), agent.VDRegistry()).SignPresentation(vp, verificationMethod)
	require.NoError(t, err)

	return vp
}

// nolint:deadcode,unused // TODO these VCs should be signed: https://github.com/trustbloc/edge-adapter/issues/304
func signVC(t *testing.T,
	agent *ariesctx.Provider, signingDID *did.Doc, vc *verifiable.Credential) *verifiable.Credential {
	t.Helper()

	verificationMethod, err := crypto2.GetVerificationMethodFromDID(signingDID, did.AssertionMethod)
	require.NoError(t, err)

	vc, err = crypto2.New(agent.KMS(), agent.Crypto(), agent.VDRegistry()).SignCredential(vc, verificationMethod)
	require.NoError(t, err)

	return vc
}

func simulateDIDExchange(t *testing.T,
	agentA *ariesctx.Provider, didA *did.Doc, agentB *ariesctx.Provider, didB *did.Doc) {
	t.Helper()

	_, err := agentA.VDRegistry().Create(peer.DIDMethod, didB, vdrapi.WithOption("store", true))
	require.NoError(t, err)

	_, err = agentB.VDRegistry().Create(peer.DIDMethod, didA, vdrapi.WithOption("store", true))
	require.NoError(t, err)
}

func newPeerDID(t *testing.T, agent *ariesctx.Provider) *did.Doc {
	t.Helper()

	d, err := agent.VDRegistry().Create(
		peer.DIDMethod, &did.Doc{
			Service: []did.Service{{ServiceEndpoint: "http://agent.example.com/didcomm", Type: "did-communication"}},
		},
	)
	require.NoError(t, err)

	return d.DIDDocument
}
