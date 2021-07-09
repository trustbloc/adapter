/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"net/url"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	ariesctx "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	"github.com/stretchr/testify/require"

	crypto2 "github.com/trustbloc/edge-adapter/pkg/crypto"
	mockdidexchange "github.com/trustbloc/edge-adapter/pkg/internal/mock/didexchange"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/messenger"
	mockpresentproof "github.com/trustbloc/edge-adapter/pkg/internal/mock/presentproof"
	"github.com/trustbloc/edge-adapter/pkg/internal/testutil"
)

func config(t *testing.T) *Config {
	t.Helper()

	return &Config{
		DIDExchClient:        &mockdidexchange.MockClient{},
		Storage:              memStorage(),
		AriesContextProvider: agent(t),
		MsgRegistrar:         msghandler.NewRegistrar(),
		AriesMessenger:       &messenger.MockMessenger{},
		PresentProofClient:   &mockpresentproof.MockClient{},
		JSONLDDocumentLoader: testutil.DocumentLoader(t),
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

	u, err := url.Parse(verificationMethod)
	require.NoError(t, err)

	kh, err := agent.KMS().Get(u.Fragment)
	require.NoError(t, err)

	now := time.Now()

	err = vp.AddLinkedDataProof(
		&verifiable.LinkedDataProofContext{
			SignatureType:           ed25519signature2018.SignatureType,
			Suite:                   ed25519signature2018.New(suite.WithSigner(suite.NewCryptoSigner(agent.Crypto(), kh))),
			SignatureRepresentation: verifiable.SignatureJWS,
			Created:                 &now,
			VerificationMethod:      verificationMethod,
			Purpose:                 "authentication",
		},
		jsonld.WithDocumentLoader(testutil.DocumentLoader(t)),
	)
	require.NoError(t, err)

	return vp
}

// nolint:deadcode,unused // TODO these VCs should be signed: https://github.com/trustbloc/edge-adapter/issues/304
func signVC(t *testing.T,
	agent *ariesctx.Provider, signingDID *did.Doc, vc *verifiable.Credential) *verifiable.Credential {
	t.Helper()

	verificationMethod, err := crypto2.GetVerificationMethodFromDID(signingDID, did.AssertionMethod)
	require.NoError(t, err)

	vc, err = crypto2.New(
		agent.KMS(),
		agent.Crypto(),
		agent.VDRegistry(),
		agent.JSONLDDocumentLoader(),
	).SignCredential(vc, verificationMethod)
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

	keyID, keyBytes, err := agent.KMS().CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	d, err := agent.VDRegistry().Create(
		peer.DIDMethod, &did.Doc{
			Service: []did.Service{{ServiceEndpoint: "http://agent.example.com/didcomm", Type: "did-communication"}},
			VerificationMethod: []did.VerificationMethod{*did.NewVerificationMethodFromBytes(
				"#"+keyID,
				crypto2.Ed25519VerificationKey2018,
				"",
				keyBytes,
			)},
		},
	)
	require.NoError(t, err)

	return d.DIDDocument
}

type actionEventEvent struct {
	myDID    string
	theirDID string
	props    map[string]interface{}
}

func (e *actionEventEvent) All() map[string]interface{} {
	if e.props != nil {
		return e.props
	}

	return map[string]interface{}{
		"myDID":    e.myDID,
		"theirDID": e.theirDID,
	}
}
