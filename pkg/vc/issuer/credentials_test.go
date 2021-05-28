/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-adapter/pkg/internal/common/adapterutil"
	"github.com/trustbloc/edge-adapter/pkg/internal/testutil"
	adaptervc "github.com/trustbloc/edge-adapter/pkg/vc"
)

const (
	id              = "e9e0f944-7b74-4298-9f3e-00ca609d6266"
	inviteeDID      = "did:example:7b744298e9e0f"
	inviterDID      = "agc"
	inviterLabel    = "user-agent"
	threadID        = "92d01dp5251sien42ad4dq4q2"
	connectionState = "completed"

	vc = `{
	   "@context":[
		  "https://www.w3.org/2018/credentials/v1",
		  "https://www.w3.org/2018/credentials/examples/v1"
	   ],
	   "id":"http://example.edu/credentials/1872",
	   "type":[
		  "VerifiableCredential",
		  "DIDConnection"
	   ],
	   "credentialSubject":{
		  "id":"` + id + `",
		  "inviteeDID":"` + inviteeDID + `",
		  "inviterDID":"` + inviterDID + `",
		  "inviterLabel":"` + inviterLabel + `",
		  "threadID":"` + threadID + `",
		  "connectionState": "` + connectionState + `"
	   },
	   "issuer":"did:example:76e12ec712ebc6f1c221ebfeb1f",
	   "issuanceDate":"2010-01-01T19:23:24Z"
	}`
)

func TestCreateManifestCredential(t *testing.T) {
	t.Parallel()

	t.Run("test create manifest credential", func(t *testing.T) {
		t.Parallel()

		issuerName := "TestIssuer"
		contexts := []string{"abc", "xyz"}

		vcBytes, err := CreateManifestCredential(issuerName, contexts)
		require.NoError(t, err)

		vc, err := verifiable.ParseCredential(vcBytes, verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
		require.NoError(t, err)
		require.True(t, adapterutil.StringsContains(ManifestCredentialType, vc.Types))

		manifestVC := &ManifestCredential{}

		err = adapterutil.DecodeJSONMarshaller(vc, manifestVC)
		require.NoError(t, err)
		require.Equal(t, contexts, manifestVC.Subject.Contexts)

		customFields := vc.CustomFields
		require.Equal(t, issuerName, customFields["name"])
	})
}

func TestParseWalletResponse(t *testing.T) {
	t.Parallel()

	t.Run("test parse wallet - success", func(t *testing.T) {
		t.Parallel()

		conn, err := ParseWalletResponse(getTestVP(t), testutil.DocumentLoader(t))
		require.NoError(t, err)
		require.NotNil(t, conn)

		require.Equal(t, conn.ID, id)
		require.Equal(t, conn.InviteeDID, inviteeDID)
		require.Equal(t, conn.InviterDID, inviterDID)
		require.Equal(t, conn.InviterLabel, inviterLabel)
		require.Equal(t, conn.ConnectionState, connectionState)
		require.Equal(t, conn.ThreadID, threadID)
	})

	t.Run("test parse wallet - invalid vp", func(t *testing.T) {
		t.Parallel()

		conn, err := ParseWalletResponse([]byte("invalid json"), testutil.DocumentLoader(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid presentation")
		require.Nil(t, conn)
	})

	t.Run("test parse wallet - no credentials inside vp", func(t *testing.T) {
		t.Parallel()

		vp := verifiable.Presentation{
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Type:    []string{"VerifiablePresentation"},
		}
		vpJSON, err := vp.MarshalJSON()
		require.NoError(t, err)

		conn, err := ParseWalletResponse(vpJSON, testutil.DocumentLoader(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "there should be only one credential")
		require.Nil(t, conn)
	})

	t.Run("test parse wallet - invalid credential inside vp", func(t *testing.T) {
		t.Parallel()

		vc := verifiable.Credential{
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Types:   []string{"VerifiablePresentation"},
		}

		vp, err := verifiable.NewPresentation(verifiable.WithCredentials(&vc))
		require.NoError(t, err)

		vpJSON, err := vp.MarshalJSON()
		require.NoError(t, err)

		conn, err := ParseWalletResponse(vpJSON, testutil.DocumentLoader(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse credential")
		require.Nil(t, conn)
	})

	t.Run("test parse wallet - no credential of DIDConnectCredential type inside vp", func(t *testing.T) {
		t.Parallel()

		vc, err := verifiable.ParseCredential([]byte(vc), verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
		require.NoError(t, err)

		vc.Types = []string{"VerifiableCredential"}

		vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
		require.NoError(t, err)

		vpJSON, err := vp.MarshalJSON()
		require.NoError(t, err)

		conn, err := ParseWalletResponse(vpJSON, testutil.DocumentLoader(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc doesn't contain DIDConnection type")
		require.Nil(t, conn)
	})
}

func TestCreateAuthorizationCredential(t *testing.T) {
	t.Parallel()

	t.Run("test create didcomm init credential", func(t *testing.T) {
		t.Parallel()

		didDocument := mockdiddoc.GetMockDIDDoc(t)

		didDocJSON, err := didDocument.JSONBytes()
		require.NoError(t, err)

		tempVC := &adaptervc.AuthorizationCredential{}
		require.NoError(t, adapterutil.DecodeJSONMarshaller(&verifiable.Credential{
			Subject: &adaptervc.AuthorizationCredentialSubject{
				IssuerDIDDoc: &adaptervc.DIDDoc{
					Doc: didDocJSON,
				},
			},
		}, tempVC))
		require.NoError(t, err)

		didDocJSON = tempVC.Subject.IssuerDIDDoc.Doc

		rpDIDDoc := &adaptervc.DIDDoc{
			ID:  didDocument.ID,
			Doc: didDocJSON,
		}

		subjectDIDDoc := &adaptervc.DIDDoc{
			ID:  didDocument.ID,
			Doc: didDocJSON,
		}

		vc := CreateAuthorizationCredential(didDocument.ID, didDocJSON, rpDIDDoc, subjectDIDDoc)
		require.True(t, adapterutil.StringsContains(adaptervc.AuthorizationCredentialType, vc.Types))

		authorizationVC := &adaptervc.AuthorizationCredential{}

		err = adapterutil.DecodeJSONMarshaller(vc, authorizationVC)
		require.NoError(t, err)
		require.Equal(t, didDocument.ID, authorizationVC.Subject.IssuerDIDDoc.ID)
		require.Equal(t, string(tempVC.Subject.IssuerDIDDoc.Doc), string(authorizationVC.Subject.IssuerDIDDoc.Doc))
		require.Equal(t, rpDIDDoc.ID, authorizationVC.Subject.RPDIDDoc.ID)
		require.Equal(t, string(didDocJSON), string(authorizationVC.Subject.RPDIDDoc.Doc))
		require.Equal(t, subjectDIDDoc.ID, authorizationVC.Subject.SubjectDIDDoc.ID)
		require.Equal(t, string(didDocJSON), string(authorizationVC.Subject.SubjectDIDDoc.Doc))
	})
}

func TestCreatePresentation(t *testing.T) {
	t.Parallel()

	t.Run("test create presentation", func(t *testing.T) {
		t.Parallel()

		vp, err := CreatePresentation(&verifiable.Credential{})
		require.NoError(t, err)
		require.NotNil(t, vp)
	})
}

func getTestVP(t *testing.T) []byte {
	t.Helper()

	vc, err := verifiable.ParseCredential([]byte(vc), verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
	require.NoError(t, err)

	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
	require.NoError(t, err)

	vpJSON, err := vp.MarshalJSON()
	require.NoError(t, err)

	return vpJSON
}
