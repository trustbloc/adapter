/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	issuecredsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	outofbandsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mocksvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	mockdiddoc "github.com/trustbloc/edge-adapter/pkg/internal/mock/diddoc"
	mockgovernance "github.com/trustbloc/edge-adapter/pkg/internal/mock/governance"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/issuecredential"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/messenger"
	mockoutofband "github.com/trustbloc/edge-adapter/pkg/internal/mock/outofband"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/presentproof"
	"github.com/trustbloc/edge-adapter/pkg/profile/issuer"
	adaptervc "github.com/trustbloc/edge-adapter/pkg/vc"
	issuervc "github.com/trustbloc/edge-adapter/pkg/vc/issuer"
)

func getAriesCtx() aries.CtxProvider {
	return &mockprovider.Provider{
		ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:              mockstore.NewMockStoreProvider(),
		ServiceMap: map[string]interface{}{
			didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
			mediator.Coordination:   &mockroute.MockMediatorSvc{},
			issuecredsvc.Name:       &issuecredential.MockIssueCredentialSvc{},
			presentproofsvc.Name:    &presentproof.MockPresentProofSvc{},
			outofbandsvc.Name:       &mockoutofband.MockService{},
		},
		KMSValue:             &mockkms.KeyManager{ImportPrivateKeyErr: fmt.Errorf("error import priv key")},
		CryptoValue:          &mockcrypto.Crypto{},
		ServiceEndpointValue: "endpoint",
		VDRegistryValue: &mockvdri.MockVDRegistry{
			CreateValue:  mockdiddoc.GetMockDIDDoc("did:example:def567"),
			ResolveValue: mockdiddoc.GetMockDIDDoc("did:example:def567"),
		},
	}
}

func config() *Config {
	return &Config{
		AriesCtx:           getAriesCtx(),
		StoreProvider:      memstore.NewProvider(),
		MsgRegistrar:       msghandler.NewRegistrar(),
		AriesMessenger:     &messenger.MockMessenger{},
		PublicDIDCreator:   &stubPublicDIDCreator{createValue: mockdiddoc.GetMockDIDDoc("did:example:def567")},
		GovernanceProvider: &mockgovernance.MockProvider{}}
}

func getHandler(t *testing.T, op *Operation, lookup string) Handler {
	return getHandlerWithError(t, op, lookup)
}

func getHandlerWithError(t *testing.T, op *Operation, lookup string) Handler {
	return handlerLookup(t, op, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func serveHTTP(t *testing.T, handler http.HandlerFunc, method, path string, req []byte) *httptest.ResponseRecorder {
	httpReq, err := http.NewRequest(
		method,
		path,
		bytes.NewBuffer(req),
	)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, httpReq)

	return rr
}

func serveHTTPMux(t *testing.T, handler Handler, endpoint string, reqBytes []byte, // nolint: unparam
	urlVars map[string]string) *httptest.ResponseRecorder {
	r, err := http.NewRequest(handler.Method(), endpoint, bytes.NewBuffer(reqBytes))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	req1 := mux.SetURLVars(r, urlVars)

	handler.Handle().ServeHTTP(rr, req1)

	return rr
}

func getDefaultTestVP(t *testing.T) []byte {
	return getTestVP(t, inviteeDID, inviterDID, uuid.New().String())
}

func getTestVP(t *testing.T, inviteeDID, inviterDID, threadID string) []byte { //nolint: unparam
	vc, err := verifiable.ParseCredential([]byte(fmt.Sprintf(vcFmt, inviteeDID, inviterDID, threadID)))
	require.NoError(t, err)

	vp, err := vc.Presentation()
	require.NoError(t, err)

	vpJSON, err := vp.MarshalJSON()
	require.NoError(t, err)

	return vpJSON
}

func createProfileData(profileID string) *issuer.ProfileData {
	return &issuer.ProfileData{
		ID:                          profileID,
		Name:                        "Issuer Profile 1",
		SupportedVCContexts:         []string{"https://w3id.org/citizenship/v3"},
		SupportsAssuranceCredential: false,
		URL:                         "http://issuer.example.com",
		PresentationSigningKey:      "did:example:123xyz#key-1",
	}
}

func createAuthorizationCredReq(t *testing.T, subjectDIDDoc, rpDIDDoc *did.Doc) json.RawMessage {
	subjectDIDDocBytes, err := subjectDIDDoc.JSONBytes()
	require.NoError(t, err)

	ccReq := AuthorizationCredentialReq{
		SubjectDIDDoc: &adaptervc.DIDDoc{
			ID:  subjectDIDDoc.ID,
			Doc: subjectDIDDocBytes,
		},
	}

	if rpDIDDoc != nil {
		rpDIDDocBytes, convErr := rpDIDDoc.JSONBytes()
		require.NoError(t, convErr)

		ccReq.RPDIDDoc = &adaptervc.DIDDoc{
			ID:  rpDIDDoc.ID,
			Doc: rpDIDDocBytes,
		}
	}

	ccReqBytes, err := json.Marshal(ccReq)
	require.NoError(t, err)

	return ccReqBytes
}

func createAuthorizationCredential(t *testing.T) *verifiable.Credential {
	didDocument := mockdiddoc.GetMockDIDDoc("did:example:def567")

	didDocJSON, err := didDocument.JSONBytes()
	require.NoError(t, err)

	subjectDIDDoc := &adaptervc.DIDDoc{
		ID:  didDocument.ID,
		Doc: didDocJSON,
	}

	rpDIDDoc := &adaptervc.DIDDoc{
		ID:  didDocument.ID,
		Doc: didDocJSON,
	}

	vc := issuervc.CreateAuthorizationCredential(didDocument.ID, didDocJSON, rpDIDDoc, subjectDIDDoc)

	return vc
}

func createCredentialReqMsg(t *testing.T, msg interface{}, continueFn func(args interface{}), // nolint: unparam
	stopFn func(err error)) service.DIDCommAction {
	if msg == nil {
		msg = issuecredsvc.RequestCredential{
			Type: issuecredsvc.RequestCredentialMsgType,
			RequestsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{
					JSON: createAuthorizationCredReq(t, mockdiddoc.GetMockDIDDoc("did:example:xyz123"),
						mockdiddoc.GetMockDIDDoc("did:example:def567")),
				}},
			},
		}
	}

	return service.DIDCommAction{
		Message:    service.NewDIDCommMsgMap(msg),
		Continue:   continueFn,
		Stop:       stopFn,
		Properties: &actionEventEvent{},
	}
}

func createProofReqMsg(t *testing.T, msg interface{}, continueFn func(args interface{}),
	stopFn func(err error)) service.DIDCommAction {
	vp, err := createAuthorizationCredential(t).Presentation()
	require.NoError(t, err)

	if msg == nil {
		msg = presentproofsvc.RequestPresentation{
			Type: presentproofsvc.RequestPresentationMsgType,
			RequestPresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{
					JSON: vp,
				}},
			},
		}
	}

	return service.DIDCommAction{
		Message:    service.NewDIDCommMsgMap(msg),
		Continue:   continueFn,
		Stop:       stopFn,
		Properties: &actionEventEvent{},
	}
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

type mockHTTPClient struct {
	respValue *http.Response
	respErr   error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.respErr != nil {
		return nil, m.respErr
	}

	return m.respValue, nil
}

type stubPublicDIDCreator struct {
	createValue *did.Doc
	createErr   error
}

func (s *stubPublicDIDCreator) Create() (*did.Doc, error) {
	return s.createValue, s.createErr
}

type mockVCCrypto struct {
	signVCValue *verifiable.Credential
	signVCErr   error
	signVPValue *verifiable.Presentation
	signVPErr   error
}

func (s *mockVCCrypto) SignCredential(*verifiable.Credential, string) (*verifiable.Credential, error) {
	return s.signVCValue, s.signVCErr
}

func (s *mockVCCrypto) SignPresentation(*verifiable.Presentation, string) (*verifiable.Presentation, error) {
	return s.signVPValue, s.signVPErr
}

type mockRouteSvc struct {
	GetDIDDocValue *did.Doc
	GetDIDDocErr   error
}

func (s *mockRouteSvc) GetDIDDoc(connID string, requiredBlindedRouting bool) (*did.Doc, error) {
	return s.GetDIDDocValue, s.GetDIDDocErr
}

type didexchangeEvent struct {
	connID    string
	invID     string
	invIDFunc func() string
}

func (d *didexchangeEvent) ConnectionID() string {
	return d.connID
}

func (d *didexchangeEvent) InvitationID() string {
	if d.invIDFunc != nil {
		return d.invIDFunc()
	}

	return d.invID
}

func (d *didexchangeEvent) All() map[string]interface{} {
	return make(map[string]interface{})
}

const (
	vcFmt = `{
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
		  "id": "e9e0f944-7b74-4298-9f3e-00ca609d6266",
		  "inviteeDID":` + `"%s"` + `,
		  "inviteeDID":` + `"%s"` + `,
		  "threadID":` + `"%s"` + `,
		  "inviterLabel": "issuer-agent"
	   },
	   "issuer":"did:example:76e12ec712ebc6f1c221ebfeb1f",
	   "issuanceDate":"2010-01-01T19:23:24Z"
	}`

	prCardData = `{
	  "data": {
		"id": "http://example.com/b34ca6cd37bbf23",
		"givenName": "JOHN",
		"familyName": "SMITH",
		"gender": "Male",
		"image": "data:image/png;base64,iVBORw0KGgo...kJggg==",
		"residentSince": "2015-01-01",
		"lprCategory": "C09",
		"lprNumber": "999-999-999",
		"commuterClassification": "C1",
		"birthCountry": "Bahamas",
		"birthDate": "1958-07-17"
	  },
	   "metadata":{
		  "contexts":["https://trustbloc.github.io/context/vc/examples/citizenship-v1.jsonld"],
		  "types":["PermanentResidentCard"]
	   }
	}
	`
)
