/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
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
	ariesmockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	mockdiddoc "github.com/trustbloc/edge-adapter/pkg/internal/mock/diddoc"
	mockgovernance "github.com/trustbloc/edge-adapter/pkg/internal/mock/governance"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/issuecredential"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/messenger"
	mockoutofband "github.com/trustbloc/edge-adapter/pkg/internal/mock/outofband"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/presentproof"
	"github.com/trustbloc/edge-adapter/pkg/internal/testutil"
	"github.com/trustbloc/edge-adapter/pkg/profile/issuer"
	"github.com/trustbloc/edge-adapter/pkg/restapi"
	mockprovider "github.com/trustbloc/edge-adapter/pkg/restapi/internal/mocks/provider"
	adaptervc "github.com/trustbloc/edge-adapter/pkg/vc"
	issuervc "github.com/trustbloc/edge-adapter/pkg/vc/issuer"
)

func getAriesCtx(t *testing.T) aries.CtxProvider {
	t.Helper()

	return &mockprovider.MockProvider{
		Provider: &ariesmockprovider.Provider{
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
		},
	}
}

func config(t *testing.T) *Config {
	t.Helper()

	oidcClientStoreKey := make([]byte, 32)
	_, _ = rand.Read(oidcClientStoreKey) // nolint:errcheck

	return &Config{
		AriesCtx:             getAriesCtx(t),
		StoreProvider:        mem.NewProvider(),
		MsgRegistrar:         msghandler.NewRegistrar(),
		AriesMessenger:       &messenger.MockMessenger{},
		PublicDIDCreator:     &stubPublicDIDCreator{createValue: mockdiddoc.GetMockDIDDoc("did:example:def567")},
		GovernanceProvider:   &mockgovernance.MockProvider{},
		OIDCClientStoreKey:   oidcClientStoreKey,
		JSONLDDocumentLoader: testutil.DocumentLoader(t),
	}
}

func getHandler(t *testing.T, op *Operation, lookup string) restapi.Handler {
	t.Helper()

	return handlerLookup(t, op, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) restapi.Handler {
	t.Helper()

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
	t.Helper()

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

func serveHTTPMux(t *testing.T, handler restapi.Handler, endpoint string, reqBytes []byte, // nolint: unparam
	urlVars map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	r, err := http.NewRequest(handler.Method(), endpoint, bytes.NewBuffer(reqBytes))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	req1 := mux.SetURLVars(r, urlVars)

	handler.Handle().ServeHTTP(rr, req1)

	return rr
}

func getDefaultTestVP(t *testing.T) []byte {
	t.Helper()

	return getTestVP(t, inviteeDID, inviterDID, uuid.New().String())
}

func getTestVP(t *testing.T, inviteeDID, inviterDID, threadID string) []byte { //nolint: unparam
	t.Helper()

	vc, err := verifiable.ParseCredential(
		[]byte(fmt.Sprintf(vcFmt, inviteeDID, inviterDID, threadID)),
		verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
	)
	require.NoError(t, err)

	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
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
		SupportsWACI:                true,
	}
}

func createAuthorizationCredReq(t *testing.T, subjectDIDDoc, rpDIDDoc *did.Doc) json.RawMessage {
	t.Helper()

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
	t.Helper()

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
	t.Helper()

	if msg == nil {
		msg = issuecredsvc.RequestCredentialV2{
			Type: issuecredsvc.RequestCredentialMsgTypeV2,
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

// TODO add createProofReqMsgV3 for VCT present proof V3
func createProofReqMsgV2(t *testing.T, msg interface{}, continueFn func(args interface{}),
	stopFn func(err error)) service.DIDCommAction {
	t.Helper()

	vc := createAuthorizationCredential(t)
	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
	require.NoError(t, err)

	if msg == nil {
		msg = presentproofsvc.RequestPresentationV2{
			Type: presentproofsvc.RequestPresentationMsgTypeV2,
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

func createMockOIDCServer(authorize, token, jwk, userinfo, register string) *httptest.Server { // nolint:unparam
	openIDConfig := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/authorize":
			w.Header().Set("Location", authorize)
			w.WriteHeader(http.StatusFound)
		case "/token":
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			w.Write([]byte(token)) //nolint:errcheck,gosec
		case "/jwk":
			w.Write([]byte(jwk)) //nolint:errcheck,gosec
		case "/userinfo":
			w.Write([]byte(userinfo)) //nolint:errcheck,gosec
		case "/register":
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(register)) //nolint:errcheck,gosec
		case "/.well-known/openid-configuration":
			w.Write([]byte(openIDConfig)) //nolint:errcheck,gosec
		default:
			w.WriteHeader(http.StatusInternalServerError)
			//nolint:errcheck,gosec
			w.Write([]byte(
				"mock OIDC server does not contain a response for the request URI: `" + r.RequestURI + "'"),
			)
		}
	}))

	openIDConfig = fmt.Sprintf(`{
    "issuer":"%s",
    "authorization_endpoint":"%s/authorize",
    "token_endpoint":"%s/token",
    "jwks_uri":"%s/jwk",
    "userinfo_endpoint":"%s/userinfo",
	"registration_endpoint":"%s/register",
    "id_token_signing_alg_values_supported":["ES256"]
}`, server.URL, server.URL, server.URL, server.URL, server.URL, server.URL)

	return server
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

type failingStoreProvider struct {
	// openN calls to OpenStore() succeed, all subsequent calls fail with Err
	openN int
	Err   error
	// SuccessProvider uses this provider for successful calls
	SuccessProvider storage.Provider
}

func (f *failingStoreProvider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	panic("implement me")
}

func (f *failingStoreProvider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	panic("implement me")
}

func (f *failingStoreProvider) GetOpenStores() []storage.Store {
	panic("implement me")
}

func (f *failingStoreProvider) OpenStore(name string) (storage.Store, error) {
	if f.openN <= 0 {
		return nil, f.Err
	}

	f.openN--

	return f.SuccessProvider.OpenStore(name) // nolint:wrapcheck // test
}

func (f *failingStoreProvider) Close() error {
	return f.SuccessProvider.Close() // nolint:wrapcheck // test
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

type mockOIDCClient struct {
	CreateOIDCRequestValue  string
	CreateOIDCRequestErr    error
	HandleOIDCCallbackTok   *oauth2.Token
	HandleOIDCCallbackIDTok *oidc.IDToken
	HandleOIDCCallbackErr   error
	CheckRefreshTok         *oauth2.Token
	CheckRefreshErr         error
}

func (c *mockOIDCClient) CreateOIDCRequest(string, string) string {
	return c.CreateOIDCRequestValue
}

func (c *mockOIDCClient) HandleOIDCCallback(context.Context, string) (*oauth2.Token, *oidc.IDToken, error) {
	return c.HandleOIDCCallbackTok, c.HandleOIDCCallbackIDTok, c.HandleOIDCCallbackErr
}

func (c *mockOIDCClient) CheckRefresh(*oauth2.Token) (*oauth2.Token, error) {
	return c.CheckRefreshTok, c.CheckRefreshErr
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
