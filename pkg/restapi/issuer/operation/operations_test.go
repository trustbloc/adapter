/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	issuecredsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	outofbandsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mocksvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	mockconn "github.com/trustbloc/edge-adapter/pkg/internal/mock/connection"
	mockdiddoc "github.com/trustbloc/edge-adapter/pkg/internal/mock/diddoc"
	mockdidexchange "github.com/trustbloc/edge-adapter/pkg/internal/mock/didexchange"
	mockgovernance "github.com/trustbloc/edge-adapter/pkg/internal/mock/governance"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/issuecredential"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/messenger"
	mockoutofband "github.com/trustbloc/edge-adapter/pkg/internal/mock/outofband"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/presentproof"
	"github.com/trustbloc/edge-adapter/pkg/profile/issuer"
	adaptervc "github.com/trustbloc/edge-adapter/pkg/vc"
)

const (
	inviteeDID = "did:example:0d76fa4e1386"
	inviterDID = "did:example:e6025bfdbb8f"
)

func TestNew(t *testing.T) {
	t.Run("test new - success", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		require.Equal(t, 5, len(c.GetRESTHandlers()))
	})

	t.Run("test new - aries provider fail", func(t *testing.T) {
		c, err := New(&Config{AriesCtx: &mockprovider.Provider{}})
		require.Nil(t, c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create aries outofband client")
	})

	t.Run("test new - store fail", func(t *testing.T) {
		c, err := New(&Config{
			AriesCtx:      getAriesCtx(),
			StoreProvider: &mockstorage.Provider{ErrCreateStore: errors.New("error creating the store")},
		})
		require.Nil(t, c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating the store")
	})

	t.Run("test get txn store - create store error", func(t *testing.T) {
		s, err := getTxnStore(&mockstorage.Provider{ErrCreateStore: errors.New("error creating the store")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating the store")
		require.Nil(t, s)
	})

	t.Run("test get txn store - open store error", func(t *testing.T) {
		s, err := getTxnStore(&mockstorage.Provider{ErrOpenStoreHandle: errors.New("error opening the store")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error opening the store")
		require.Nil(t, s)
	})

	t.Run("test get token store - create store error", func(t *testing.T) {
		s, err := getTokenStore(&mockstorage.Provider{ErrCreateStore: errors.New("error creating the store")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating the store")
		require.Nil(t, s)
	})

	t.Run("test get token store - open store error", func(t *testing.T) {
		s, err := getTokenStore(&mockstorage.Provider{ErrOpenStoreHandle: errors.New("error opening the store")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error opening the store")
		require.Nil(t, s)
	})

	t.Run("mediator client error", func(t *testing.T) {
		config := config()
		config.AriesCtx = &mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				outofbandsvc.Name: &mockoutofband.MockService{},
			},
		}

		c, err := New(config)
		require.Nil(t, c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create aries mediator client")
	})
}

func TestCreateProfile(t *testing.T) {
	op, err := New(config())
	require.NoError(t, err)

	endpoint := profileEndpoint
	handler := getHandler(t, op, endpoint)

	t.Run("create profile - success", func(t *testing.T) {
		vReq := createProfileData(uuid.New().String())

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusCreated, rr.Code)

		profileRes := &issuer.ProfileData{}
		err = json.Unmarshal(rr.Body.Bytes(), &profileRes)
		require.NoError(t, err)
		require.Equal(t, vReq.ID, profileRes.ID)
		require.Equal(t, vReq.Name, profileRes.Name)
		require.Equal(t, vReq.URL, profileRes.URL)
		require.Equal(t, vReq.SupportsAssuranceCredential, profileRes.SupportsAssuranceCredential)
	})

	t.Run("create profile - failed to issue governance vc", func(t *testing.T) {
		op, err := New(config())
		require.NoError(t, err)

		op.governanceProvider = &mockgovernance.MockProvider{
			IssueCredentialFunc: func(didID, profileID string) ([]byte, error) {
				return nil, fmt.Errorf("failed to issue governance vc")
			}}

		h := getHandler(t, op, endpoint)

		vReq := createProfileData(uuid.New().String())

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, h.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to issue governance vc")
	})

	t.Run("create profile - invalid request", func(t *testing.T) {
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, []byte("invalid-json"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request")
	})

	t.Run("create profile - did creation failure", func(t *testing.T) {
		ops, err := New(config())
		require.NoError(t, err)

		ops.publicDIDCreator = &stubPublicDIDCreator{createErr: errors.New("did create error")}

		vReq := &ProfileDataRequest{}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, getHandler(t, ops, endpoint).Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create public did")

		// missing authentication
		didDoc := mockdiddoc.GetMockDIDDoc("did:example:123yz")
		auth := didDoc.Authentication
		didDoc.Authentication = nil
		ops.publicDIDCreator = &stubPublicDIDCreator{createValue: didDoc}

		rr = serveHTTP(t, getHandler(t, ops, endpoint).Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to fetch authentication method")

		didDoc.Authentication = auth

		// missing assertionMethod
		didDoc.AssertionMethod = nil

		rr = serveHTTP(t, getHandler(t, ops, endpoint).Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to fetch assertion method")
	})

	t.Run("create profile - error", func(t *testing.T) {
		vReq := &ProfileDataRequest{}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create profile: profile id mandatory")
	})
}

func TestGetProfile(t *testing.T) {
	op, err := New(config())
	require.NoError(t, err)

	endpoint := getProfileEndpoint
	handler := getHandler(t, op, endpoint)

	urlVars := make(map[string]string)

	t.Run("get profile - success", func(t *testing.T) {
		vReq := createProfileData(uuid.New().String())
		err := op.profileStore.SaveProfile(vReq)
		require.NoError(t, err)

		urlVars[idPathParam] = vReq.ID

		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusOK, rr.Code)

		profileRes := &issuer.ProfileData{}
		err = json.Unmarshal(rr.Body.Bytes(), &profileRes)
		require.NoError(t, err)
		require.Equal(t, vReq.ID, profileRes.ID)
	})

	t.Run("get profile - no data found", func(t *testing.T) {
		urlVars[idPathParam] = "invalid-name"

		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), storage.ErrValueNotFound.Error())
	})
}

func TestConnectWallet(t *testing.T) {
	uiEndpoint := "/ui"
	profileID := "test-1"
	state := uuid.New().String()
	endpoint := walletConnectEndpoint
	urlVars := make(map[string]string)

	tknResp := &IssuerTokenResp{
		Token: uuid.New().String(),
	}

	tknRespBytes, err := json.Marshal(tknResp)
	require.NoError(t, err)

	t.Run("test connect wallet - success", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		c.uiEndpoint = uiEndpoint
		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader(tknRespBytes)),
			},
		}

		data := createProfileData(profileID)
		err = c.profileStore.SaveProfile(data)
		require.NoError(t, err)

		walletConnectHandler := getHandler(t, c, endpoint)

		urlVars[idPathParam] = profileID

		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint+"?"+stateQueryParam+"="+state, nil, urlVars)

		require.Equal(t, http.StatusFound, rr.Code)
		require.Contains(t, rr.Header().Get("Location"), uiEndpoint)
	})

	t.Run("test connect wallet - profile doesn't exists", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader(tknRespBytes)),
			},
		}

		walletConnectHandler := getHandler(t, c, endpoint)

		urlVars[idPathParam] = profileID

		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), storage.ErrValueNotFound.Error())
	})

	t.Run("test connect wallet - no state in the url", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader(tknRespBytes)),
			},
		}

		data := createProfileData(profileID)
		err = c.profileStore.SaveProfile(data)
		require.NoError(t, err)

		walletConnectHandler := getHandler(t, c, endpoint)

		urlVars[idPathParam] = profileID

		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get state from the url")
	})

	t.Run("test connect wallet - failed to create invitation", func(t *testing.T) {
		config := config()
		config.AriesCtx = &mockprovider.Provider{
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
				issuecredsvc.Name:       &issuecredential.MockIssueCredentialSvc{},
				presentproofsvc.Name:    &presentproof.MockPresentProofSvc{},
				outofbandsvc.Name:       &mockoutofband.MockService{},
			},
			KMSValue:             &mockkms.KeyManager{CrAndExportPubKeyErr: errors.New("key generation error")},
			ServiceEndpointValue: "endpoint",
		}

		c, err := New(config)
		require.NoError(t, err)

		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader(tknRespBytes)),
			},
		}

		data := createProfileData(profileID)
		err = c.profileStore.SaveProfile(data)
		require.NoError(t, err)

		walletConnectHandler := getHandler(t, c, endpoint)

		urlVars[idPathParam] = profileID

		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint+"?"+stateQueryParam+"="+state, nil, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create invitation")
	})

	t.Run("test connect wallet - txn data store error", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader(tknRespBytes)),
			},
		}

		data := createProfileData(profileID)
		err = c.profileStore.SaveProfile(data)
		require.NoError(t, err)

		walletConnectHandler := getHandler(t, c, endpoint)

		urlVars[idPathParam] = profileID

		c.txnStore = &mockstorage.MockStore{
			Store:  make(map[string][]byte),
			ErrPut: errors.New("error inserting data"),
		}

		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint+"?"+stateQueryParam+"="+state, nil, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create txn")
	})

	t.Run("test connect wallet - retrieve token errors", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusBadRequest, Body: ioutil.NopCloser(bytes.NewReader([]byte("failed at issuer"))),
			},
		}

		data := createProfileData(profileID)
		err = c.profileStore.SaveProfile(data)
		require.NoError(t, err)

		walletConnectHandler := getHandler(t, c, endpoint)

		urlVars[idPathParam] = profileID

		// issuer http call error
		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint+"?"+stateQueryParam+"="+state, nil, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get token from to the issuer")

		// empty token from the issuer
		tknRespBytes, err = json.Marshal(&IssuerTokenResp{})
		require.NoError(t, err)

		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader(tknRespBytes)),
			},
		}

		rr = serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint+"?"+stateQueryParam+"="+state, nil, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "received empty token from the issuer")

		// issuer http call error
		rr = serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint+"?"+stateQueryParam+"="+state, nil, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get token from to the issuer")

		// invalid resp from issuer
		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte("invalid resp"))),
			},
		}

		rr = serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint+"?"+stateQueryParam+"="+state, nil, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "issuer response parse error")
	})
}

func TestValidateWalletResponse(t *testing.T) {
	c, err := New(config())
	require.NoError(t, err)

	profileID := "profile1"
	callbackURL := "http://issuer.example.com/cb"

	data := createProfileData(profileID)
	data.URL = callbackURL

	err = c.profileStore.SaveProfile(data)
	require.NoError(t, err)

	handler := getHandler(t, c, validateConnectResponseEndpoint)

	vReq := &WalletConnect{
		Resp: []byte(""),
	}

	vReqBytes, err := json.Marshal(vReq)
	require.NoError(t, err)

	connID := uuid.New().String()
	threadID := uuid.New().String()
	state := uuid.New().String()
	token := uuid.New().String()

	txnID, err := c.createTxn(data, state, token)
	require.NoError(t, err)

	txn, err := c.getTxn(txnID)
	require.NoError(t, err)

	c.connectionLookup = &mockconn.MockConnectionsLookup{
		ConnIDByDIDs: connID,
		ConnRecord: &connection.Record{
			ConnectionID:   connID,
			State:          didExCompletedState,
			ThreadID:       threadID,
			TheirDID:       inviteeDID,
			MyDID:          inviterDID,
			ParentThreadID: txn.DIDCommInvitation.ID,
		},
	}

	t.Run("test validate response - success", func(t *testing.T) {
		req := &WalletConnect{
			Resp: getTestVP(t, inviteeDID, inviterDID, threadID),
		}

		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+txnID, reqBytes)

		require.Equal(t, http.StatusOK, rr.Code)

		resp := &ValidateConnectResp{}
		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)

		u, parseErr := url.Parse(resp.RedirectURL)
		require.NoError(t, parseErr)

		require.Equal(t, state, u.Query().Get(stateQueryParam))
	})

	t.Run("test validate response - missing cookie", func(t *testing.T) {
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, validateConnectResponseEndpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get txnID from the url")
	})

	t.Run("test validate response - invalid req", func(t *testing.T) {
		txnID = "invalid-txn-id"

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+txnID, []byte("invalid-request"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request")
	})

	t.Run("test validate response - invalid txn id", func(t *testing.T) {
		txnID = "invalid-txn-id"

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+txnID, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "txn data not found")
	})

	t.Run("test validate response - invalid txn data", func(t *testing.T) {
		txnID = uuid.New().String()

		putErr := c.txnStore.Put(txnID, []byte("invalid json"))
		require.NoError(t, putErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+txnID, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "txn data not found")
	})

	t.Run("test validate response - invalid vp", func(t *testing.T) {
		txnID, err = c.createTxn(createProfileData("profile1"), uuid.New().String(), token)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+txnID, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to validate presentation")
	})

	t.Run("test validate response - profile not found", func(t *testing.T) {
		txnID, err = c.createTxn(createProfileData("invalid-profile"), uuid.New().String(), token)
		require.NoError(t, err)

		txn, err = c.getTxn(txnID)
		require.NoError(t, err)

		c.connectionLookup = &mockconn.MockConnectionsLookup{
			ConnIDByDIDs: connID,
			ConnRecord: &connection.Record{
				State:          didExCompletedState,
				ThreadID:       threadID,
				ParentThreadID: txn.DIDCommInvitation.ID,
			},
		}

		req := &WalletConnect{
			Resp: getTestVP(t, inviteeDID, inviterDID, threadID),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+txnID, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "profile not found")
	})

	t.Run("test validate response - validate connection errors", func(t *testing.T) {
		// inviterDID and inviteeDID combo not found
		c.connectionLookup = &mockconn.MockConnectionsLookup{
			ConnIDByDIDsErr: errors.New("connID not found"),
		}

		req := &WalletConnect{
			Resp: getDefaultTestVP(t),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+txnID, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "connection using DIDs not found")

		// connection not found
		c.connectionLookup = &mockconn.MockConnectionsLookup{
			ConnIDByDIDs:  connID,
			ConnRecordErr: errors.New("connection not found"),
		}

		rr = serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+txnID, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "connection using id not found")

		// connection state not completed
		c.connectionLookup = &mockconn.MockConnectionsLookup{
			ConnIDByDIDs: connID,
			ConnRecord: &connection.Record{
				ParentThreadID: txn.DIDCommInvitation.ID,
			},
		}

		rr = serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+txnID, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "connection state is not complete")

		// threadID not found
		c.connectionLookup = &mockconn.MockConnectionsLookup{
			ConnIDByDIDs: connID,
			ConnRecord: &connection.Record{
				ParentThreadID: txn.DIDCommInvitation.ID,
				State:          didExCompletedState,
			},
		}

		rr = serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+txnID, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "thread id not found")
	})

	t.Run("test validate response - success", func(t *testing.T) {
		ops, err := New(config())
		require.NoError(t, err)

		ops.connectionLookup = &mockconn.MockConnectionsLookup{
			ConnIDByDIDs: connID,
			ConnRecord: &connection.Record{
				ConnectionID:   connID,
				State:          didExCompletedState,
				ThreadID:       threadID,
				TheirDID:       inviteeDID,
				MyDID:          inviterDID,
				ParentThreadID: txn.DIDCommInvitation.ID,
			},
		}

		err = ops.profileStore.SaveProfile(data)
		require.NoError(t, err)

		id, err := ops.createTxn(createProfileData(profileID), state, token)
		require.NoError(t, err)

		ops.tokenStore = &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: errors.New("error put")}

		handler := getHandler(t, ops, validateConnectResponseEndpoint)

		req := &WalletConnect{
			Resp: getTestVP(t, inviteeDID, inviterDID, threadID),
		}

		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+id, reqBytes)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to store user connection mapping")
	})
}

func TestCHAPIRequest(t *testing.T) {
	t.Run("test fetch chapi request - success", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		c.governanceProvider = &mockgovernance.MockProvider{GetCredentialFunc: func(profileID string) ([]byte, error) {
			return []byte(`{"key":"value"}`), nil
		}}

		t.Run("without assurance support", func(t *testing.T) {
			profile := createProfileData("profile1")

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			txnID, txnErr := c.createTxn(profile, uuid.New().String(), uuid.New().String())
			require.NoError(t, txnErr)

			getCHAPIRequestHandler := getHandler(t, c, getCHAPIRequestEndpoint)

			rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
				getCHAPIRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)

			require.Equal(t, http.StatusOK, rr.Code)

			chapiReq := &CHAPIRequest{}
			err = json.Unmarshal(rr.Body.Bytes(), &chapiReq)
			require.NoError(t, err)
			require.Equal(t, DIDConnectCHAPIQueryType, chapiReq.Query.Type)
			require.Equal(t, "https://didcomm.org/oob-invitation/1.0/invitation", chapiReq.DIDCommInvitation.Type)
			require.Equal(t, `{"key":"value"}`, string(chapiReq.Credentials[1]))
			require.Equal(t, 2, len(chapiReq.Credentials))
		})

		t.Run("with assurance support", func(t *testing.T) {
			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}

			profile := createProfileData("profile2")
			profile.SupportsAssuranceCredential = true
			profile.CredentialSigningKey = mockdiddoc.GetMockDIDDoc("did:example:def567").VerificationMethod[0].ID

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			txnID, err := c.createTxn(profile, uuid.New().String(), uuid.New().String())
			require.NoError(t, err)

			getCHAPIRequestHandler := getHandler(t, c, getCHAPIRequestEndpoint)

			rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
				getCHAPIRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)

			require.Equal(t, http.StatusOK, rr.Code)

			chapiReq := &CHAPIRequest{}
			err = json.Unmarshal(rr.Body.Bytes(), &chapiReq)
			require.NoError(t, err)
			require.Equal(t, DIDConnectCHAPIQueryType, chapiReq.Query.Type)
			require.Equal(t, "https://didcomm.org/oob-invitation/1.0/invitation", chapiReq.DIDCommInvitation.Type)
			require.Equal(t, `{"key":"value"}`, string(chapiReq.Credentials[2]))
			require.Equal(t, 3, len(chapiReq.Credentials))
		})
	})

	t.Run("test get governance - failed", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		c.governanceProvider = &mockgovernance.MockProvider{GetCredentialFunc: func(profileID string) ([]byte, error) {
			return nil, fmt.Errorf("failed to get vc")
		}}

		profile := createProfileData("profile1")

		err = c.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		txnID, err := c.createTxn(profile, uuid.New().String(), uuid.New().String())
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCHAPIRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
			getCHAPIRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "error retrieving governance vc : failed to get vc")
	})

	t.Run("test fetch invitation - no txnID in the url query", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCHAPIRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet, getCHAPIRequestEndpoint, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get txnID from the url")
	})

	t.Run("test fetch invitation - invalid txnID", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCHAPIRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
			getCHAPIRequestEndpoint+"?"+txnIDQueryParam+"=invalid-txnID", nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "txn data not found")
	})

	t.Run("test fetch invitation - profile not found", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		profile := createProfileData("profile1")

		txnID, err := c.createTxn(profile, uuid.New().String(), uuid.New().String())
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCHAPIRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
			getCHAPIRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "issuer not found")
	})

	t.Run("test fetch chapi request with assurance - error", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		profile := createProfileData("profile2")
		profile.SupportsAssuranceCredential = true

		err = c.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		txnID, err := c.createTxn(profile, uuid.New().String(), uuid.New().String())
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCHAPIRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
			getCHAPIRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "error creating reference credential")
	})
}

// nolint
func TestIssueCredentialHandler(t *testing.T) {
	t.Run("test issue credential", func(t *testing.T) {
		actionCh := make(chan service.DIDCommAction, 1)

		c, err := issueCredentialClient(getAriesCtx(), actionCh)
		require.NoError(t, err)
		require.NotNil(t, c)

		c, err = issueCredentialClient(&mockprovider.Provider{}, actionCh)
		require.Error(t, err)
		require.Nil(t, c)

		c, err = issueCredentialClient(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				issuecredsvc.Name: &issuecredential.MockIssueCredentialSvc{
					RegisterActionEventErr: errors.New("register error")},
			},
		}, actionCh)
		require.Error(t, err)
		require.Contains(t, err.Error(), "register error")
		require.Nil(t, c)
	})

	t.Run("test present proof", func(t *testing.T) {
		actionCh := make(chan service.DIDCommAction, 1)

		c, err := presentProofClient(getAriesCtx(), actionCh)
		require.NoError(t, err)
		require.NotNil(t, c)

		c, err = presentProofClient(&mockprovider.Provider{}, actionCh)
		require.Error(t, err)
		require.Nil(t, c)

		c, err = presentProofClient(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				presentproofsvc.Name: &presentproof.MockPresentProofSvc{
					RegisterActionEventErr: errors.New("register error")},
			},
		}, actionCh)
		require.Error(t, err)
		require.Contains(t, err.Error(), "register error")
		require.Nil(t, c)
	})

	t.Run("test didcomm actions - unsupported message", func(t *testing.T) {
		actionCh := make(chan service.DIDCommAction, 1)

		c, err := New(config())
		require.NoError(t, err)

		go c.didCommActionListener(actionCh)

		done := make(chan struct{})

		actionCh <- service.DIDCommAction{
			Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredential{
				Type: "unsupported-message-type",
			}),
			Stop: func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "unsupported message type")
				done <- struct{}{}
			},
		}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("test didcomm actions - issue credential request", func(t *testing.T) {
		t.Run("test request issue cred - success", func(t *testing.T) {
			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config())
			require.NoError(t, err)

			connID := uuid.New().String()
			c.connectionLookup = &mockconn.MockConnectionsLookup{
				ConnIDByDIDs: connID,
			}

			issuerID := uuid.New().String()

			profile := createProfileData(issuerID)
			profile.CredentialSigningKey = mockdiddoc.GetMockDIDDoc("did:example:def567").VerificationMethod[0].ID

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			err = c.storeUserConnectionMapping(&UserConnectionMapping{
				ConnectionID: connID,
				IssuerID:     issuerID,
				Token:        uuid.New().String(),
			})
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			done := make(chan struct{})

			actionCh <- service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredential{
					Type: issuecredsvc.RequestCredentialMsgType,
					RequestsAttach: []decorator.Attachment{
						{Data: decorator.AttachmentData{
							JSON: createAuthorizationCredReq(t, mockdiddoc.GetMockDIDDoc("did:example:xyz123"),
								mockdiddoc.GetMockDIDDoc("did:example:def567")),
						}},
					},
				}),
				Continue: func(args interface{}) {
					done <- struct{}{}
				},
				Properties: &actionEventEvent{},
			}

			select {
			case <-done:
			case <-time.After(65 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}
		})

		t.Run("test request issue cred - did creation failure", func(t *testing.T) {
			actionCh := make(chan service.DIDCommAction, 1)

			config := config()
			config.AriesCtx = &mockprovider.Provider{
				ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
				StorageProviderValue:              mockstore.NewMockStoreProvider(),
				ServiceMap: map[string]interface{}{
					didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
					mediator.Coordination:   &mockroute.MockMediatorSvc{},
					issuecredsvc.Name:       &issuecredential.MockIssueCredentialSvc{},
					presentproofsvc.Name:    &presentproof.MockPresentProofSvc{},
					outofbandsvc.Name:       &mockoutofband.MockService{},
				},
				ServiceEndpointValue: "endpoint",
				VDRegistryValue: &mockvdr.MockVDRegistry{
					CreateErr: errors.New("did create error"),
				},
			}

			c, err := New(config)
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			connID := uuid.New().String()
			c.connectionLookup = &mockconn.MockConnectionsLookup{
				ConnIDByDIDs: connID,
			}

			issuerID := uuid.New().String()

			profile := createProfileData(issuerID)
			profile.CredentialSigningKey = mockdiddoc.GetMockDIDDoc("did:example:def567").VerificationMethod[0].ID

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			err = c.storeUserConnectionMapping(&UserConnectionMapping{
				ConnectionID: connID,
				IssuerID:     issuerID,
				Token:        uuid.New().String(),
			})
			require.NoError(t, err)

			done := make(chan struct{})

			actionCh <- createCredentialReqMsg(t, nil, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "create new issuer did")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}
		})

		t.Run("test request issue cred - validation failures", func(t *testing.T) {
			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config())
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			done := make(chan struct{})

			// connection not found
			actionCh <- createCredentialReqMsg(t, nil, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "connection using DIDs not found")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// connID-token mapping not found
			connID := uuid.New().String()
			c.connectionLookup = &mockconn.MockConnectionsLookup{
				ConnIDByDIDs: connID,
			}

			actionCh <- createCredentialReqMsg(t, nil, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "get token from the connectionID")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// profile not found
			issuerID := uuid.New().String()

			err = c.storeUserConnectionMapping(&UserConnectionMapping{
				ConnectionID: connID,
				IssuerID:     issuerID,
				Token:        uuid.New().String(),
			})
			require.NoError(t, err)

			actionCh <- createCredentialReqMsg(t, nil, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "fetch issuer profile")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// error saving authorization cred data
			profile := createProfileData(issuerID)
			profile.CredentialSigningKey = mockdiddoc.GetMockDIDDoc("did:example:def567").VerificationMethod[0].ID

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			err = c.storeUserConnectionMapping(&UserConnectionMapping{
				ConnectionID: connID,
				IssuerID:     issuerID,
				Token:        uuid.New().String(),
			})
			require.NoError(t, err)

			c.txnStore = &mockstorage.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: errors.New("error inserting data"),
			}

			actionCh <- createCredentialReqMsg(t, nil, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "store authorization credential")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// signing error
			c.txnStore = &mockstorage.MockStore{
				Store: make(map[string][]byte),
			}
			c.vccrypto = &mockVCCrypto{signVCErr: errors.New("sign error")}

			actionCh <- createCredentialReqMsg(t, nil, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "sign authorization credential")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// no attachment
			actionCh <- createCredentialReqMsg(t, issuecredsvc.RequestCredential{
				Type: issuecredsvc.RequestCredentialMsgType,
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(),
					"credential request should have one attachment")
				done <- struct{}{}
			})
		})

		t.Run("test request issue cred - request validation", func(t *testing.T) {
			cc, err := fetchAuthorizationCreReq(service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredential{
					Type: issuecredsvc.RequestCredentialMsgType,
				}),
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "credential request should have one attachment")
			require.Nil(t, cc)

			cc, err = fetchAuthorizationCreReq(service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredential{
					Type: issuecredsvc.RequestCredentialMsgType,
					RequestsAttach: []decorator.Attachment{
						{Data: decorator.AttachmentData{}},
					},
				}),
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "no data inside the credential request attachment")
			require.Nil(t, cc)

			cc, err = fetchAuthorizationCreReq(service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredential{
					Type: issuecredsvc.RequestCredentialMsgType,
					RequestsAttach: []decorator.Attachment{
						{Data: decorator.AttachmentData{
							JSON: []byte("invalid json"),
						}},
					},
				}),
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid json data in credential request")
			require.Nil(t, cc)

			// authorization cred does't contain subjectDID
			cc, err = fetchAuthorizationCreReq(service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredential{
					Type: issuecredsvc.RequestCredentialMsgType,
					RequestsAttach: []decorator.Attachment{
						{Data: decorator.AttachmentData{
							JSON: createAuthorizationCredReq(t, mockdiddoc.GetMockDIDDoc(""),
								mockdiddoc.GetMockDIDDoc("did:example:def567")),
						}},
					},
				}),
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "subject did data is missing in authorization cred request")
			require.Nil(t, cc)

			// authorization cred does't contain rpDIDDoc
			cc, err = fetchAuthorizationCreReq(service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredential{
					Type: issuecredsvc.RequestCredentialMsgType,
					RequestsAttach: []decorator.Attachment{
						{Data: decorator.AttachmentData{
							JSON: createAuthorizationCredReq(t, mockdiddoc.GetMockDIDDoc("did:example:xyz123"), nil),
						}},
					},
				}),
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "rp did data is missing in authorization cred request")
			require.Nil(t, cc)
		})

		t.Run("create did doc error", func(t *testing.T) {
			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config())
			require.NoError(t, err)

			c.routeSvc = &mockRouteSvc{
				GetDIDDocErr: errors.New("create did"),
			}

			connID := uuid.New().String()
			c.connectionLookup = &mockconn.MockConnectionsLookup{
				ConnIDByDIDs: connID,
			}

			issuerID := uuid.New().String()

			profile := createProfileData(issuerID)

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			err = c.storeUserConnectionMapping(&UserConnectionMapping{
				ConnectionID: connID,
				IssuerID:     issuerID,
				Token:        uuid.New().String(),
			})
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			done := make(chan struct{})

			actionCh <- service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredential{
					Type: issuecredsvc.RequestCredentialMsgType,
					RequestsAttach: []decorator.Attachment{
						{Data: decorator.AttachmentData{
							JSON: createAuthorizationCredReq(t, mockdiddoc.GetMockDIDDoc("did:example:xyz123"),
								mockdiddoc.GetMockDIDDoc("did:example:def567")),
						}},
					},
				}),
				Stop: func(err error) {
					require.NotNil(t, err)
					require.Contains(t, err.Error(), "create new issuer did")
					done <- struct{}{}
				},
				Properties: &actionEventEvent{},
			}

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}
		})
	})
}

// nolint
func TestPresentProofHandler(t *testing.T) {
	t.Run("test didcomm actions - present proof request", func(t *testing.T) {
		t.Run("test request presentation - success", func(t *testing.T) {
			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config())
			require.NoError(t, err)

			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}

			issuerID := uuid.New().String()

			profile := createProfileData(issuerID)
			profile.PresentationSigningKey = mockdiddoc.GetMockDIDDoc("did:example:def567").VerificationMethod[0].ID
			profile.CredentialSigningKey = mockdiddoc.GetMockDIDDoc("did:example:def567").VerificationMethod[0].ID

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			didDocument := mockdiddoc.GetMockDIDDoc("did:example:def567")

			didDocJSON, err := didDocument.JSONBytes()
			require.NoError(t, err)

			subjectDID := "did:example:abc789"

			rpDIDDoc := &adaptervc.DIDDoc{
				ID:  didDocument.ID,
				Doc: didDocJSON,
			}

			vc := createAuthorizationCredential(t)

			handle := &AuthorizationCredentialHandle{
				ID:         vc.ID,
				IssuerDID:  didDocument.ID,
				SubjectDID: subjectDID,
				RPDID:      rpDIDDoc.ID,
				Token:      uuid.New().String(),
				IssuerID:   issuerID,
			}

			err = c.storeAuthorizationCredHandle(handle)
			require.NoError(t, err)

			vp, err := vc.Presentation()
			require.NoError(t, err)

			done := make(chan struct{})

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, func(args interface{}) {
				done <- struct{}{}
			}, nil)

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}
		})

		t.Run("test request presentation - success (assurance flow)", func(t *testing.T) {
			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config())
			require.NoError(t, err)

			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}

			issuerID := uuid.New().String()

			profile := createProfileData(issuerID)
			profile.PresentationSigningKey = mockdiddoc.GetMockDIDDoc("did:example:def567").VerificationMethod[0].ID
			profile.CredentialSigningKey = mockdiddoc.GetMockDIDDoc("did:example:def567").VerificationMethod[0].ID
			profile.SupportsAssuranceCredential = true

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			didDocument := mockdiddoc.GetMockDIDDoc("did:example:def567")

			didDocJSON, err := didDocument.JSONBytes()
			require.NoError(t, err)

			subjectDID := "did:example:abc789"

			rpDIDDoc := &adaptervc.DIDDoc{
				ID:  didDocument.ID,
				Doc: didDocJSON,
			}

			vc := createAuthorizationCredential(t)

			handle := &AuthorizationCredentialHandle{
				ID:         vc.ID,
				IssuerDID:  didDocument.ID,
				SubjectDID: subjectDID,
				RPDID:      rpDIDDoc.ID,
				Token:      uuid.New().String(),
				IssuerID:   issuerID,
			}

			err = c.storeAuthorizationCredHandle(handle)
			require.NoError(t, err)

			refCredData := &ReferenceCredentialData{
				ID: uuid.New().String(),
			}

			refCredDataBytes, err := json.Marshal(refCredData)
			require.NoError(t, err)

			err = c.txnStore.Put(handle.Token, refCredDataBytes)
			require.NoError(t, err)

			vp, err := vc.Presentation()
			require.NoError(t, err)

			done := make(chan struct{})

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, func(args interface{}) {
				done <- struct{}{}
			}, nil)

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}
		})

		t.Run("test request presentation - failures", func(t *testing.T) {
			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config())
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			done := make(chan struct{})

			// request doesn't have attachment
			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(),
					"presentation request should have one attachment")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// request doesn't have authorization cred
			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(),
					"no data inside the presentation request attachment")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// invalid authorization cred
			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: "invalid vp",
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(),
					"parse presentation")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// authorization cred not found
			actionCh <- createProofReqMsg(t, nil, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "authorization credential not found")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// authorization cred data error
			didDocument := mockdiddoc.GetMockDIDDoc("did:example:def567")

			didDocJSON, err := didDocument.JSONBytes()
			require.NoError(t, err)

			subjectDID := "did:example:abc789"

			rpDIDDoc := &adaptervc.DIDDoc{
				ID:  didDocument.ID,
				Doc: didDocJSON,
			}

			vc := createAuthorizationCredential(t)
			vp, err := vc.Presentation()
			require.NoError(t, err)

			err = c.txnStore.Put(vc.ID, []byte("invalid data"))
			require.NoError(t, err)

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "authorization credential handle")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// issuer doesnt exists
			handle := &AuthorizationCredentialHandle{
				ID:         vc.ID,
				IssuerDID:  didDocument.ID,
				SubjectDID: subjectDID,
				RPDID:      rpDIDDoc.ID,
				Token:      uuid.New().String(),
				IssuerID:   uuid.New().String(),
			}

			err = c.storeAuthorizationCredHandle(handle)
			require.NoError(t, err)

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "fetch issuer profile")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// set up issuer/handle data
			issuerID := uuid.New().String()
			handle.IssuerID = issuerID
			err = c.storeAuthorizationCredHandle(handle)
			require.NoError(t, err)

			err = c.profileStore.SaveProfile(createProfileData(issuerID))
			require.NoError(t, err)

			// no vc inside vp
			pres := &verifiable.Presentation{
				Context: []string{"https://www.w3.org/2018/credentials/v1"},
				ID:      uuid.New().URN(),
				Type:    []string{"VerifiablePresentation"},
			}

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: pres,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "request presentation should have one credential, but contains 0")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// sign error
			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}

			c.vccrypto = &mockVCCrypto{signVPErr: errors.New("sign error")}

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "sign presentation")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// assertionMethod not present
			didDocument.AssertionMethod = nil

			c.vdriRegistry = &mockvdr.MockVDRegistry{
				ResolveValue: didDocument,
			}

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "failed to obtain a assertion verification method from issuer did")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// authentication not present
			didDocument = mockdiddoc.GetMockDIDDoc("did:example:def567")
			didDocument.Authentication = nil

			c.vdriRegistry = &mockvdr.MockVDRegistry{
				ResolveValue: didDocument,
			}

			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "failed to obtain a authentication verification method from issuer did")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// issuer did not found
			c.vdriRegistry = &mockvdr.MockVDRegistry{
				ResolveErr: errors.New("did not found"),
			}

			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "failed to resolve issuer did")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}
		})

		t.Run("test request presentation - issuer user data fetch failures", func(t *testing.T) {
			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config())
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			done := make(chan struct{})

			vc := createAuthorizationCredential(t)
			vp, err := vc.Presentation()
			require.NoError(t, err)

			issuerID := uuid.New().String()
			err = c.profileStore.SaveProfile(createProfileData(issuerID))
			require.NoError(t, err)

			handle := &AuthorizationCredentialHandle{
				ID:       vc.ID,
				Token:    uuid.New().String(),
				IssuerID: issuerID,
			}
			err = c.storeAuthorizationCredHandle(handle)
			require.NoError(t, err)

			// http request fails
			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "http request")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// invalid user data resp
			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte("invalid data json"))),
				},
			}

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "unmarshal issuer resp")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// invalid user data
			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte(`{
	  					"data": "abc"
					}`))),
				},
			}

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "unmarshal user data")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// sign error
			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}
			c.vccrypto = &mockVCCrypto{signVCErr: errors.New("sign error")}

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "sign vc")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}
		})

		t.Run("test request presentation - failures (assurance flow)", func(t *testing.T) {
			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config())
			require.NoError(t, err)

			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}

			issuerID := uuid.New().String()

			profile := createProfileData(issuerID)
			profile.PresentationSigningKey = mockdiddoc.GetMockDIDDoc("did:example:def567").VerificationMethod[0].ID
			profile.CredentialSigningKey = mockdiddoc.GetMockDIDDoc("did:example:def567").VerificationMethod[0].ID
			profile.SupportsAssuranceCredential = true

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			didDocument := mockdiddoc.GetMockDIDDoc("did:example:def567")

			didDocJSON, err := didDocument.JSONBytes()
			require.NoError(t, err)

			subjectDID := "did:example:abc789"

			rpDIDDoc := &adaptervc.DIDDoc{
				ID:  didDocument.ID,
				Doc: didDocJSON,
			}

			vc := createAuthorizationCredential(t)

			handle := &AuthorizationCredentialHandle{
				ID:         vc.ID,
				IssuerDID:  didDocument.ID,
				SubjectDID: subjectDID,
				RPDID:      rpDIDDoc.ID,
				Token:      uuid.New().String(),
				IssuerID:   issuerID,
			}

			err = c.storeAuthorizationCredHandle(handle)
			require.NoError(t, err)

			vp, err := vc.Presentation()
			require.NoError(t, err)

			done := make(chan struct{})

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vp,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "get reference credential data")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}
		})
	})
}

func TestGetConnectionIDFromEvent(t *testing.T) {
	c, err := New(config())
	require.NoError(t, err)

	connID := uuid.New().String()
	c.connectionLookup = &mockconn.MockConnectionsLookup{
		ConnIDByDIDs: connID,
	}

	t.Run("test get connID from event - success", func(t *testing.T) {
		id, err := c.getConnectionIDFromEvent(
			service.DIDCommAction{
				Properties: &actionEventEvent{},
			},
		)

		require.NoError(t, err)
		require.Equal(t, connID, id)
	})

	t.Run("test get connID from event - error", func(t *testing.T) {
		// no props found
		id, err := c.getConnectionIDFromEvent(
			service.DIDCommAction{
				Properties: &actionEventEvent{props: make(map[string]interface{})},
			},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no properties in the event")
		require.Empty(t, id)

		// myDID not found
		id, err = c.getConnectionIDFromEvent(
			service.DIDCommAction{
				Properties: &actionEventEvent{props: map[string]interface{}{
					"theirDID": "did:example:789",
				}},
			},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "myDID not found")
		require.Empty(t, id)

		// theirDID not found
		id, err = c.getConnectionIDFromEvent(
			service.DIDCommAction{
				Properties: &actionEventEvent{props: map[string]interface{}{
					"myDID": "did:example:123",
				}},
			},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "theirDID not found")
		require.Empty(t, id)

		// theirDID value is not string
		id, err = c.getConnectionIDFromEvent(
			service.DIDCommAction{
				Properties: &actionEventEvent{props: map[string]interface{}{
					"myDID":    "did:example:123",
					"theirDID": 100,
				}},
			},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "theirDID not a string")
		require.Empty(t, id)
	})

	t.Run("test get connection mapping - error", func(t *testing.T) {
		connID := uuid.New().String()

		err := c.tokenStore.Put(connID, []byte("invalid json data"))
		require.NoError(t, err)

		data, err := c.getUserConnectionMapping(connID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "user conn map :")
		require.Empty(t, data)
	})

	t.Run("test send http request - error", func(t *testing.T) {
		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusBadRequest, Body: ioutil.NopCloser(bytes.NewReader([]byte("invalid vc"))),
			},
		}

		req, err := http.NewRequest(http.MethodPost, "", nil)
		require.NoError(t, err)

		data, err := sendHTTPRequest(req, c.httpClient, http.StatusOK, "abc789")
		require.Error(t, err)
		require.Contains(t, err.Error(), "http request: 400 invalid vc")
		require.Empty(t, data)
	})
}

func TestDIDCommStateMsgListener(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		done := make(chan struct{})

		c.messenger = &messenger.MockMessenger{
			SendFunc: func(msg service.DIDCommMsgMap, myDID, theirDID string) error {
				pMsg := &aries.DIDCommMsg{}
				err = msg.Decode(pMsg)
				require.NoError(t, err)

				done <- struct{}{}

				return nil
			},
		}
		c.didExClient = &mockdidexchange.MockClient{}

		msgCh := make(chan service.StateMsg, 1)
		go c.didCommStateMsgListener(msgCh)

		msgCh <- service.StateMsg{
			Type:         service.PostState,
			ProtocolName: didexchange.DIDExchange,
			StateID:      didexchange.StateIDCompleted,
			Properties: &didexchangeEvent{
				connID: uuid.New().String(),
			},
		}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("ignore pre state", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		msg := service.StateMsg{
			Type:         service.PreState,
			ProtocolName: didexchange.DIDExchange,
			StateID:      didexchange.StateIDCompleted,
			Properties: &didexchangeEvent{
				connID: uuid.New().String(),
			},
		}

		err = c.hanlDIDExStateMsg(msg)
		require.NoError(t, err)
	})

	t.Run("send message error", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		c.messenger = &messenger.MockMessenger{
			SendFunc: func(msg service.DIDCommMsgMap, myDID, theirDID string) error {
				return errors.New("send error")
			},
		}
		c.didExClient = &mockdidexchange.MockClient{}

		msg := service.StateMsg{
			Type:         service.PostState,
			ProtocolName: didexchange.DIDExchange,
			StateID:      didexchange.StateIDCompleted,
			Properties: &didexchangeEvent{
				connID: uuid.New().String(),
			},
		}

		err = c.hanlDIDExStateMsg(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "send didex state complete msg")
	})

	t.Run("cast to didex event error", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		c.messenger = &messenger.MockMessenger{
			SendFunc: func(msg service.DIDCommMsgMap, myDID, theirDID string) error {
				return errors.New("send error")
			},
		}
		c.didExClient = &mockdidexchange.MockClient{}

		msg := service.StateMsg{
			Type:         service.PostState,
			ProtocolName: didexchange.DIDExchange,
			StateID:      didexchange.StateIDCompleted,
		}

		err = c.hanlDIDExStateMsg(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to cast didexchange event properties")
	})

	t.Run("get connection error", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		c.messenger = &messenger.MockMessenger{
			SendFunc: func(msg service.DIDCommMsgMap, myDID, theirDID string) error {
				return errors.New("send error")
			},
		}
		c.didExClient = &mockdidexchange.MockClient{
			GetConnectionErr: errors.New("get conn error"),
		}

		msg := service.StateMsg{
			Type:         service.PostState,
			ProtocolName: didexchange.DIDExchange,
			StateID:      didexchange.StateIDCompleted,
			Properties: &didexchangeEvent{
				connID: uuid.New().String(),
			},
		}

		err = c.hanlDIDExStateMsg(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get connection for id=")
	})
}
