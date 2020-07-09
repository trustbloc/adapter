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
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	issuecredsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mocksvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	mockconn "github.com/trustbloc/edge-adapter/pkg/internal/mock/connection"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/issuecredential"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/presentproof"
	"github.com/trustbloc/edge-adapter/pkg/profile/issuer"
	adaptervc "github.com/trustbloc/edge-adapter/pkg/vc"
	issuervc "github.com/trustbloc/edge-adapter/pkg/vc/issuer"
)

const (
	inviteeDID = "did:example:0d76fa4e1386"
	inviterDID = "did:example:e6025bfdbb8f"
)

func TestNew(t *testing.T) {
	t.Run("test new - success", func(t *testing.T) {
		c, err := New(&Config{
			AriesCtx:      getAriesCtx(),
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		require.Equal(t, 5, len(c.GetRESTHandlers()))
	})

	t.Run("test new - aries provider fail", func(t *testing.T) {
		c, err := New(&Config{AriesCtx: &mockprovider.Provider{}})
		require.Nil(t, c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create aries did exchange client")
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
}

func TestCreateProfile(t *testing.T) {
	op, err := New(&Config{
		AriesCtx:      getAriesCtx(),
		StoreProvider: memstore.NewProvider(),
	})
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
	})

	t.Run("create profile - invalid request", func(t *testing.T) {
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, []byte("invalid-json"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request")
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
	op, err := New(&Config{
		AriesCtx:      getAriesCtx(),
		StoreProvider: memstore.NewProvider(),
	})
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
		require.Contains(t, rr.Body.String(), "store does not have a value associated with this key")
	})
}

func TestConnectWallet(t *testing.T) {
	uiEndpoint := "/ui"
	profileID := "test-1"
	state := uuid.New().String()
	endpoint := walletConnectEndpoint
	urlVars := make(map[string]string)

	t.Run("test connect wallet - success", func(t *testing.T) {
		c, err := New(&Config{
			AriesCtx:      getAriesCtx(),
			StoreProvider: memstore.NewProvider(),
			UIEndpoint:    uiEndpoint,
		})
		require.NoError(t, err)

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
		c, err := New(&Config{
			AriesCtx:      getAriesCtx(),
			StoreProvider: memstore.NewProvider(),
			UIEndpoint:    uiEndpoint,
		})
		require.NoError(t, err)

		walletConnectHandler := getHandler(t, c, endpoint)

		urlVars[idPathParam] = profileID

		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "store does not have a value associated with this key")
	})

	t.Run("test connect wallet - no state in the url", func(t *testing.T) {
		c, err := New(&Config{
			AriesCtx:      getAriesCtx(),
			StoreProvider: memstore.NewProvider(),
			UIEndpoint:    uiEndpoint,
		})
		require.NoError(t, err)

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
		ariesCtx := &mockprovider.Provider{
			TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:          mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
				issuecredsvc.Name:       &issuecredential.MockIssueCredentialSvc{},
				presentproofsvc.Name:    &presentproof.MockPresentProofSvc{},
			},
			LegacyKMSValue:       &mockkms.CloseableKMS{CreateKeyErr: errors.New("key generation error")},
			ServiceEndpointValue: "endpoint",
		}

		c, err := New(&Config{
			AriesCtx:      ariesCtx,
			StoreProvider: memstore.NewProvider(),
			UIEndpoint:    uiEndpoint,
		})
		require.NoError(t, err)

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
		c, err := New(&Config{
			AriesCtx:      getAriesCtx(),
			StoreProvider: memstore.NewProvider(),
			UIEndpoint:    uiEndpoint,
		})
		require.NoError(t, err)

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
}

func TestValidateWalletResponse(t *testing.T) {
	c, err := New(&Config{
		AriesCtx:      getAriesCtx(),
		StoreProvider: memstore.NewProvider(),
	})
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

	txnID, err := c.createTxn(data, state)
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
		require.True(t, u.Query().Get("token") != "")
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
		txnID, err = c.createTxn(createProfileData("profile1"), uuid.New().String())
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+txnID, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to validate presentation")
	})

	t.Run("test validate response - profile not found", func(t *testing.T) {
		txnID, err = c.createTxn(createProfileData("invalid-profile"), uuid.New().String())
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
		ops, err := New(&Config{
			AriesCtx:      getAriesCtx(),
			StoreProvider: memstore.NewProvider(),
			//StoreProvider: &mockstorage.Provider{ErrCreateStore: errors.New("error creating the store")},
		})
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

		id, err := ops.createTxn(createProfileData(profileID), state)
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
	t.Run("test fetch invitation - success", func(t *testing.T) {
		c, err := New(&Config{
			AriesCtx:      getAriesCtx(),
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		txnID, err := c.createTxn(createProfileData("profile1"), uuid.New().String())
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCHAPIRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
			getCHAPIRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		chapiReq := &CHAPIRequest{}
		err = json.Unmarshal(rr.Body.Bytes(), &chapiReq)
		require.NoError(t, err)
		require.Equal(t, DIDConnectCHAPIQueryType, chapiReq.Query.Type)
		require.Equal(t, "https://didcomm.org/didexchange/1.0/invitation", chapiReq.DIDCommInvitation.Type)
	})

	t.Run("test fetch invitation - no txnID in the url query", func(t *testing.T) {
		c, err := New(&Config{
			AriesCtx:      getAriesCtx(),
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCHAPIRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet, getCHAPIRequestEndpoint, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get txnID from the url")
	})

	t.Run("test fetch invitation - invalid txnID", func(t *testing.T) {
		c, err := New(&Config{
			AriesCtx:      getAriesCtx(),
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCHAPIRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
			getCHAPIRequestEndpoint+"?"+txnIDQueryParam+"=invalid-txnID", nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "txn data not found")
	})
}

// nolint
func TestDIDCommListeners(t *testing.T) {
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

		c, err := New(&Config{
			AriesCtx:      getAriesCtx(),
			StoreProvider: memstore.NewProvider(),
		})
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

			c, err := New(&Config{
				AriesCtx:      getAriesCtx(),
				StoreProvider: memstore.NewProvider(),
			})
			require.NoError(t, err)

			connID := uuid.New().String()
			c.connectionLookup = &mockconn.MockConnectionsLookup{
				ConnIDByDIDs: connID,
			}

			err = c.storeUserConnectionMapping(&UserConnectionMapping{
				ConnectionID: connID,
				IssuerID:     uuid.New().String(),
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
							JSON: createConsentCredReq(t, "did:example:xyz123", mockdiddoc.GetMockDIDDoc()),
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
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}
		})

		t.Run("test request issue cred - did creation failure", func(t *testing.T) {
			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(&Config{
				AriesCtx: &mockprovider.Provider{
					TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
					StorageProviderValue:          mockstore.NewMockStoreProvider(),
					ServiceMap: map[string]interface{}{
						didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
						mediator.Coordination:   &mockroute.MockMediatorSvc{},
						issuecredsvc.Name:       &issuecredential.MockIssueCredentialSvc{},
						presentproofsvc.Name:    &presentproof.MockPresentProofSvc{},
					},
					LegacyKMSValue:       &mockkms.CloseableKMS{CreateEncryptionKeyValue: "sample-key"},
					ServiceEndpointValue: "endpoint",
					VDRIRegistryValue: &mockvdri.MockVDRIRegistry{
						CreateErr: errors.New("did create error"),
					},
				},
				StoreProvider: memstore.NewProvider(),
			})
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			done := make(chan struct{})

			actionCh <- createCredentialReqMsg(t, nil, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "handle credential request : did create error")
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

			c, err := New(&Config{
				AriesCtx:      getAriesCtx(),
				StoreProvider: memstore.NewProvider(),
			})
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			done := make(chan struct{})

			// connection not found
			actionCh <- createCredentialReqMsg(t, nil, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "handle credential request : connection using DIDs not found")
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

			// error saving consent cred data
			err = c.storeUserConnectionMapping(&UserConnectionMapping{
				ConnectionID: connID,
				IssuerID:     uuid.New().String(),
				Token:        uuid.New().String(),
			})
			require.NoError(t, err)

			c.txnStore = &mockstorage.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: errors.New("error inserting data"),
			}

			actionCh <- createCredentialReqMsg(t, nil, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "handle credential request : store consent credential")
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
					"handle credential request : credential request should have one attachment")
				done <- struct{}{}
			})
		})

		t.Run("test request issue cred - request validation", func(t *testing.T) {
			cc, err := fetchConsentCredReq(service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredential{
					Type: issuecredsvc.RequestCredentialMsgType,
				}),
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "credential request should have one attachment")
			require.Nil(t, cc)

			cc, err = fetchConsentCredReq(service.DIDCommAction{
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

			cc, err = fetchConsentCredReq(service.DIDCommAction{
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
		})
	})

	t.Run("test didcomm actions - present proof request", func(t *testing.T) {
		t.Run("test request presentation - success", func(t *testing.T) {
			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(&Config{
				AriesCtx:      getAriesCtx(),
				StoreProvider: memstore.NewProvider(),
			})
			require.NoError(t, err)

			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte(prCardVC))),
				},
			}

			issuerID := uuid.New().String()

			err = c.profileStore.SaveProfile(createProfileData(issuerID))
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			didDocument := mockdiddoc.GetMockDIDDoc()

			didDocJSON, err := didDocument.JSONBytes()
			require.NoError(t, err)

			userDID := "did:example:abc789"

			rpDIDDoc := &adaptervc.DIDDoc{
				ID:  didDocument.ID,
				Doc: didDocJSON,
			}

			vc := createConsentCredential(t)

			handle := &ConsentCredentialHandle{
				ID:        vc.ID,
				IssuerDID: didDocument.ID,
				UserDID:   userDID,
				RPDID:     rpDIDDoc.ID,
				Token:     uuid.New().String(),
				IssuerID:  issuerID,
			}

			err = c.storeConsentCredHandle(handle)
			require.NoError(t, err)

			done := make(chan struct{})

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vc,
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

			c, err := New(&Config{
				AriesCtx:      getAriesCtx(),
				StoreProvider: memstore.NewProvider(),
			})
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			done := make(chan struct{})

			// request doesn't have attachment
			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(),
					"handle presentation request : presentation request should have one attachment")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// request doesn't have consent cred
			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(),
					"handle presentation request : no data inside the presentation request attachment")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// invalid consent cred
			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: "invalid vc",
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(),
					"handle presentation request : decode new credential: embedded proof is not JSON")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// consent cred not found
			actionCh <- createProofReqMsg(t, nil, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "handle presentation request : consent credential not found")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// consent cred data error
			didDocument := mockdiddoc.GetMockDIDDoc()

			didDocJSON, err := didDocument.JSONBytes()
			require.NoError(t, err)

			userDID := "did:example:abc789"

			rpDIDDoc := &adaptervc.DIDDoc{
				ID:  didDocument.ID,
				Doc: didDocJSON,
			}

			vc := createConsentCredential(t)

			err = c.txnStore.Put(vc.ID, []byte("invalid data"))
			require.NoError(t, err)

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vc,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "handle presentation request : consent credential handle")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// issuer doesnt exists
			handle := &ConsentCredentialHandle{
				ID:        vc.ID,
				IssuerDID: didDocument.ID,
				UserDID:   userDID,
				RPDID:     rpDIDDoc.ID,
				Token:     uuid.New().String(),
				IssuerID:  uuid.New().String(),
			}

			err = c.storeConsentCredHandle(handle)
			require.NoError(t, err)

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vc,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "handle presentation request : get profile")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// http request fails
			issuerID := uuid.New().String()
			handle.IssuerID = issuerID
			err = c.storeConsentCredHandle(handle)
			require.NoError(t, err)

			err = c.profileStore.SaveProfile(createProfileData(issuerID))
			require.NoError(t, err)

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vc,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "handle presentation request : http request")
				done <- struct{}{}
			})

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				require.Fail(t, "tests are not validated due to timeout")
			}

			// invalid vc data
			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte("invalid vc json"))),
				},
			}

			actionCh <- createProofReqMsg(t, presentproofsvc.RequestPresentation{
				Type: presentproofsvc.RequestPresentationMsgType,
				RequestPresentationsAttach: []decorator.Attachment{
					{Data: decorator.AttachmentData{
						JSON: vc,
					}},
				},
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), "handle presentation request : parse user data vc")
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
	c, err := New(&Config{
		AriesCtx:      getAriesCtx(),
		StoreProvider: memstore.NewProvider(),
	})
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

func getAriesCtx() aries.CtxProvider {
	return &mockprovider.Provider{
		TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:          mockstore.NewMockStoreProvider(),
		ServiceMap: map[string]interface{}{
			didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
			mediator.Coordination:   &mockroute.MockMediatorSvc{},
			issuecredsvc.Name:       &issuecredential.MockIssueCredentialSvc{},
			presentproofsvc.Name:    &presentproof.MockPresentProofSvc{},
		},
		LegacyKMSValue:       &mockkms.CloseableKMS{CreateEncryptionKeyValue: "sample-key"},
		ServiceEndpointValue: "endpoint",
		VDRIRegistryValue: &mockvdri.MockVDRIRegistry{
			CreateValue: mockdiddoc.GetMockDIDDoc(),
		},
	}
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

	prCardVC = `{
	  "@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/citizenship/v1"
	  ],
	  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
	  "type": [
		"VerifiableCredential",
		"PermanentResidentCard"
	  ],
	  "name": "Permanent Resident Card",
	  "description": "Permanent Resident Card",
	  "issuer": "did:example:28394728934792387",
	  "issuanceDate": "2019-12-03T12:19:52Z",
	  "expirationDate": "2029-12-03T12:19:52Z",
	  "credentialSubject": {
		"id": "did:example:b34ca6cd37bbf23",
		"type": [
		  "PermanentResident",
		  "Person"
		],
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
	  }
	}
	`
)

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
		ID:                  profileID,
		Name:                "Issuer Profile 1",
		SupportedVCContexts: []string{"https://w3id.org/citizenship/v3"},
		URL:                 "http://issuer.example.com",
	}
}

func createConsentCredReq(t *testing.T, userDID string, rpDIDDoc *did.Doc) json.RawMessage {
	rpDIDDOcBytes, err := mockdiddoc.GetMockDIDDoc().JSONBytes()
	require.NoError(t, err)

	ccReq := ConsentCredentialReq{
		UserDID: userDID,
		RPDIDDoc: &adaptervc.DIDDoc{
			ID:  rpDIDDoc.ID,
			Doc: rpDIDDOcBytes,
		},
	}

	ccReqBytes, err := json.Marshal(ccReq)
	require.NoError(t, err)

	return ccReqBytes
}

func createConsentCredential(t *testing.T) *verifiable.Credential {
	didDocument := mockdiddoc.GetMockDIDDoc()

	didDocJSON, err := didDocument.JSONBytes()
	require.NoError(t, err)

	userDID := "did:example:abc789"

	rpDIDDoc := &adaptervc.DIDDoc{
		ID:  didDocument.ID,
		Doc: didDocJSON,
	}

	vc := issuervc.CreateConsentCredential(didDocument.ID, didDocJSON, rpDIDDoc, userDID)

	return vc
}

func createCredentialReqMsg(t *testing.T, msg interface{}, continueFn func(args interface{}), // nolint: unparam
	stopFn func(err error)) service.DIDCommAction {
	if msg == nil {
		msg = issuecredsvc.RequestCredential{
			Type: issuecredsvc.RequestCredentialMsgType,
			RequestsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{
					JSON: createConsentCredReq(t, "did:example:xyz123", mockdiddoc.GetMockDIDDoc()),
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
	if msg == nil {
		msg = presentproofsvc.RequestPresentation{
			Type: presentproofsvc.RequestPresentationMsgType,
			RequestPresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{
					JSON: createConsentCredential(t),
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
