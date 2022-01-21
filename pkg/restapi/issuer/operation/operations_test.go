/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	issuecredsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	outofbandsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mocksvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

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
	mockprovider "github.com/trustbloc/edge-adapter/pkg/restapi/internal/mocks/provider"
	adaptervc "github.com/trustbloc/edge-adapter/pkg/vc"
)

const (
	inviteeDID       = "did:example:0d76fa4e1386"
	inviterDID       = "did:example:e6025bfdbb8f"
	mockOIDCProvider = "mock.provider.local"
	mockCredScope    = "prc"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("test new - success", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		require.Equal(t, 12, len(c.GetRESTHandlers()))
	})

	t.Run("test new - aries provider fail", func(t *testing.T) {
		t.Parallel()

		c, err := New(&Config{AriesCtx: mockprovider.NewMockProvider()})
		require.Nil(t, c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create aries outofband client")
	})

	t.Run("test new - store fails", func(t *testing.T) {
		t.Parallel()

		const numStores = 6

		for i := 0; i < numStores; i++ {
			conf := config(t)

			conf.StoreProvider = &failingStoreProvider{
				openN:           i,
				Err:             fmt.Errorf("error opening the store"),
				SuccessProvider: conf.StoreProvider,
			}

			c, err := New(conf)
			require.Nil(t, c)
			require.Error(t, err)
			require.Contains(t, err.Error(), "error opening the store")
		}
	})

	t.Run("mediator client error", func(t *testing.T) {
		t.Parallel()

		config := config(t)
		config.AriesCtx = &mockprovider.MockProvider{
			Provider: &ariesmockprovider.Provider{
				ServiceMap: map[string]interface{}{
					outofbandsvc.Name: &mockoutofband.MockService{},
				},
			},
		}

		c, err := New(config)
		require.Nil(t, c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create aries mediator client")
	})

	t.Run("wallet bridge error", func(t *testing.T) {
		t.Parallel()

		config := config(t)
		config.AriesCtx = &mockprovider.MockProvider{
			Provider: &ariesmockprovider.Provider{
				StorageProviderValue: &mockstore.MockStoreProvider{
					FailNamespace: "walletappprofile",
				},
				ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
				ServiceMap: map[string]interface{}{
					outofbandsvc.Name:       &mockoutofband.MockService{},
					mediator.Coordination:   &mockroute.MockMediatorSvc{},
					didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
					issuecredsvc.Name:       &issuecredential.MockIssueCredentialSvc{},
					presentproofsvc.Name:    &presentproof.MockPresentProofSvc{},
				},
			},
		}

		c, err := New(config)
		require.Nil(t, c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to initialize wallet bridge")
	})
}

func Test_OIDCClientData(t *testing.T) {
	t.Parallel()

	t.Run("success: encrypt then decrypt", func(t *testing.T) {
		t.Parallel()

		data := oidcClientData{
			ID:     "abcd",
			Secret: "this is a secret value",
			Expiry: 1000,
		}

		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		enc, err := encryptClientData("abdc.website", key, &data)
		require.NoError(t, err)

		var wrapper oidcClientDataWrapper

		err = json.Unmarshal(enc, &wrapper)
		require.NoError(t, err)

		dec, err := decryptClientData(key, enc)
		require.NoError(t, err)

		require.Equal(t, data.ID, dec.ID)
		require.Equal(t, data.Secret, dec.Secret)
		require.Equal(t, data.Expiry, dec.Expiry)
	})

	t.Run("encrypt error: bad key", func(t *testing.T) {
		t.Parallel()

		data := oidcClientData{
			ID:     "abcd",
			Secret: "this is a secret value",
			Expiry: 1000,
		}

		badKey := make([]byte, 5) // bad length

		_, err := encryptClientData("abdc.website", badKey, &data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating AES cipher")
	})

	t.Run("decrypt error: bad key", func(t *testing.T) {
		t.Parallel()

		data := oidcClientData{
			ID:     "abcd",
			Secret: "this is a secret value",
			Expiry: 1000,
		}

		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		badKey := make([]byte, 5) // bad length

		enc, err := encryptClientData("abdc.website", key, &data)
		require.NoError(t, err)

		_, err = decryptClientData(badKey, enc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating AES cipher")
	})

	t.Run("decrypt error: garbled wrapper", func(t *testing.T) {
		t.Parallel()

		data := oidcClientData{
			ID:     "abcd",
			Secret: "this is a secret value",
			Expiry: 1000,
		}

		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		enc, err := encryptClientData("abdc.website", key, &data)
		require.NoError(t, err)

		if len(enc) != 0 {
			enc[0]++
		}

		_, err = decryptClientData(key, enc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error unmarshaling wrapper")
	})

	t.Run("decrypt error: incorrect encrypted payload", func(t *testing.T) {
		t.Parallel()

		data := oidcClientData{
			ID:     "abcd",
			Secret: "this is a secret value",
			Expiry: 1000,
		}

		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		enc, err := encryptClientData("abdc.website", key, &data)
		require.NoError(t, err)

		wrapper := oidcClientDataWrapper{}
		require.NoError(t, json.Unmarshal(enc, &wrapper))

		if len(wrapper.Payload) != 0 {
			wrapper.Payload[0]++
		}

		enc, err = json.Marshal(wrapper)
		require.NoError(t, err)

		_, err = decryptClientData(key, enc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error decrypting client data")
	})

	t.Run("decrypt error: garbled wrapped data", func(t *testing.T) {
		t.Parallel()

		data := oidcClientData{
			ID:     "abcd",
			Secret: "this is a secret value",
			Expiry: 1000,
		}

		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		// perform encryptClientData except the data gets garbled before encryption
		dataBytes, err := json.Marshal(data)
		require.NoError(t, err)

		// garble dataBytes
		if len(dataBytes) != 0 {
			dataBytes[0]++
		}

		nonce, err := makeNonce([]byte("provider.url"))
		require.NoError(t, err)

		block, err := aes.NewCipher(key)
		require.NoError(t, err)

		gcm, err := cipher.NewGCM(block)
		require.NoError(t, err)

		cipherText := gcm.Seal(nil, nonce, dataBytes, nil)

		dataWrapper := oidcClientDataWrapper{
			Nonce:   nonce,
			Payload: cipherText,
		}

		wrappedBytes, err := json.Marshal(dataWrapper)
		require.NoError(t, err)

		_, err = decryptClientData(key, wrappedBytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error unmarshaling client data")
	})
}

func Test_OIDCClientStore(t *testing.T) {
	t.Parallel()

	t.Run("success - save then load oidc client data", func(t *testing.T) {
		t.Parallel()

		conf := config(t)

		op, err := New(conf)
		require.NoError(t, err)

		data := oidcClientData{
			ID:     "abcd",
			Secret: "this is a secret value",
			Expiry: 1000,
		}

		require.NoError(t, op.saveOIDCClientData("provider.url", &data))

		out, err := op.loadOIDCClientData("provider.url")
		require.NoError(t, err)

		require.Equal(t, data.ID, out.ID)
		require.Equal(t, data.Secret, out.Secret)
		require.Equal(t, data.Expiry, out.Expiry)
	})

	t.Run("save error - error encrypting client data", func(t *testing.T) {
		t.Parallel()

		conf := config(t)

		op, err := New(conf)
		require.NoError(t, err)

		op.oidcClientStoreKey = make([]byte, 5) // bad key size

		data := oidcClientData{
			ID:     "abcd",
			Secret: "this is a secret value",
			Expiry: 1000,
		}

		err = op.saveOIDCClientData("provider.url", &data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error encrypting client data")
	})

	t.Run("save error - error storing to oidc client data store", func(t *testing.T) {
		t.Parallel()

		conf := config(t)

		op, err := New(conf)
		require.NoError(t, err)

		op.oidcClientStore = &mockstorage.Store{
			ErrPut: fmt.Errorf("test err"),
		}

		data := oidcClientData{
			ID:     "abcd",
			Secret: "this is a secret value",
			Expiry: 1000,
		}

		err = op.saveOIDCClientData("provider.url", &data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error storing client data")
	})

	t.Run("load error - error loading from oidc client data store", func(t *testing.T) {
		t.Parallel()

		conf := config(t)

		op, err := New(conf)
		require.NoError(t, err)

		op.oidcClientStore = &mockstorage.Store{
			ErrGet: fmt.Errorf("test err"),
		}

		_, err = op.loadOIDCClientData("provider.url")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error loading client data")
	})

	t.Run("load error - error decrypting client data", func(t *testing.T) {
		t.Parallel()

		conf := config(t)

		op, err := New(conf)
		require.NoError(t, err)

		// save some garbage data
		require.NoError(t, op.oidcClientStore.Put("provider.url", []byte("abcd blah blah")))

		_, err = op.loadOIDCClientData("provider.url")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error decrypting client data")
	})
}

func TestRegisterOAuthClient(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		conf := config(t)

		op, err := New(conf)
		require.NoError(t, err)

		mockOIDCServer := createMockOIDCServer("", "", "", "", fmt.Sprintf(
			`{"client_id":"example_client","client_secret":"abcdefg","client_secret_expires_at":%d}`,
			time.Now().Add(time.Hour*300).Unix()))

		defer mockOIDCServer.Close()

		_, err = op.registerOAuthClient(mockOIDCServer.URL+"/register", nil)
		require.NoError(t, err)
	})

	t.Run("failure - server error", func(t *testing.T) {
		t.Parallel()

		conf := config(t)

		op, err := New(conf)
		require.NoError(t, err)

		badServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
		}))

		defer badServer.Close()

		_, err = op.registerOAuthClient(badServer.URL+"/register", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error response")
	})
}

func TestCreateProfile(t *testing.T) {
	t.Parallel()

	op, err := New(config(t))
	require.NoError(t, err)

	mockOIDC := mockOIDCClient{}

	op.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
		return &mockOIDC, nil
	}

	op.getOIDCClientFunc = func(string, string) (oidcClient, error) {
		return &mockOIDC, nil
	}

	endpoint := profileEndpoint
	handler := getHandler(t, op, endpoint)

	t.Run("create profile - success", func(t *testing.T) {
		t.Parallel()

		vReq := createProfileData(uuid.New().String())
		vReq.OIDCClientParams = &issuer.OIDCClientParams{
			ClientID:     "client id",
			ClientSecret: "client secret",
			SecretExpiry: 0,
		}

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
		require.Equal(t, vReq.IssuerID, profileRes.IssuerID)
		require.Equal(t, vReq.SupportsWACI, profileRes.SupportsWACI)
	})

	t.Run("create profile - success with default oidc", func(t *testing.T) {
		t.Parallel()

		op2, err := New(config(t))
		require.NoError(t, err)

		mockOIDCServer := createMockOIDCServer("", "", "", "", fmt.Sprintf(
			`{"client_id":"example_client","client_secret":"abcdefg","client_secret_expires_at":%d}`,
			time.Now().Add(time.Hour*300).Unix()))

		defer mockOIDCServer.Close()

		handler2 := getHandler(t, op2, endpoint)

		vReq := createProfileData(uuid.New().String())
		vReq.OIDCProviderURL = mockOIDCServer.URL

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler2.Handle(), http.MethodPost, endpoint, vReqBytes)

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
		t.Parallel()

		op2, err := New(config(t))
		require.NoError(t, err)

		op2.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
			return &mockOIDC, nil
		}

		op2.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDC, nil
		}

		op2.governanceProvider = &mockgovernance.MockProvider{
			IssueCredentialFunc: func(didID, profileID string) ([]byte, error) {
				return nil, fmt.Errorf("failed to issue governance vc")
			},
		}

		h := getHandler(t, op2, endpoint)

		vReq := createProfileData(uuid.New().String())

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, h.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to issue governance vc")
	})

	t.Run("create profile - invalid request", func(t *testing.T) {
		t.Parallel()

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, []byte("invalid-json"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request")
	})

	t.Run("create profile - did creation failure", func(t *testing.T) {
		t.Parallel()

		ops, err := New(config(t))
		require.NoError(t, err)

		ops.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
			return &mockOIDC, nil
		}

		op.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDC, nil
		}

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
		t.Parallel()

		vReq := &ProfileDataRequest{}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "profile id mandatory")
	})

	t.Run("create profile - oidc error", func(t *testing.T) {
		t.Parallel()

		ops, err := New(config(t))
		require.NoError(t, err)

		vReq := createProfileData(uuid.New().String())

		vReq.OIDCProviderURL = "abcd"

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, getHandler(t, ops, endpoint).Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusInternalServerError, rr.Code)

		resErr := struct {
			ErrMessage string `json:"errMessage"`
		}{}
		err = json.Unmarshal(rr.Body.Bytes(), &resErr)
		require.NoError(t, err)

		require.Contains(t, resErr.ErrMessage, "create oidc client")
	})
}

func TestGetProfile(t *testing.T) {
	t.Parallel()

	op, err := New(config(t))
	require.NoError(t, err)

	mockOIDC := mockOIDCClient{}

	op.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
		return &mockOIDC, nil
	}

	op.getOIDCClientFunc = func(string, string) (oidcClient, error) {
		return &mockOIDC, nil
	}

	endpoint := getProfileEndpoint
	handler := getHandler(t, op, endpoint)

	urlVars := make(map[string]string)

	t.Run("get profile - success", func(t *testing.T) {
		t.Parallel()

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
		require.Equal(t, vReq.SupportsWACI, profileRes.SupportsWACI)
	})

	t.Run("get profile - no data found", func(t *testing.T) {
		t.Parallel()

		urlVars[idPathParam] = "invalid-name"

		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), storage.ErrDataNotFound.Error())
	})
}

func TestConnectWallet(t *testing.T) { // nolint:tparallel // data race
	t.Parallel()

	uiEndpoint := "/ui"
	profileID := "test-1"
	state := uuid.New().String()
	endpoint := walletConnectEndpoint
	urlVars := make(map[string]string)

	tknResp := &IssuerTokenResp{
		Token:  uuid.New().String(),
		UserID: "testuser",
	}

	tknRespBytes, err := json.Marshal(tknResp)
	require.NoError(t, err)

	mockOIDC := mockOIDCClient{}

	t.Run("test connect wallet - success", func(t *testing.T) { // nolint:paralleltest // data race
		c, err := New(config(t))
		require.NoError(t, err)

		c.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDC, nil
		}

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

	t.Run("test connect wallet - success and redirect to oidc auth", func(t *testing.T) { // nolint:paralleltest,lll // data race
		c, err := New(config(t))
		require.NoError(t, err)

		c.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.uiEndpoint = uiEndpoint
		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader(tknRespBytes)),
			},
		}

		data := createProfileData(profileID)
		data.OIDCProviderURL = "mock-issuer.website"

		err = c.profileStore.SaveProfile(data)
		require.NoError(t, err)

		walletConnectHandler := getHandler(t, c, endpoint)

		urlVars[idPathParam] = profileID

		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint+"?"+stateQueryParam+"="+state, nil, urlVars)

		require.Equal(t, http.StatusFound, rr.Code)
		require.Contains(t, rr.Header().Get("Location"), "/oidc/request")
	})

	t.Run("test connect wallet - profile doesn't exists", func(t *testing.T) { // nolint:paralleltest // data race
		c, err := New(config(t))
		require.NoError(t, err)

		c.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader(tknRespBytes)),
			},
		}

		walletConnectHandler := getHandler(t, c, endpoint)

		urlVars[idPathParam] = profileID

		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), storage.ErrDataNotFound.Error())
	})

	t.Run("test connect wallet - no state in the url", func(t *testing.T) { // nolint:paralleltest // data race
		c, err := New(config(t))
		require.NoError(t, err)

		c.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDC, nil
		}

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

	t.Run("test connect wallet - failed to create invitation", func(t *testing.T) { // nolint:paralleltest // data race
		config := config(t)
		config.AriesCtx = &mockprovider.MockProvider{
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
				KMSValue:             &mockkms.KeyManager{CrAndExportPubKeyErr: errors.New("key generation error")},
				ServiceEndpointValue: "endpoint",
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		c.createOIDCClientFunc = func(profileData *issuer.ProfileData) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDC, nil
		}

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

	t.Run("test connect wallet - txn data store error", func(t *testing.T) { // nolint:paralleltest // data race
		c, err := New(config(t))
		require.NoError(t, err)

		c.createOIDCClientFunc = func(profileData *issuer.ProfileData) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDC, nil
		}

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

		c.txnStore = &mockstorage.Store{
			ErrPut: errors.New("error inserting data"),
		}

		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint+"?"+stateQueryParam+"="+state, nil, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create txn")
	})

	t.Run("test connect wallet - retrieve token errors", func(t *testing.T) { // nolint:paralleltest // data race
		c, err := New(config(t))
		require.NoError(t, err)

		c.createOIDCClientFunc = func(profileData *issuer.ProfileData) (oidcClient, error) {
			return &mockOIDC, nil
		}

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
		require.Contains(t, rr.Body.String(), "received empty token info from the issuer")

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

func TestCredScopeHandler(t *testing.T) { // nolint:tparallel // data race
	t.Parallel()

	profileID := "test-1"
	credScope := "TestCredScope"
	endpoint := walletConnectEndpoint
	urlVars := make(map[string]string)

	tknResp := &IssuerTokenResp{
		Token:  uuid.New().String(),
		UserID: "testuser",
	}

	tknRespBytes, err := json.Marshal(tknResp)
	require.NoError(t, err)

	mockOIDC := mockOIDCClient{}

	t.Run("success - test connect wallet using cred scope", func(t *testing.T) { // nolint:paralleltest // data race
		c, err := New(config(t))
		require.NoError(t, err)

		c.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader(tknRespBytes)),
			},
		}

		data := createProfileData(profileID)
		data.CredentialScopes = []string{credScope}

		err = c.profileStore.SaveProfile(data)
		require.NoError(t, err)

		walletConnectHandler := getHandler(t, c, endpoint)

		urlVars[idPathParam] = profileID

		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint+"?"+credScopeQueryParam+"="+credScope, nil, urlVars)

		require.Equal(t, http.StatusFound, rr.Code)
		require.Contains(t, rr.Header().Get("Location"), oidcAuthRequestEndpoint)
	})

	t.Run("failure - cred scope not configured in issuer profile", func(t *testing.T) { // nolint:paralleltest,lll // data race
		c, err := New(config(t))
		require.NoError(t, err)

		c.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDC, nil
		}

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

		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint+"?"+credScopeQueryParam+"="+credScope, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("failure - could not create transaction record", func(t *testing.T) { // nolint:paralleltest // data race
		c, err := New(config(t))
		require.NoError(t, err)

		c.txnStore = &mockstorage.Store{ErrPut: fmt.Errorf("store error")}

		c.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDC, nil
		}

		c.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader(tknRespBytes)),
			},
		}

		data := createProfileData(profileID)
		data.CredentialScopes = []string{credScope}

		err = c.profileStore.SaveProfile(data)
		require.NoError(t, err)

		walletConnectHandler := getHandler(t, c, endpoint)

		urlVars[idPathParam] = profileID

		rr := serveHTTPMux(t, walletConnectHandler, walletConnectEndpoint+"?"+credScopeQueryParam+"="+credScope, nil, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestValidateWalletResponse(t *testing.T) {
	t.Parallel()

	c, err := New(config(t))
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

	t.Run("test validate response - success", func(t *testing.T) { // nolint:paralleltest // data race
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
		t.Parallel()

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, validateConnectResponseEndpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get txnID from the url")
	})

	t.Run("test validate response - invalid req", func(t *testing.T) {
		t.Parallel()

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"=invalid-txn-id", []byte("invalid-request"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request")
	})

	t.Run("test validate response - invalid txn id", func(t *testing.T) {
		t.Parallel()

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"=invalid-txn-id", vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "txn data not found")
	})

	t.Run("test validate response - invalid txn data", func(t *testing.T) {
		t.Parallel()

		putErr := c.txnStore.Put(txnID, []byte("invalid json"))
		require.NoError(t, putErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+uuid.New().String(), vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "txn data not found")
	})

	t.Run("test validate response - invalid vp", func(t *testing.T) {
		t.Parallel()

		txnID, err = c.createTxn(createProfileData("profile1"), uuid.New().String(), token)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost,
			validateConnectResponseEndpoint+"?"+txnIDQueryParam+"="+txnID, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to validate presentation")
	})

	t.Run("test validate response - profile not found", func(t *testing.T) { // nolint:paralleltest // data race
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

	t.Run("test validate response - validate connection errors", func(t *testing.T) { // nolint:paralleltest // data race
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
		t.Parallel()

		ops, err := New(config(t))
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

		ops.tokenStore = &mockstorage.Store{ErrPut: errors.New("error put")}

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

func TestRequestOIDCAuthHandler(t *testing.T) {
	t.Parallel()

	uiEndpoint := "/mock-ui-endpoint"
	profileID := "test-profile-1"
	userID := "user_123"
	oidcProvider := "https://mock-issuer.local"

	mockToken := oauth2.Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}

	mockOIDC := mockOIDCClient{
		CreateOIDCRequestValue: oidcProvider,
		CheckRefreshTok:        &mockToken,
	}

	defaultConf := config(t)
	c, err := New(defaultConf)
	require.NoError(t, err)

	c.uiEndpoint = uiEndpoint

	c.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
		return &mockOIDC, nil
	}

	c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
		return &mockOIDC, nil
	}

	credScope := "TestCredScope"

	data := createProfileData(profileID)
	data.OIDCProviderURL = oidcProvider
	data.CredentialScopes = []string{credScope}

	err = c.profileStore.SaveProfile(data)
	require.NoError(t, err)

	txnID, err := c.createTxn(data, "state", "token")
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		authHandler := getHandler(t, c, oidcAuthRequestEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcAuthRequestEndpoint,
			txnIDQueryParam, txnID, userIDQueryParam, userID)

		rr := serveHTTPMux(t, authHandler, reqPath, nil, nil)

		require.Equal(t, http.StatusFound, rr.Code)
		require.Contains(t, rr.Header().Get("Location"), data.OIDCProviderURL)
	})

	t.Run("success - using credential scope", func(t *testing.T) {
		t.Parallel()

		txnID2, err := c.createTxnWithCredScope(data, credScope)
		require.NoError(t, err)

		authHandler := getHandler(t, c, oidcAuthRequestEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcAuthRequestEndpoint,
			txnIDQueryParam, txnID2, userIDQueryParam, userID)

		rr := serveHTTPMux(t, authHandler, reqPath, nil, nil)

		require.Equal(t, http.StatusFound, rr.Code)
		require.Contains(t, rr.Header().Get("Location"), data.OIDCProviderURL)
	})

	t.Run("success: missing optional userID query param", func(t *testing.T) {
		t.Parallel()

		authHandler := getHandler(t, c, oidcAuthRequestEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s", oidcAuthRequestEndpoint, txnIDQueryParam, txnID)

		rr := serveHTTPMux(t, authHandler, reqPath, nil, nil)

		require.Equal(t, http.StatusFound, rr.Code)
		require.Contains(t, rr.Header().Get("Location"), data.OIDCProviderURL)
	})

	t.Run("failure: missing txnID query param", func(t *testing.T) {
		t.Parallel()

		authHandler := getHandler(t, c, oidcAuthRequestEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s", oidcAuthRequestEndpoint, userIDQueryParam, userID)

		rr := serveHTTPMux(t, authHandler, reqPath, nil, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("failure: missing txn record", func(t *testing.T) {
		t.Parallel()

		authHandler := getHandler(t, c, oidcAuthRequestEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcAuthRequestEndpoint,
			txnIDQueryParam, "bad-txn-id", userIDQueryParam, userID)

		rr := serveHTTPMux(t, authHandler, reqPath, nil, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("failure: missing profile record", func(t *testing.T) {
		t.Parallel()

		authHandler := getHandler(t, c, oidcAuthRequestEndpoint)

		data2 := createProfileData(profileID + "_version_2")

		txnID2, err := c.createTxn(data2, "state2", "token2")
		require.NoError(t, err)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcAuthRequestEndpoint,
			txnIDQueryParam, txnID2, userIDQueryParam, userID)

		rr := serveHTTPMux(t, authHandler, reqPath, nil, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("success - valid token available", func(t *testing.T) {
		t.Parallel()

		authHandler := getHandler(t, c, oidcAuthRequestEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcAuthRequestEndpoint,
			txnIDQueryParam, txnID, userIDQueryParam, userID)

		c.userTokens[txnID] = &mockToken

		rr := serveHTTPMux(t, authHandler, reqPath, nil, nil)

		require.Equal(t, http.StatusFound, rr.Code)
		require.Contains(t, rr.Header().Get("Location"), uiEndpoint)

		delete(c.userTokens, txnID)
	})

	t.Run("failure - error getting oidc client", func(t *testing.T) {
		t.Parallel()

		prevClientFunc := c.getOIDCClientFunc

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return nil, fmt.Errorf("test error")
		}

		authHandler := getHandler(t, c, oidcAuthRequestEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcAuthRequestEndpoint,
			txnIDQueryParam, txnID, userIDQueryParam, userID)

		rr := serveHTTPMux(t, authHandler, reqPath, nil, nil)

		require.Equal(t, http.StatusInternalServerError, rr.Code)

		c.getOIDCClientFunc = prevClientFunc
	})
}

func TestOIDCCallback(t *testing.T) { // nolint:tparallel // data race
	t.Parallel()

	uiEndpoint := "/mock-ui-endpoint"
	profileID := "test-profile"
	userID := "user_123"
	oidcProvider := "https://oidc-provider.xyz"

	defaultConf := config(t)
	c, err := New(defaultConf)
	require.NoError(t, err)

	c.uiEndpoint = uiEndpoint

	mockToken := oauth2.Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}

	mockOIDC := mockOIDCClient{
		CreateOIDCRequestValue: oidcProvider,
		CheckRefreshTok:        &mockToken,
		HandleOIDCCallbackTok:  &mockToken,
	}

	c.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
		return &mockOIDC, nil
	}

	c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
		return &mockOIDC, nil
	}

	data := createProfileData(profileID)
	data.OIDCProviderURL = oidcProvider

	err = c.profileStore.SaveProfile(data)
	require.NoError(t, err)

	txnID, err := c.createTxn(data, "state", "token")
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) { // nolint:paralleltest // data race
		cbHandler := getHandler(t, c, oidcCallbackEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcCallbackEndpoint,
			"state", "state-value", "code", "auth-code-value")

		rr := httptest.NewRecorder()

		req, err := http.NewRequest(http.MethodGet, reqPath, nil)
		require.NoError(t, err)

		req.AddCookie(&http.Cookie{Name: "oidcState", Value: "state-value"})
		req.AddCookie(&http.Cookie{Name: "txnID", Value: txnID})
		req.AddCookie(&http.Cookie{Name: "userID", Value: userID})

		cbHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusFound, rr.Code)
		require.Contains(t, rr.Header().Get("Location"), uiEndpoint)
	})

	t.Run("failure - missing state url param", func(t *testing.T) { // nolint:paralleltest // data race
		cbHandler := getHandler(t, c, oidcCallbackEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s", oidcCallbackEndpoint, "code", "auth-code-value")

		rr := httptest.NewRecorder()

		req, err := http.NewRequest(http.MethodGet, reqPath, nil)
		require.NoError(t, err)

		req.AddCookie(&http.Cookie{Name: "oidcState", Value: "state-value"})
		req.AddCookie(&http.Cookie{Name: "txnID", Value: txnID})
		req.AddCookie(&http.Cookie{Name: "userID", Value: userID})

		cbHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("failure - missing cookies", func(t *testing.T) { // nolint:paralleltest // data race
		cbHandler := getHandler(t, c, oidcCallbackEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcCallbackEndpoint,
			"state", "state-value", "code", "auth-code-value")

		cookies := []http.Cookie{
			{Name: "oidcState", Value: "state-value"},
			{Name: "txnID", Value: txnID},
			{Name: "userID", Value: userID},
		}

		numTests := len(cookies)

		for i := 0; i < numTests; i++ {
			rr := httptest.NewRecorder()

			req, err := http.NewRequest(http.MethodGet, reqPath, nil)
			require.NoError(t, err)

			for j := 0; j < numTests; j++ {
				if i == j {
					continue
				}

				req.AddCookie(&cookies[j])
			}

			cbHandler.Handle().ServeHTTP(rr, req)
			require.Equal(t, http.StatusInternalServerError, rr.Code)
		}
	})

	t.Run("failure - getting transaction", func(t *testing.T) { // nolint:paralleltest // data race
		prevStore := c.txnStore

		c.txnStore = &mockstorage.Store{ErrGet: fmt.Errorf("err get")}

		cbHandler := getHandler(t, c, oidcCallbackEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcCallbackEndpoint,
			"state", "state-value", "code", "auth-code-value")

		rr := httptest.NewRecorder()

		req, err := http.NewRequest(http.MethodGet, reqPath, nil)
		require.NoError(t, err)

		req.AddCookie(&http.Cookie{Name: "oidcState", Value: "state-value"})
		req.AddCookie(&http.Cookie{Name: "txnID", Value: txnID})
		req.AddCookie(&http.Cookie{Name: "userID", Value: userID})

		cbHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)

		c.txnStore = prevStore
	})

	t.Run("failure - initializing oidc client", func(t *testing.T) { // nolint:paralleltest // data race
		prevClientFunc := c.getOIDCClientFunc

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return nil, fmt.Errorf("client create error")
		}

		cbHandler := getHandler(t, c, oidcCallbackEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcCallbackEndpoint,
			"state", "state-value", "code", "auth-code-value")

		rr := httptest.NewRecorder()

		req, err := http.NewRequest(http.MethodGet, reqPath, nil)
		require.NoError(t, err)

		req.AddCookie(&http.Cookie{Name: "oidcState", Value: "state-value"})
		req.AddCookie(&http.Cookie{Name: "txnID", Value: txnID})
		req.AddCookie(&http.Cookie{Name: "userID", Value: userID})

		cbHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)

		c.getOIDCClientFunc = prevClientFunc
	})

	t.Run("failure - handling oauth callback", func(t *testing.T) { // nolint:paralleltest // data race
		prevClientFunc := c.getOIDCClientFunc

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDCClient{HandleOIDCCallbackErr: fmt.Errorf("handle error")}, nil
		}

		cbHandler := getHandler(t, c, oidcCallbackEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcCallbackEndpoint,
			"state", "state-value", "code", "auth-code-value")

		rr := httptest.NewRecorder()

		req, err := http.NewRequest(http.MethodGet, reqPath, nil)
		require.NoError(t, err)

		req.AddCookie(&http.Cookie{Name: "oidcState", Value: "state-value"})
		req.AddCookie(&http.Cookie{Name: "txnID", Value: txnID})
		req.AddCookie(&http.Cookie{Name: "userID", Value: userID})

		cbHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)

		c.getOIDCClientFunc = prevClientFunc
	})

	t.Run("failure - storing refresh token", func(t *testing.T) { // nolint:paralleltest // data race
		prevStore := c.refreshTokenStore

		c.refreshTokenStore = &mockstorage.Store{ErrPut: fmt.Errorf("err put")}

		cbHandler := getHandler(t, c, oidcCallbackEndpoint)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcCallbackEndpoint,
			"state", "state-value", "code", "auth-code-value")

		rr := httptest.NewRecorder()

		req, err := http.NewRequest(http.MethodGet, reqPath, nil)
		require.NoError(t, err)

		req.AddCookie(&http.Cookie{Name: "oidcState", Value: "state-value"})
		req.AddCookie(&http.Cookie{Name: "txnID", Value: txnID})
		req.AddCookie(&http.Cookie{Name: "userID", Value: userID})

		cbHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)

		c.refreshTokenStore = prevStore
	})

	t.Run("failure - getting issuer profile", func(t *testing.T) { // nolint:paralleltest // data race
		cbHandler := getHandler(t, c, oidcCallbackEndpoint)

		txnID2, err := c.createTxn(
			&issuer.ProfileData{
				ID:  "test-issuer-profile",
				URL: "invalid.url",
			}, "state", "token")
		require.NoError(t, err)

		reqPath := fmt.Sprintf("%s?%s=%s&%s=%s", oidcCallbackEndpoint,
			"state", "state-value", "code", "auth-code-value")

		rr := httptest.NewRecorder()

		req, err := http.NewRequest(http.MethodGet, reqPath, nil)
		require.NoError(t, err)

		req.AddCookie(&http.Cookie{Name: "oidcState", Value: "state-value"})
		req.AddCookie(&http.Cookie{Name: "txnID", Value: txnID2})
		req.AddCookie(&http.Cookie{Name: "userID", Value: userID})

		cbHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestGetOIDCAccessToken(t *testing.T) {
	t.Parallel()

	conf := config(t)
	c, err := New(conf)
	require.NoError(t, err)

	oidcProvider := "https://auth.issuer.local"

	mockToken := oauth2.Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}

	mockOIDC := mockOIDCClient{
		CreateOIDCRequestValue: oidcProvider,
		CheckRefreshTok:        &mockToken,
		HandleOIDCCallbackTok:  &mockToken,
	}

	c.createOIDCClientFunc = func(*issuer.ProfileData) (oidcClient, error) {
		return &mockOIDC, nil
	}

	c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
		return &mockOIDC, nil
	}

	t.Run("success - token present in cache", func(t *testing.T) {
		t.Parallel()

		txnID := "txn-id-0"
		c.userTokens[txnID] = &mockToken

		tok, err := c.getOIDCAccessToken(txnID, &issuer.ProfileData{OIDCProviderURL: oidcProvider})
		require.NoError(t, err)
		require.Equal(t, mockToken.AccessToken, tok)
	})

	t.Run("success - loading refresh token from store", func(t *testing.T) {
		t.Parallel()

		txnID := "txn-id-1"

		err := c.refreshTokenStore.Put(txnID, []byte("refresh-token"))
		require.NoError(t, err)

		tok, err := c.getOIDCAccessToken(txnID, &issuer.ProfileData{OIDCProviderURL: oidcProvider})
		require.NoError(t, err)
		require.Equal(t, mockToken.AccessToken, tok)
	})

	t.Run("failure - refresh token missing from store", func(t *testing.T) {
		t.Parallel()

		tok, err := c.getOIDCAccessToken("txn-id-2", &issuer.ProfileData{OIDCProviderURL: oidcProvider})
		require.Error(t, err)
		require.Equal(t, "", tok)
		require.ErrorIs(t, err, storage.ErrDataNotFound)
	})

	t.Run("failure - error getting oidc client", func(t *testing.T) {
		t.Parallel()

		prevClientFunc := c.getOIDCClientFunc

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return nil, fmt.Errorf("client create error")
		}

		txnID := "txn-id-3"
		c.userTokens[txnID] = &mockToken

		tok, err := c.getOIDCAccessToken(txnID, &issuer.ProfileData{OIDCProviderURL: oidcProvider})
		require.Error(t, err)
		require.Equal(t, "", tok)
		require.Contains(t, err.Error(), "client create error")

		c.getOIDCClientFunc = prevClientFunc
	})

	t.Run("failure - error refreshing token", func(t *testing.T) {
		t.Parallel()

		prevClientFunc := c.getOIDCClientFunc

		c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
			return &mockOIDCClient{CheckRefreshErr: fmt.Errorf("refresh error")}, nil
		}

		txnID := "txn-id-4"
		c.userTokens[txnID] = &mockToken

		tok, err := c.getOIDCAccessToken(txnID, &issuer.ProfileData{OIDCProviderURL: oidcProvider})
		require.Error(t, err)
		require.Equal(t, "", tok)
		require.Contains(t, err.Error(), "refresh error")

		c.getOIDCClientFunc = prevClientFunc
	})

	t.Run("failure - error storing refresh token", func(t *testing.T) {
		t.Parallel()

		prevStore := c.refreshTokenStore

		txnID := "txn-id-5"

		c.userTokens[txnID] = &oauth2.Token{
			AccessToken:  "old-access-token",
			RefreshToken: "old-refresh-token",
		}

		c.refreshTokenStore = &mockstorage.Store{ErrPut: fmt.Errorf("store error")}

		tok, err := c.getOIDCAccessToken(txnID, &issuer.ProfileData{OIDCProviderURL: oidcProvider})
		require.Error(t, err)
		require.Equal(t, "", tok)
		require.Contains(t, err.Error(), "store error")

		c.refreshTokenStore = prevStore
	})
}

func TestCredentialInteractionRequest(t *testing.T) {
	t.Parallel()

	t.Run("test fetch chapi request - success", func(t *testing.T) {
		t.Parallel()

		c, e := New(config(t))
		require.NoError(t, e)

		c.governanceProvider = &mockgovernance.MockProvider{GetCredentialFunc: func(profileID string) ([]byte, error) {
			return []byte(`{"key":"value"}`), nil
		}}

		t.Run("without assurance support", func(t *testing.T) {
			t.Parallel()

			profile := createProfileData("profile1")

			err := c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			txnID, txnErr := c.createTxn(profile, uuid.New().String(), uuid.New().String())
			require.NoError(t, txnErr)

			getCHAPIRequestHandler := getHandler(t, c, getCredentialInteractionRequestEndpoint)

			rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
				getCredentialInteractionRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)

			require.Equal(t, http.StatusOK, rr.Code)

			chapiReq := &CredentialHandlerRequest{}
			err = json.Unmarshal(rr.Body.Bytes(), &chapiReq)
			require.NoError(t, err)
			require.Equal(t, DIDConnectCHAPIQueryType, chapiReq.Query.Type)
			require.Equal(t, "https://didcomm.org/out-of-band/1.0/invitation", chapiReq.DIDCommInvitation.Type)
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

			err := c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			txnID, err := c.createTxn(profile, uuid.New().String(), uuid.New().String())
			require.NoError(t, err)

			getCHAPIRequestHandler := getHandler(t, c, getCredentialInteractionRequestEndpoint)

			rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
				getCredentialInteractionRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)

			require.Equal(t, http.StatusOK, rr.Code)

			chapiReq := &CredentialHandlerRequest{}
			err = json.Unmarshal(rr.Body.Bytes(), &chapiReq)
			require.NoError(t, err)
			require.Equal(t, DIDConnectCHAPIQueryType, chapiReq.Query.Type)
			require.Equal(t, "https://didcomm.org/out-of-band/1.0/invitation", chapiReq.DIDCommInvitation.Type)
			require.Equal(t, `{"key":"value"}`, string(chapiReq.Credentials[2]))
			require.Equal(t, 3, len(chapiReq.Credentials))
		})

		t.Run("with assurance credential using oidc", func(t *testing.T) {
			t.Parallel()

			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}

			profile := createProfileData("profile3")
			profile.SupportsAssuranceCredential = true
			profile.CredentialSigningKey = mockdiddoc.GetMockDIDDoc("did:example:def567").VerificationMethod[0].ID

			profile.OIDCProviderURL = mockOIDCProvider

			mockToken := oauth2.Token{RefreshToken: "refresh-token", AccessToken: "access-token"}

			c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
				return &mockOIDCClient{
					CheckRefreshTok: &mockToken,
				}, nil
			}

			err := c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			txnID, err := c.createTxn(profile, uuid.New().String(), uuid.New().String())
			require.NoError(t, err)

			c.userTokens[txnID] = &mockToken

			getCHAPIRequestHandler := getHandler(t, c, getCredentialInteractionRequestEndpoint)

			rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
				getCredentialInteractionRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)

			require.Equal(t, http.StatusOK, rr.Code)

			chapiReq := &CredentialHandlerRequest{}
			err = json.Unmarshal(rr.Body.Bytes(), &chapiReq)
			require.NoError(t, err)
			require.Equal(t, DIDConnectCHAPIQueryType, chapiReq.Query.Type)
			require.Equal(t, "https://didcomm.org/out-of-band/1.0/invitation", chapiReq.DIDCommInvitation.Type)
			require.Equal(t, `{"key":"value"}`, string(chapiReq.Credentials[2]))
			require.Equal(t, 3, len(chapiReq.Credentials))
		})
	})

	t.Run("test fetch waci request - success", func(t *testing.T) {
		t.Parallel()

		c, e := New(config(t))
		require.NoError(t, e)

		c.governanceProvider = &mockgovernance.MockProvider{GetCredentialFunc: func(profileID string) ([]byte, error) {
			return []byte(`{"key":"value"}`), nil
		}}

		t.Run("without linked wallet", func(t *testing.T) {
			t.Parallel()

			profile := createProfileData("profile_waci_1")
			profile.SupportsWACI = true

			err := c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			txnID, txnErr := c.createTxn(profile, uuid.New().String(), uuid.New().String())
			require.NoError(t, txnErr)

			getCHAPIRequestHandler := getHandler(t, c, getCredentialInteractionRequestEndpoint)

			rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
				getCredentialInteractionRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)

			require.Equal(t, http.StatusOK, rr.Code)

			waciReq := &CredentialHandlerRequest{}
			err = json.Unmarshal(rr.Body.Bytes(), &waciReq)
			require.NoError(t, err)
			require.Empty(t, waciReq.Query)
			require.Empty(t, waciReq.Credentials)
			require.Equal(t, "https://didcomm.org/out-of-band/1.0/invitation", waciReq.DIDCommInvitation.Type)
			require.Empty(t, waciReq.WalletRedirect)
			require.True(t, waciReq.WACI)
		})

		t.Run("with linked wallet", func(t *testing.T) {
			t.Parallel()

			profile := createProfileData("profile_waci_2")
			profile.SupportsWACI = true
			profile.LinkedWalletURL = "https://example/com"

			err := c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			txnID, txnErr := c.createTxn(profile, uuid.New().String(), uuid.New().String())
			require.NoError(t, txnErr)

			getCHAPIRequestHandler := getHandler(t, c, getCredentialInteractionRequestEndpoint)

			rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
				getCredentialInteractionRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)

			require.Equal(t, http.StatusOK, rr.Code)

			waciReq := &CredentialHandlerRequest{}
			err = json.Unmarshal(rr.Body.Bytes(), &waciReq)
			require.NoError(t, err)
			require.Empty(t, waciReq.Query)
			require.Empty(t, waciReq.Credentials)
			require.Equal(t, "https://didcomm.org/out-of-band/1.0/invitation", waciReq.DIDCommInvitation.Type)
			require.NotEmpty(t, waciReq.WalletRedirect)
			require.True(t, waciReq.WACI)
		})
	})

	t.Run("test get governance - failed", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		c.governanceProvider = &mockgovernance.MockProvider{GetCredentialFunc: func(profileID string) ([]byte, error) {
			return nil, fmt.Errorf("failed to get vc")
		}}

		profile := createProfileData("profile1")

		err = c.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		txnID, err := c.createTxn(profile, uuid.New().String(), uuid.New().String())
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCredentialInteractionRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
			getCredentialInteractionRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "error retrieving governance vc : failed to get vc")
	})

	t.Run("test fetch invitation - no txnID in the url query", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCredentialInteractionRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet, getCredentialInteractionRequestEndpoint, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get txnID from the url")
	})

	t.Run("test fetch invitation - invalid txnID", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCredentialInteractionRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
			getCredentialInteractionRequestEndpoint+"?"+txnIDQueryParam+"=invalid-txnID", nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "txn data not found")
	})

	t.Run("test fetch invitation - profile not found", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		profile := createProfileData("profile1")

		txnID, err := c.createTxn(profile, uuid.New().String(), uuid.New().String())
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCredentialInteractionRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
			getCredentialInteractionRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "issuer not found")
	})

	t.Run("test fetch chapi request with assurance - error", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		profile := createProfileData("profile2")
		profile.SupportsAssuranceCredential = true

		err = c.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		txnID, err := c.createTxn(profile, uuid.New().String(), uuid.New().String())
		require.NoError(t, err)

		getCHAPIRequestHandler := getHandler(t, c, getCredentialInteractionRequestEndpoint)

		rr := serveHTTP(t, getCHAPIRequestHandler.Handle(), http.MethodGet,
			getCredentialInteractionRequestEndpoint+"?"+txnIDQueryParam+"="+txnID, nil)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "error creating reference credential")
	})
}

// nolint
func TestIssueCredentialHandler(t *testing.T) {
	t.Parallel()

	t.Run("test issue credential", func(t *testing.T) {
		t.Parallel()

		actionCh := make(chan service.DIDCommAction, 1)

		c, err := issueCredentialClient(getAriesCtx(t), actionCh)
		require.NoError(t, err)
		require.NotNil(t, c)

		c, err = issueCredentialClient(mockprovider.NewMockProvider(), actionCh)
		require.Error(t, err)
		require.Nil(t, c)

		c, err = issueCredentialClient(&mockprovider.MockProvider{
			Provider: &ariesmockprovider.Provider{
				ServiceMap: map[string]interface{}{
					issuecredsvc.Name: &issuecredential.MockIssueCredentialSvc{
						RegisterActionEventErr: errors.New("register error"),
					},
				},
			},
		}, actionCh)
		require.Error(t, err)
		require.Contains(t, err.Error(), "register error")
		require.Nil(t, c)
	})

	t.Run("test present proof", func(t *testing.T) {
		t.Parallel()

		actionCh := make(chan service.DIDCommAction, 1)

		c, err := presentProofClient(getAriesCtx(t), actionCh)
		require.NoError(t, err)
		require.NotNil(t, c)

		c, err = presentProofClient(mockprovider.NewMockProvider(), actionCh)
		require.Error(t, err)
		require.Nil(t, c)

		c, err = presentProofClient(&mockprovider.MockProvider{
			Provider: &ariesmockprovider.Provider{
				ServiceMap: map[string]interface{}{
					presentproofsvc.Name: &presentproof.MockPresentProofSvc{
						RegisterActionEventErr: errors.New("register error"),
					},
				},
			},
		}, actionCh)
		require.Error(t, err)
		require.Contains(t, err.Error(), "register error")
		require.Nil(t, c)
	})

	t.Run("test didcomm actions - unsupported message", func(t *testing.T) {
		t.Parallel()

		actionCh := make(chan service.DIDCommAction, 1)

		c, err := New(config(t))
		require.NoError(t, err)

		go c.didCommActionListener(actionCh)

		done := make(chan struct{})

		actionCh <- service.DIDCommAction{
			Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredentialV2{
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
		t.Parallel()

		t.Run("test request issue cred - success", func(t *testing.T) {
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config(t))
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
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredentialV2{
					Type: issuecredsvc.RequestCredentialMsgTypeV2,
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
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			config := config(t)
			config.AriesCtx = &mockprovider.MockProvider{
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
					ServiceEndpointValue: "endpoint",
					VDRegistryValue: &mockvdr.MockVDRegistry{
						CreateErr: errors.New("did create error"),
					},
					KMSValue: &mockkms.KeyManager{},
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
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config(t))
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

			c.txnStore = &mockstorage.Store{
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
			c.txnStore = &mockstorage.Store{}
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
			actionCh <- createCredentialReqMsg(t, issuecredsvc.RequestCredentialV2{
				Type: issuecredsvc.RequestCredentialMsgTypeV2,
			}, nil, func(err error) {
				require.NotNil(t, err)
				require.Contains(t, err.Error(),
					"credential request should have one attachment")
				done <- struct{}{}
			})
		})

		t.Run("test request issue cred - request validation", func(t *testing.T) {
			t.Parallel()

			cc, err := fetchAuthorizationCreReq(service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredentialV2{
					Type: issuecredsvc.RequestCredentialMsgTypeV2,
				}),
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "credential request should have one attachment")
			require.Nil(t, cc)

			cc, err = fetchAuthorizationCreReq(service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredentialV2{
					Type: issuecredsvc.RequestCredentialMsgTypeV2,
					RequestsAttach: []decorator.Attachment{
						{Data: decorator.AttachmentData{}},
					},
				}),
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "no data inside the credential request attachment")
			require.Nil(t, cc)

			cc, err = fetchAuthorizationCreReq(service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredentialV2{
					Type: issuecredsvc.RequestCredentialMsgTypeV2,
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
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredentialV2{
					Type: issuecredsvc.RequestCredentialMsgTypeV2,
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
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredentialV2{
					Type: issuecredsvc.RequestCredentialMsgTypeV2,
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
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config(t))
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
				Message: service.NewDIDCommMsgMap(issuecredsvc.RequestCredentialV2{
					Type: issuecredsvc.RequestCredentialMsgTypeV2,
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
	t.Parallel()

	t.Run("test didcomm actions - present proof request", func(t *testing.T) {
		t.Parallel()

		t.Run("test request presentation - success", func(t *testing.T) {
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config(t))
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

			profile.OIDCProviderURL = mockOIDCProvider

			mockToken := oauth2.Token{RefreshToken: "refresh-token", AccessToken: "access-token"}

			c.getOIDCClientFunc = func(string, string) (oidcClient, error) {
				return &mockOIDCClient{
					CheckRefreshTok: &mockToken,
				}, nil
			}

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

			txnID := "txn-id"

			handle := &AuthorizationCredentialHandle{
				ID:         vc.ID,
				IssuerDID:  didDocument.ID,
				SubjectDID: subjectDID,
				RPDID:      rpDIDDoc.ID,
				Token:      uuid.New().String(),
				IssuerID:   issuerID,
				OauthID:    txnID,
			}

			c.userTokens[txnID] = &mockToken

			err = c.storeAuthorizationCredHandle(handle)
			require.NoError(t, err)

			vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
			require.NoError(t, err)

			done := make(chan struct{})

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config(t))
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

			vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
			require.NoError(t, err)

			done := make(chan struct{})

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config(t))
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			done := make(chan struct{})

			// request doesn't have attachment
			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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
			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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
			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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
			actionCh <- createProofReqMsgV2(t, nil, nil, func(err error) {
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
			vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
			require.NoError(t, err)

			err = c.txnStore.Put(vc.ID, []byte("invalid data"))
			require.NoError(t, err)

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config(t))
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			done := make(chan struct{})

			vc := createAuthorizationCredential(t)
			vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
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
			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config(t))
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

			vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
			require.NoError(t, err)

			done := make(chan struct{})

			actionCh <- createProofReqMsgV2(t, presentproofsvc.RequestPresentationV2{
				Type: presentproofsvc.RequestPresentationMsgTypeV2,
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

func TestWACIIssuanceHandler(t *testing.T) {
	t.Parallel()

	testFailure := func(actionCh chan service.DIDCommAction, msg service.DIDCommMsg, errMatch string) {
		done := make(chan struct{})
		stop := make(chan error)

		actionCh <- service.DIDCommAction{
			Message: msg,
			Continue: func(args interface{}) {
				done <- struct{}{}
			},
			Properties: &actionEventEvent{},
			Stop: func(err error) {
				stop <- err
			},
		}

		select {
		case <-done:
			require.Fail(t, "this test supposed to fail")
		case e := <-stop:
			require.Error(t, e)
			require.Contains(t, e.Error(), errMatch)
		case <-time.After(65 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	}

	t.Run("test WACI Credential interaction - propose credential", func(t *testing.T) {
		t.Parallel()

		t.Run("test propose credential success", func(t *testing.T) {
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config(t))
			require.NoError(t, err)

			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}

			connID := uuid.New().String()
			c.connectionLookup = &mockconn.MockConnectionsLookup{
				ConnIDByDIDs: connID,
			}

			c.cmOutputDescriptor = map[string][]*cm.OutputDescriptor{
				mockCredScope: {
					&cm.OutputDescriptor{
						ID:     uuid.New().String(),
						Schema: "https://www.w3.org/2018/credentials/examples/v1",
					},
				},
			}

			invitationID := uuid.New().String()
			issuerID := uuid.New().String()

			profile := createProfileData(issuerID)
			profile.SupportsWACI = true

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			usrInvitationMapping := &UserInvitationMapping{
				InvitationID: invitationID,
				IssuerID:     issuerID,
				TxID:         uuid.New().String(),
				TxToken:      uuid.New().String(),
			}

			err = c.storeUserInvitationMapping(usrInvitationMapping)
			require.NoError(t, err)

			txDataSample := &txnData{
				IssuerID:  profile.ID,
				CredScope: mockCredScope,
			}

			tdByte, err := json.Marshal(txDataSample)
			require.NoError(t, err)

			err = c.txnStore.Put(usrInvitationMapping.TxID, tdByte)
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			done := make(chan struct{})

			actionCh <- service.DIDCommAction{
				Message: service.NewDIDCommMsgMap(issuecredsvc.ProposeCredentialV2{
					Type:         issuecredsvc.ProposeCredentialMsgTypeV2,
					InvitationID: invitationID,
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

		t.Run("test propose credential failures", func(t *testing.T) {
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config(t))
			require.NoError(t, err)

			invitationID := uuid.New().String()
			issuerID := uuid.New().String()
			c.cmOutputDescriptor = map[string][]*cm.OutputDescriptor{
				mockCredScope: {
					&cm.OutputDescriptor{
						ID:     uuid.New().String(),
						Schema: "https://www.w3.org/2018/credentials/examples/v1",
					},
				},
			}
			profile := createProfileData(issuerID)
			profile.SupportsWACI = true

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			usrInvitationMapping := &UserInvitationMapping{
				InvitationID: invitationID,
				IssuerID:     issuerID,
				TxID:         uuid.New().String(),
				TxToken:      uuid.New().String(),
			}

			err = c.storeUserInvitationMapping(usrInvitationMapping)
			require.NoError(t, err)

			go c.didCommActionListener(actionCh)

			testFailure(actionCh, service.NewDIDCommMsgMap(issuecredsvc.ProposeCredentialV2{
				Type:         issuecredsvc.ProposeCredentialMsgTypeV2,
				InvitationID: invitationID,
			}), "failed to fetch txn data")

			// validate manifest data error
			txDataSample := &txnData{
				IssuerID: profile.ID,
			}
			// credential data error
			txDataSample.CredScope = mockCredScope
			tdCredByte, err := json.Marshal(txDataSample)
			require.NoError(t, err)

			err = c.txnStore.Put(usrInvitationMapping.TxID, tdCredByte)
			require.NoError(t, err)
			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       ioutil.NopCloser(bytes.NewBufferString("{}")),
				},
			}

			testFailure(actionCh, service.NewDIDCommMsgMap(issuecredsvc.ProposeCredentialV2{
				Type:         issuecredsvc.ProposeCredentialMsgTypeV2,
				InvitationID: invitationID,
			}), "failed to fetch credential data")

			// get connection ID from event error
			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}

			testFailure(actionCh, service.NewDIDCommMsgMap(issuecredsvc.ProposeCredentialV2{
				Type:         issuecredsvc.ProposeCredentialMsgTypeV2,
				InvitationID: invitationID,
			}), "failed to get connection ID from event")

			// test missing invitation ID
			testFailure(actionCh, service.NewDIDCommMsgMap(issuecredsvc.ProposeCredentialV2{
				Type: issuecredsvc.ProposeCredentialMsgTypeV2,
			}), "invalid invitation ID")

			// test user invitation mapping not found
			testFailure(actionCh, service.NewDIDCommMsgMap(issuecredsvc.ProposeCredentialV2{
				Type:         issuecredsvc.ProposeCredentialMsgTypeV2,
				InvitationID: "invalid",
			}), "failed to get user invitation mapping")

			// test incorrect issuerID
			newInvitationID := uuid.New().String()
			issuerID = uuid.New().String()
			err = c.storeUserInvitationMapping(&UserInvitationMapping{
				InvitationID: newInvitationID,
				IssuerID:     issuerID,
				TxToken:      uuid.New().String(),
			})
			require.NoError(t, err)

			testFailure(actionCh, service.NewDIDCommMsgMap(issuecredsvc.ProposeCredentialV2{
				Type:         issuecredsvc.ProposeCredentialMsgTypeV2,
				InvitationID: newInvitationID,
			}), "failed to fetch issuer profile")

			// no WACI support
			profile = createProfileData(issuerID)

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			testFailure(actionCh, service.NewDIDCommMsgMap(issuecredsvc.ProposeCredentialV2{
				Type:         issuecredsvc.ProposeCredentialMsgTypeV2,
				InvitationID: newInvitationID,
			}), "unsupported protocol")

			// OIDC auth token error
			newInvitationID = uuid.New().String()
			issuerID = uuid.New().String()
			err = c.storeUserInvitationMapping(&UserInvitationMapping{
				InvitationID: newInvitationID,
				IssuerID:     issuerID,
				TxToken:      uuid.New().String(),
			})
			require.NoError(t, err)

			profile = createProfileData(issuerID)
			profile.SupportsWACI = true
			profile.OIDCProviderURL = mockOIDCProvider

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			testFailure(actionCh, service.NewDIDCommMsgMap(issuecredsvc.ProposeCredentialV2{
				Type:         issuecredsvc.ProposeCredentialMsgTypeV2,
				InvitationID: newInvitationID,
			}), "failed to get OIDC access token for WACI transaction")

			newInvitationID = uuid.New().String()
			issuerID = uuid.New().String()
			usrInvitationMapping = &UserInvitationMapping{
				InvitationID: newInvitationID,
				IssuerID:     issuerID,
				TxID:         usrInvitationMapping.TxID,
				TxToken:      uuid.New().String(),
			}
			err = c.storeUserInvitationMapping(usrInvitationMapping)
			require.NoError(t, err)

			profile = createProfileData(issuerID)
			profile.SupportsWACI = true

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			connID := uuid.New().String()
			c.connectionLookup = &mockconn.MockConnectionsLookup{
				ConnIDByDIDs: connID,
			}

			c.tokenStore = &mockStoreWrapper{
				Store:  c.tokenStore,
				errPut: errors.New("error inserting data"),
			}

			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}

			testFailure(actionCh, service.NewDIDCommMsgMap(issuecredsvc.ProposeCredentialV2{
				Type:         issuecredsvc.ProposeCredentialMsgTypeV2,
				InvitationID: newInvitationID,
			}), "failed to save user connection mapping")

			// txnStore put error
			c.txnStore = &mockStoreWrapper{
				Store:  c.txnStore,
				errPut: errors.New("error inserting data"),
			}

			c.httpClient = &mockHTTPClient{
				respValue: &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
				},
			}

			testFailure(actionCh, service.NewDIDCommMsgMap(issuecredsvc.ProposeCredentialV2{
				Type:         issuecredsvc.ProposeCredentialMsgTypeV2,
				InvitationID: newInvitationID,
			}), "failed to persist credential fulfillment")
		})
	})

	t.Run("test WACI Credential interaction - request credential", func(t *testing.T) {
		t.Parallel()

		t.Run("test request credential success", func(t *testing.T) {
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config(t))
			require.NoError(t, err)

			connectionID := uuid.New().String()
			c.connectionLookup = &mockconn.MockConnectionsLookup{
				ConnIDByDIDs: connectionID,
			}

			issuerID := uuid.New().String()

			profile := createProfileData(issuerID)
			profile.SupportsWACI = true
			profile.PresentationSigningKey = mockdiddoc.GetMockDIDDoc("did:example:def567").VerificationMethod[0].ID

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			err = c.storeUserConnectionMapping(&UserConnectionMapping{
				ConnectionID: connectionID,
				IssuerID:     issuerID,
				Token:        uuid.NewString(),
				State:        uuid.NewString(),
			})
			require.NoError(t, err)

			thID := uuid.NewString()
			fulfillment := createCredentialFulFillment(t, c, profile)
			require.NoError(t, c.saveCredentialFulfillment(thID, fulfillment))

			go c.didCommActionListener(actionCh)

			done := make(chan struct{})

			msg := service.NewDIDCommMsgMap(issuecredsvc.RequestCredentialV2{
				Type: issuecredsvc.RequestCredentialMsgTypeV2,
			})
			msg.SetThread(thID, "")

			actionCh <- service.DIDCommAction{
				Message: msg,
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

		t.Run("test request credential failure", func(t *testing.T) {
			t.Parallel()

			actionCh := make(chan service.DIDCommAction, 1)

			c, err := New(config(t))
			require.NoError(t, err)

			connectionID := uuid.New().String()
			c.connectionLookup = &mockconn.MockConnectionsLookup{
				ConnIDByDIDs: connectionID,
			}

			issuerID := uuid.New().String()

			profile := createProfileData(issuerID)
			profile.SupportsWACI = true

			err = c.profileStore.SaveProfile(profile)
			require.NoError(t, err)

			err = c.storeUserConnectionMapping(&UserConnectionMapping{
				ConnectionID: connectionID,
				IssuerID:     issuerID,
				Token:        uuid.NewString(),
				State:        uuid.NewString(),
			})
			require.NoError(t, err)

			thID := uuid.NewString()
			fulfillment := createCredentialFulFillment(t, c, profile)
			require.NoError(t, c.saveCredentialFulfillment(thID, fulfillment))

			go c.didCommActionListener(actionCh)

			msg := service.NewDIDCommMsgMap(issuecredsvc.RequestCredentialV2{
				Type: issuecredsvc.RequestCredentialMsgTypeV2,
			})
			msg.SetThread(thID, "")

			// test credential fulfillment signing failure
			testFailure(actionCh, msg, "failed to sign credential fulfillment")

			// test delete credential fulfillment error(JUST WARNING)
			c.txnStore = &mockStoreWrapper{
				Store:     c.txnStore,
				errDelete: errors.New("delete error"),
			}
			require.NoError(t, c.saveCredentialFulfillment(thID, fulfillment))
			testFailure(actionCh, msg, "failed to sign credential fulfillment")

			// test read credential fulfillment error
			c.txnStore = &mockStoreWrapper{
				Store:  c.txnStore,
				errGet: errors.New("get error"),
			}
			testFailure(actionCh, msg, "failed to read credential fulfillment")

			// test missing threadID
			mockMsg := &mockMsgWrapper{
				DIDCommMsgMap: &msg,
			}

			testFailure(actionCh, mockMsg, "failed to correlate WACI interaction, missing thread ID")

			// test error getting threadID
			mockMsg.thIDerr = errors.New("thid error")
			testFailure(actionCh, mockMsg, "failed to read threadID from request credential message")
		})
	})
}

func createCredentialFulFillment(t *testing.T, o *Operation, profile *issuer.ProfileData) *verifiable.Presentation {
	t.Helper()

	o.httpClient = &mockHTTPClient{
		respValue: &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(bytes.NewReader([]byte(prCardData))),
		},
	}

	vc, err := o.createCredential(profile.URL, "", "", "", false, profile)
	require.NoError(t, err)

	// prepare fulfillment
	presentation, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
	require.NoError(t, err)

	fulfillment, err := cm.PresentCredentialFulfillment(&cm.CredentialManifest{ID: uuid.NewString()},
		cm.WithExistingPresentationForPresentCredentialFulfillment(presentation))
	require.NoError(t, err)

	return fulfillment
}

func TestGetConnectionIDFromEvent(t *testing.T) {
	t.Parallel()

	c, err := New(config(t))
	require.NoError(t, err)

	connID := uuid.New().String()
	c.connectionLookup = &mockconn.MockConnectionsLookup{
		ConnIDByDIDs: connID,
	}

	t.Run("test get connID from event - success", func(t *testing.T) {
		t.Parallel()

		id, err := c.getConnectionIDFromEvent(
			service.DIDCommAction{
				Properties: &actionEventEvent{},
			},
		)

		require.NoError(t, err)
		require.Equal(t, connID, id)
	})

	t.Run("test get connID from event - error", func(t *testing.T) {
		t.Parallel()

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
		t.Parallel()

		connID := uuid.New().String()

		err := c.tokenStore.Put(connID, []byte("invalid json data"))
		require.NoError(t, err)

		data, err := c.getUserConnectionMapping(connID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "user conn map :")
		require.Empty(t, data)
	})

	t.Run("test send http request - error", func(t *testing.T) {
		t.Parallel()

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
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		done := make(chan struct{})

		c.messenger = &messenger.MockMessenger{
			SendFunc: func(msg service.DIDCommMsgMap, myDID, theirDID string, _ ...service.Opt) error {
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
		t.Parallel()

		c, err := New(config(t))
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
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		c.messenger = &messenger.MockMessenger{
			SendFunc: func(msg service.DIDCommMsgMap, myDID, theirDID string, _ ...service.Opt) error {
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
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		c.messenger = &messenger.MockMessenger{
			SendFunc: func(msg service.DIDCommMsgMap, myDID, theirDID string, _ ...service.Opt) error {
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
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		c.messenger = &messenger.MockMessenger{
			SendFunc: func(msg service.DIDCommMsgMap, myDID, theirDID string, _ ...service.Opt) error {
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

type mockStoreWrapper struct {
	storage.Store
	errPut    error
	errGet    error
	errDelete error
}

// Put returns mocked results.
func (s *mockStoreWrapper) Put(k string, v []byte, t ...storage.Tag) error {
	if s.errPut != nil {
		return s.errPut
	}

	return s.Store.Put(k, v, t...) // nolint:wrapcheck
}

// Get returns mocked results.
func (s *mockStoreWrapper) Get(k string) ([]byte, error) {
	if s.errGet != nil {
		return nil, s.errGet
	}

	return s.Store.Get(k) // nolint:wrapcheck
}

// Delete returns mocked results.
func (s *mockStoreWrapper) Delete(k string) error {
	if s.errDelete != nil {
		return s.errDelete
	}

	return s.Store.Delete(k) // nolint:wrapcheck
}

// mockMsgWrapper containing custom thread IDs.
type mockMsgWrapper struct {
	*service.DIDCommMsgMap
	thID    string
	thIDerr error
}

func (m *mockMsgWrapper) ThreadID() (string, error) {
	return m.thID, m.thIDerr
}
