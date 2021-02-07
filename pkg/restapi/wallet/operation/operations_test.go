/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation // nolint:testpackage // changing to different package requires exposing internal features.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	didexchangesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	outofbandsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	mockmsghandler "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/msghandler"
	mockdidexsvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/stretchr/testify/require"
	edgemockstore "github.com/trustbloc/edge-core/pkg/storage/mockstore"

	mockoutofband "github.com/trustbloc/edge-adapter/pkg/internal/mock/outofband"
	mockprotocol "github.com/trustbloc/edge-adapter/pkg/restapi/internal/mocks/protocol"
	mockprovider "github.com/trustbloc/edge-adapter/pkg/restapi/internal/mocks/provider"
)

const (
	sampleAppURL = "http://demo.wallet.app/home"
	sampleErr    = "sample-error"
)

func TestNew(t *testing.T) {
	t.Run("create new instance - success", func(t *testing.T) {
		op, err := New(newMockConfig())

		require.NoError(t, err)
		require.NotEmpty(t, op)
		require.Len(t, op.GetRESTHandlers(), 5)
	})

	t.Run("create new instance - oob client failure", func(t *testing.T) {
		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue:              mockstore.NewMockStoreProvider(),
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
						mediator.Coordination:      &mockroute.MockMediatorSvc{},
					},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create out-of-band client")
		require.Empty(t, op)
	})

	t.Run("create new instance - did exchange client failure", func(t *testing.T) {
		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue:              mockstore.NewMockStoreProvider(),
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					ServiceMap: map[string]interface{}{
						outofbandsvc.Name:     &mockoutofband.MockService{},
						mediator.Coordination: &mockroute.MockMediatorSvc{},
					},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create did-exchange client")
		require.Empty(t, op)
	})

	t.Run("create new instance - open store failure", func(t *testing.T) {
		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue: &mockstore.MockStoreProvider{
						ErrOpenStoreHandle: fmt.Errorf(sampleErr),
					},
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
						outofbandsvc.Name:          &mockoutofband.MockService{},
						mediator.Coordination:      &mockroute.MockMediatorSvc{},
					},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open wallet profile store")
		require.Contains(t, err.Error(), "sample-error")
		require.Empty(t, op)
	})

	t.Run("create new instance - register state event failure", func(t *testing.T) {
		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue:              mockstore.NewMockStoreProvider(),
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{
							RegisterMsgEventErr: fmt.Errorf(sampleErr),
						},
						outofbandsvc.Name:     &mockoutofband.MockService{},
						mediator.Coordination: &mockroute.MockMediatorSvc{},
					},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
		})

		require.Error(t, err)
		require.Empty(t, op)
		require.Contains(t, err.Error(), "failed to register events")
	})

	t.Run("create new instance - init messenger failure", func(t *testing.T) {
		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue: &mockstore.MockStoreProvider{
						FailNamespace: "didexchange",
					},
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
						outofbandsvc.Name:          &mockoutofband.MockService{},
						mediator.Coordination:      &mockroute.MockMediatorSvc{},
					},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
		})

		require.Error(t, err)
		require.Empty(t, op)
		require.Contains(t, err.Error(), "failed to create messenger client")
	})
}

func TestOperation_CreateInvitation(t *testing.T) {
	const sampleRequest = `{"userID": "1234"}`

	const sampleInvalidRequest = `{"userID": ""}`

	t.Run("create new invitation - success", func(t *testing.T) {
		op, err := New(newMockConfig())

		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, operationID+CreateInvitationPath,
			bytes.NewBufferString(sampleRequest))

		op.CreateInvitation(rw, rq)

		require.Equal(t, rw.Code, http.StatusOK)
		require.Contains(t, rw.Body.String(), `{"url":"http://demo.wallet.app/home?oob=eyJAaWQiO`)
	})

	t.Run("create new invitation - failure - oob error", func(t *testing.T) {
		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue:              mockstore.NewMockStoreProvider(),
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					KMSValue:                          &mockkms.KeyManager{},
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
						outofbandsvc.Name: &mockprotocol.MockOobService{
							SaveInvitationErr: fmt.Errorf(sampleErr),
						},
						mediator.Coordination: &mockroute.MockMediatorSvc{},
					},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
		})

		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, operationID+CreateInvitationPath,
			bytes.NewBufferString(sampleRequest))

		op.CreateInvitation(rw, rq)
		require.Equal(t, rw.Code, http.StatusInternalServerError)

		require.Contains(t, rw.Body.String(), `{"errMessage":"failed to save outofband invitation : sample-error"}`)
	})

	t.Run("create new invitation - failure - validation error", func(t *testing.T) {
		op, err := New(newMockConfig())

		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, operationID+CreateInvitationPath,
			bytes.NewBufferString(sampleInvalidRequest))

		op.CreateInvitation(rw, rq)
		require.Equal(t, rw.Code, http.StatusBadRequest)

		require.Contains(t, rw.Body.String(), invalidIDErr)
	})

	t.Run("create new invitation - failure - invalid request", func(t *testing.T) {
		op, err := New(newMockConfig())

		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, operationID+CreateInvitationPath,
			bytes.NewBufferString("-----"))

		op.CreateInvitation(rw, rq)
		require.Equal(t, rw.Code, http.StatusBadRequest)

		require.Contains(t, rw.Body.String(), "invalid character")
	})

	t.Run("create new invitation - failure - save profile error", func(t *testing.T) {
		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue: &mockstore.MockStoreProvider{
						Store: &mockstore.MockStore{
							ErrPut: fmt.Errorf(sampleErr),
						},
					},
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					KMSValue:                          &mockkms.KeyManager{},
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
						outofbandsvc.Name:          &mockoutofband.MockService{},
						mediator.Coordination:      &mockroute.MockMediatorSvc{},
					},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
			WalletAppURL: sampleAppURL,
		})

		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, operationID+CreateInvitationPath,
			bytes.NewBufferString(sampleRequest))

		op.CreateInvitation(rw, rq)
		require.Equal(t, rw.Code, http.StatusInternalServerError)

		require.Contains(t, rw.Body.String(), `{"errMessage":"failed to save invitation: sample-error"}`)
	})

	t.Run("create new invitation - failure - save transient store error", func(t *testing.T) {
		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue:              mockstore.NewMockStoreProvider(),
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					KMSValue:                          &mockkms.KeyManager{},
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
						outofbandsvc.Name:          &mockoutofband.MockService{},
						mediator.Coordination:      &mockroute.MockMediatorSvc{},
					},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
			WalletAppURL: sampleAppURL,
			AdapterTransientStore: &edgemockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: fmt.Errorf(sampleErr),
			},
		})

		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, operationID+CreateInvitationPath,
			bytes.NewBufferString(sampleRequest))

		op.CreateInvitation(rw, rq)
		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), `{"errMessage":"failed to save in adapter transient store: sample-error"}`)

		err = op.putInAdapterTransientStore("test-key", make(chan int))
		require.Error(t, err)
		require.Contains(t, err.Error(), `failed to marshal transient data`)
	})
}

func TestOperation_RequestApplicationProfile(t *testing.T) {
	sampleReq := fmt.Sprintf(`{"userID":"%s"}`, sampleUserID)
	sampleReq2 := fmt.Sprintf(`{"userID":"%s", "waitForConnection":true, "timeout":1}`, sampleUserID)
	sampleReq3 := `{"userID":"invalid-001", "waitForConnection":false}`

	t.Run("create application profile - success", func(t *testing.T) {
		op, err := New(newMockConfig())

		require.NoError(t, err)
		require.NotEmpty(t, op)

		err = op.store.SaveInvitation(sampleInvID, sampleUserID)
		require.NoError(t, err)

		err = op.store.SaveProfile(sampleInvID, sampleConnID)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodGet, operationID+RequestAppProfilePath, bytes.NewBufferString(sampleReq))

		op.RequestApplicationProfile(rw, rq)

		require.Equal(t, rw.Code, http.StatusOK)

		response := ApplicationProfileResponse{}
		err = json.Unmarshal(rw.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Equal(t, response.InvitationID, sampleInvID)
		require.Equal(t, response.ConnectionStatus, didexchangesvc.StateIDCompleted)
	})

	t.Run("create application profile - success but status not completed", func(t *testing.T) {
		op, err := New(newMockConfig())

		require.NoError(t, err)
		require.NotEmpty(t, op)

		err = op.store.SaveInvitation(sampleInvID, sampleUserID)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodGet, operationID+RequestAppProfilePath, bytes.NewBufferString(sampleReq))

		op.RequestApplicationProfile(rw, rq)

		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), "failed to get wallet application profile by user ID")
	})

	t.Run("create application profile - invalid request", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodGet, operationID+RequestAppProfilePath, bytes.NewBufferString(`{}`))

		op.RequestApplicationProfile(rw, rq)

		require.Equal(t, rw.Code, http.StatusBadRequest)
		require.Contains(t, rw.Body.String(), invalidIDErr)

		rw = httptest.NewRecorder()
		rq = httptest.NewRequest(http.MethodGet, operationID+RequestAppProfilePath, bytes.NewBufferString(`===`))

		op.RequestApplicationProfile(rw, rq)

		require.Equal(t, rw.Code, http.StatusBadRequest)
		require.Contains(t, rw.Body.String(), "invalid character")
	})

	t.Run("create application profile - profile not found", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodGet, operationID+RequestAppProfilePath, bytes.NewBufferString(sampleReq3))

		op.RequestApplicationProfile(rw, rq)

		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), "failed to get wallet application profile by user ID: data not found")
	})

	t.Run("test didexchange completed", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		err = op.store.SaveInvitation(sampleInvID, sampleUserID)
		require.NoError(t, err)

		ch := make(chan service.StateMsg)

		go op.stateMsgListener(ch)

		ch <- service.StateMsg{
			Type:    service.PostState,
			StateID: didexchangesvc.StateIDCompleted,
			Properties: &mockdidexsvc.MockEventProperties{
				InvID:  sampleInvID,
				ConnID: sampleConnID,
			},
		}

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodGet, operationID+RequestAppProfilePath, bytes.NewBufferString(sampleReq))

		op.RequestApplicationProfile(rw, rq)

		require.Equal(t, rw.Code, http.StatusOK)

		response := ApplicationProfileResponse{}
		err = json.Unmarshal(rw.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Equal(t, response.InvitationID, sampleInvID)
		require.Equal(t, response.ConnectionStatus, didexchangesvc.StateIDCompleted)
	})

	t.Run("test didexchange completed - but update profile failed", func(t *testing.T) {
		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue: &mockstore.MockStoreProvider{
						Store: &mockstore.MockStore{
							ErrPut: fmt.Errorf(sampleErr),
						},
					},
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					KMSValue:                          &mockkms.KeyManager{},
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
						outofbandsvc.Name:          &mockoutofband.MockService{},
						mediator.Coordination:      &mockroute.MockMediatorSvc{},
					},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
			WalletAppURL: sampleAppURL,
		})
		require.NoError(t, err)
		require.NotEmpty(t, op)

		ch := make(chan service.StateMsg)

		go op.stateMsgListener(ch)

		ch <- service.StateMsg{
			Type:    service.PostState,
			StateID: didexchangesvc.StateIDCompleted,
			Properties: &mockdidexsvc.MockEventProperties{
				InvID:  sampleInvID,
				ConnID: sampleConnID,
			},
		}

		profile, err := op.store.GetProfileByUserID(sampleUserID)
		require.Error(t, err)
		require.Empty(t, profile)
	})

	t.Run("test didexchange not completed", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		err = op.store.SaveInvitation(sampleInvID, sampleUserID)
		require.NoError(t, err)

		ch := make(chan service.StateMsg)

		go op.stateMsgListener(ch)

		ch <- service.StateMsg{
			Type:    service.PostState,
			StateID: didexchangesvc.StateIDCompleted,
		}

		ch <- service.StateMsg{
			Type:    service.PostState,
			StateID: didexchangesvc.StateIDRequested,
			Properties: &mockdidexsvc.MockEventProperties{
				InvID:  sampleInvID,
				ConnID: sampleConnID,
			},
		}

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodGet, operationID+RequestAppProfilePath, bytes.NewBufferString(sampleReq))
		rq = mux.SetURLVars(rq, map[string]string{
			"id": sampleUserID,
		})

		op.RequestApplicationProfile(rw, rq)

		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), "failed to get wallet application profile by user ID: data not found")
	})

	t.Run("create application profile - failure wait for completion", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		err = op.store.SaveInvitation(sampleInvID, sampleUserID)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodGet, operationID+RequestAppProfilePath, bytes.NewBufferString(sampleReq2))

		op.RequestApplicationProfile(rw, rq)
		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), "time out waiting for state 'completed'")
	})

	t.Run("create application profile - test prepare request", func(t *testing.T) {
		request, err := prepareAppProfileRequest(bytes.NewBufferString(`{"userID":"test", "waitForConnection":true}`))

		require.NoError(t, err)
		require.Equal(t, request.WaitForConnection, true)
		require.Equal(t, request.UserID, "test")
		require.Equal(t, request.Timeout, defaultTimeout)
	})
}

func TestOperation_SendCHAPIRequest(t *testing.T) {
	const chapiRequestSample = `{
			"userID": "userID-001",
			"request" : {
				"web": {
        			"VerifiablePresentation": {
            			"query": {
                			"type": "DIDAuth"
            			}
        			}
    			}
			}
		}`

	const chapiResponseSample = `{
  	"@context": [
    	"https://www.w3.org/2018/credentials/v1"
  	],
  	"holder": "did:trustbloc:4vSjd:EiCpyXBU6bBluyIBkDGLFEIJ5wqqfcSIXgqSLSV19f-e2g",
  	"proof": {
    		"challenge": "487c6f9b-b2c5-4c64-be01-eac663797ea9",
    		"created": "2021-01-21T17:56:35.838-05:00",
    		"domain": "example.com",
    		"jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiLMNik59d8p4MsdpaBA",
			"proofPurpose": "authentication",
    		"type": "Ed25519Signature2018",
    		"verificationMethod": "did:trustbloc:4vSjd:EiCpyXBU6bBluyIBk1HM"
		},
	"type": "VerifiablePresentation"
	}`

	const responseMsg = `
						{
							"@id": "EiCpyXBU6bBluy",
							"@type": "%s",
							"data": %s,
							"~thread" : {"thid": "%s"}
						}
					`

	t.Run("test send CHAPI request - validation errors", func(t *testing.T) {
		op, err := New(newMockConfig())

		require.NoError(t, err)
		require.NotEmpty(t, op)

		// test missing user ID
		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, operationID+SendCHAPIRequestPath, bytes.NewBufferString(`{}`))
		op.SendCHAPIRequest(rw, rq)

		require.Equal(t, rw.Code, http.StatusBadRequest)
		require.Contains(t, rw.Body.String(), invalidIDErr)

		// test missing CHAPI request
		rw = httptest.NewRecorder()
		rq = httptest.NewRequest(http.MethodPost, operationID+SendCHAPIRequestPath, bytes.NewBufferString(`{
			"userID": "sample-001"
		}`))
		op.SendCHAPIRequest(rw, rq)

		require.Equal(t, rw.Code, http.StatusBadRequest)
		require.Contains(t, rw.Body.String(), invalidCHAPIRequestErr)

		// test invalid request
		rw = httptest.NewRecorder()
		rq = httptest.NewRequest(http.MethodPost, operationID+SendCHAPIRequestPath, bytes.NewBufferString(`---`))
		op.SendCHAPIRequest(rw, rq)

		require.Equal(t, rw.Code, http.StatusBadRequest)
		require.Contains(t, rw.Body.String(), "invalid character")
	})

	t.Run("test send CHAPI request - missing profile", func(t *testing.T) {
		op, err := New(newMockConfig())

		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, operationID+SendCHAPIRequestPath,
			bytes.NewBufferString(chapiRequestSample))
		op.SendCHAPIRequest(rw, rq)

		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), "failed to get wallet application profile by user ID")
	})

	t.Run("test send CHAPI request - connection not found", func(t *testing.T) {
		op, err := New(newMockConfig())

		require.NoError(t, err)
		require.NotEmpty(t, op)

		err = op.store.SaveInvitation(sampleInvID, sampleUserID)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, operationID+SendCHAPIRequestPath,
			bytes.NewBufferString(chapiRequestSample))
		op.SendCHAPIRequest(rw, rq)

		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), "failed to get wallet application profile by user ID")
	})

	t.Run("test send CHAPI request - message send error", func(t *testing.T) {
		op, err := New(newMockConfig())

		require.NoError(t, err)
		require.NotEmpty(t, op)

		err = op.store.SaveInvitation(sampleInvID, sampleUserID)
		require.NoError(t, err)

		err = op.store.SaveProfile(sampleInvID, sampleConnID)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, operationID+SendCHAPIRequestPath,
			bytes.NewBufferString(chapiRequestSample))
		op.SendCHAPIRequest(rw, rq)

		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), fmt.Sprintf(failedToSendCHAPIRequestErr, "data not found"))
	})

	t.Run("test send CHAPI request - success", func(t *testing.T) {
		connBytes, err := json.Marshal(&connection.Record{
			ConnectionID: sampleConnID,
			State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
		})
		require.NoError(t, err)

		mockStore := &mockstore.MockStore{Store: make(map[string][]byte)}
		require.NoError(t, mockStore.Put("conn_"+sampleConnID, connBytes))

		registrar := mockmsghandler.NewMockMsgServiceProvider()
		mockMessenger := mockprovider.NewMockMessenger()

		go func() {
			for {
				if len(registrar.Services()) > 0 && mockMessenger.GetLastID() != "" { //nolint: gocritic
					replyMsg, e := service.ParseDIDCommMsgMap([]byte(
						fmt.Sprintf(responseMsg, chapiRespDIDCommMsgType, chapiResponseSample, mockMessenger.GetLastID()),
					))
					require.NoError(t, e)

					_, e = registrar.Services()[0].HandleInbound(replyMsg, "sampleDID", "sampleTheirDID")
					require.NoError(t, e)

					break
				}
			}
		}()

		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue:              mockstore.NewCustomMockStoreProvider(mockStore),
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
						outofbandsvc.Name:          &mockoutofband.MockService{},
						mediator.Coordination:      &mockroute.MockMediatorSvc{},
					},
					KMSValue: &mockkms.KeyManager{},
				},
				CustomMessenger: mockMessenger,
			},
			MsgRegistrar: registrar,
			WalletAppURL: sampleAppURL,
		})

		require.NoError(t, err)
		require.NotEmpty(t, op)

		err = op.store.SaveInvitation(sampleInvID, sampleUserID)
		require.NoError(t, err)

		err = op.store.SaveProfile(sampleInvID, sampleConnID)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, operationID+SendCHAPIRequestPath, bytes.NewBufferString(`{
			"userID": "userID-001",
			"request" : {
				"web": {
        			"VerifiablePresentation": {
            			"query": {
                			"type": "DIDAuth"
            			}
        			}
    			}
			}
		}`))
		op.SendCHAPIRequest(rw, rq)

		require.Equal(t, rw.Code, http.StatusOK)

		var response CHAPIResponse
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &response))
		require.JSONEq(t, string(response.Data), chapiResponseSample, "")
	})

	t.Run("test send CHAPI request - extract CHAPI response", func(t *testing.T) {
		_, err := extractCHAPIResponse([]byte("{"))
		require.Error(t, err)
	})
}

func TestOperation_WaitForStateCompletion(t *testing.T) {
	t.Run("test wait for state completion - success", func(t *testing.T) {
		mockDIDExSvc := &mockDIDExchangeSvc{MockDIDExchangeSvc: &mockdidexsvc.MockDIDExchangeSvc{}}

		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue:              mockstore.NewMockStoreProvider(),
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: mockDIDExSvc,
						outofbandsvc.Name:          &mockoutofband.MockService{},
						mediator.Coordination:      &mockroute.MockMediatorSvc{},
					},
					KMSValue: &mockkms.KeyManager{},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
			WalletAppURL: sampleAppURL,
		})

		require.NoError(t, err)
		require.NotEmpty(t, op)

		err = op.store.SaveInvitation(sampleInvID, sampleUserID)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		go func() {
			for {
				mockDIDExSvc.pushEvent(service.StateMsg{
					Type:    service.PostState,
					StateID: didexchangesvc.StateIDRequested,
					Properties: &mockdidexsvc.MockEventProperties{
						InvID:  sampleInvID,
						ConnID: sampleConnID,
					},
				}, 1)

				mockDIDExSvc.pushEvent(service.StateMsg{
					Type:    service.PostState,
					StateID: didexchangesvc.StateIDCompleted,
					Properties: &mockdidexsvc.MockEventProperties{
						InvID:  sampleInvID,
						ConnID: sampleConnID,
					},
				}, 1)
			}
		}()

		invID, err := op.waitForConnectionCompletion(ctx, sampleUserID)
		require.NoError(t, err)
		require.NotEmpty(t, invID)
		require.Equal(t, sampleInvID, invID)
	})

	t.Run("test wait for state completion - timeout error & unregister error", func(t *testing.T) {
		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue:              mockstore.NewMockStoreProvider(),
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{
							UnregisterMsgEventErr: fmt.Errorf(sampleErr),
						},
						outofbandsvc.Name:     &mockoutofband.MockService{},
						mediator.Coordination: &mockroute.MockMediatorSvc{},
					},
					KMSValue: &mockkms.KeyManager{},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
			WalletAppURL: sampleAppURL,
		})

		require.NoError(t, err)
		require.NotEmpty(t, op)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		_, err = op.waitForConnectionCompletion(ctx, sampleUserID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "time out waiting for state 'completed'")
	})

	t.Run("test wait for state completion - register msg event error", func(t *testing.T) {
		mockDIDExSvc := &mockdidexsvc.MockDIDExchangeSvc{}

		op, err := New(&Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue:              mockstore.NewMockStoreProvider(),
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: mockDIDExSvc,
						outofbandsvc.Name:          &mockoutofband.MockService{},
						mediator.Coordination:      &mockroute.MockMediatorSvc{},
					},
					KMSValue: &mockkms.KeyManager{},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
			WalletAppURL: sampleAppURL,
		})

		require.NoError(t, err)
		require.NotEmpty(t, op)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		mockDIDExSvc.RegisterMsgEventErr = fmt.Errorf(sampleErr)

		_, err = op.waitForConnectionCompletion(ctx, sampleUserID)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleErr)
	})
}

func TestOperation_SaveWalletPreferences(t *testing.T) {
	const (
		validSaveRequest         = `{"userID":"sampleUser", "walletType":"remote"}`
		missingIDRequest         = `{"walletType":"remote"}`
		missingWaletTypeRequest  = `{"userID":"sampleUser"}`
		invalidWalletTypeRequest = `{"userID":"sampleUser", "walletType":"invalid"}`
	)

	t.Run("test save wallet preferences - success", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, SavePreferencesPath,
			bytes.NewBufferString(validSaveRequest))
		op.SaveWalletPreferences(rw, rq)

		require.Equal(t, rw.Code, http.StatusOK)
		require.Empty(t, rw.Body.String())
	})

	t.Run("test save wallet preferences - invalid request", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, SavePreferencesPath,
			bytes.NewBufferString("=="))
		op.SaveWalletPreferences(rw, rq)

		require.Equal(t, rw.Code, http.StatusBadRequest)
		require.Contains(t, rw.Body.String(), "invalid character")
	})

	t.Run("test save wallet preferences - invalid user ID", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, SavePreferencesPath,
			bytes.NewBufferString(missingIDRequest))
		op.SaveWalletPreferences(rw, rq)

		require.Equal(t, rw.Code, http.StatusBadRequest)
		require.Contains(t, rw.Body.String(), invalidIDErr)
	})

	t.Run("test save wallet preferences - missing wallet Type", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, SavePreferencesPath,
			bytes.NewBufferString(missingWaletTypeRequest))
		op.SaveWalletPreferences(rw, rq)

		require.Equal(t, rw.Code, http.StatusBadRequest)
		require.Contains(t, rw.Body.String(), "invalid wallet type '', supported types are [browser remote]")
	})

	t.Run("test save wallet preferences - invalid wallet Type", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, SavePreferencesPath,
			bytes.NewBufferString(invalidWalletTypeRequest))
		op.SaveWalletPreferences(rw, rq)

		require.Equal(t, rw.Code, http.StatusBadRequest)
		require.Contains(t, rw.Body.String(), "invalid wallet type 'invalid', supported types are [browser remote]")
	})

	t.Run("test save wallet preferences - save error", func(t *testing.T) {
		config := &Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue: &mockstore.MockStoreProvider{
						Store: &mockstore.MockStore{
							ErrPut: fmt.Errorf(sampleErr),
						},
					},
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					ServiceMap: map[string]interface{}{
						didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
						outofbandsvc.Name:          &mockoutofband.MockService{},
						mediator.Coordination:      &mockroute.MockMediatorSvc{},
					},
					KMSValue: &mockkms.KeyManager{},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
			WalletAppURL: sampleAppURL,
		}

		op, err := New(config)
		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, SavePreferencesPath,
			bytes.NewBufferString(validSaveRequest))
		op.SaveWalletPreferences(rw, rq)

		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), sampleErr)
	})
}

func TestOperation_GetWalletPreferences(t *testing.T) {
	const validSaveRequest = `{"userID":"userID-001", "walletType":"remote"}`

	t.Run("test get wallet preferences - success", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		// save preference
		rws := httptest.NewRecorder()
		rqs := httptest.NewRequest(http.MethodPost, SavePreferencesPath,
			bytes.NewBufferString(validSaveRequest))
		op.SaveWalletPreferences(rws, rqs)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, GetPreferencesPath,
			nil)

		rq = mux.SetURLVars(rq, map[string]string{
			"id": sampleUserID,
		})

		op.GetWalletPreferences(rw, rq)

		require.Equal(t, rw.Code, http.StatusOK)
		require.Contains(t, rw.Body.String(), `{"walletType":"remote"}`)
	})

	t.Run("test save wallet preferences - invalid request", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, GetPreferencesPath,
			nil)

		op.GetWalletPreferences(rw, rq)

		require.Equal(t, rw.Code, http.StatusBadRequest)
		require.Contains(t, rw.Body.String(), invalidIDErr)
	})

	t.Run("test save wallet preferences - data not found", func(t *testing.T) {
		op, err := New(newMockConfig())
		require.NoError(t, err)
		require.NotEmpty(t, op)

		rw := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, GetPreferencesPath,
			nil)

		rq = mux.SetURLVars(rq, map[string]string{
			"id": sampleUserID,
		})

		op.GetWalletPreferences(rw, rq)

		require.Equal(t, rw.Code, http.StatusInternalServerError)
		require.Contains(t, rw.Body.String(), `data not found`)
	})
}

func newMockConfig() *Config {
	return &Config{
		AriesCtx: &mockprovider.MockProvider{
			Provider: &ariesmockprovider.Provider{
				StorageProviderValue:              mockstore.NewMockStoreProvider(),
				ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
				ServiceMap: map[string]interface{}{
					didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
					outofbandsvc.Name:          &mockoutofband.MockService{},
					mediator.Coordination:      &mockroute.MockMediatorSvc{},
				},
				KMSValue: &mockkms.KeyManager{},
			},
		},
		MsgRegistrar: msghandler.NewRegistrar(),
		WalletAppURL: sampleAppURL,
	}
}

type mockDIDExchangeSvc struct {
	*mockdidexsvc.MockDIDExchangeSvc
	lock   sync.RWMutex
	events []chan<- service.StateMsg
}

func (m *mockDIDExchangeSvc) RegisterMsgEvent(ch chan<- service.StateMsg) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.events = append(m.events, ch)

	return nil
}

func (m *mockDIDExchangeSvc) pushEvent(msg service.StateMsg, index int) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if index < len(m.events) {
		m.events[index] <- msg
	}
}
