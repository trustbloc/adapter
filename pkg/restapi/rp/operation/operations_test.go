/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	didexchangesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/edge-adapter/pkg/db/rp"
	"github.com/trustbloc/edge-adapter/pkg/internal/common/adapterutil"
	mockdidexchange "github.com/trustbloc/edge-adapter/pkg/internal/mock/didexchange"
	mockoutofband "github.com/trustbloc/edge-adapter/pkg/internal/mock/outofband"
	mockpresentproof "github.com/trustbloc/edge-adapter/pkg/internal/mock/presentproof"
	"github.com/trustbloc/edge-adapter/pkg/presexch"
	rp2 "github.com/trustbloc/edge-adapter/pkg/vc/rp"
)

const (
	creditCardStatementScope = "CreditCardStatement"
)

func TestNew(t *testing.T) {
	t.Run("registers for didcomm events", func(t *testing.T) {
		registeredDIDExchActions := false
		registeredPresentProofActions := false
		registeredMsgs := false
		_, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				ActionEventFunc: func(chan<- service.DIDCommAction) error {
					registeredDIDExchActions = true
					return nil
				},
				MsgEventFunc: func(chan<- service.StateMsg) error {
					registeredMsgs = true
					return nil
				},
			},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient: &mockpresentproof.MockClient{
				RegisterActionFunc: func(chan<- service.DIDCommAction) error {
					registeredPresentProofActions = true
					return nil
				},
			},
		})
		require.NoError(t, err)
		require.True(t, registeredDIDExchActions)
		require.True(t, registeredMsgs)
		require.True(t, registeredPresentProofActions)
	})

	t.Run("wraps error when didexchange actions registration fails", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				ActionEventFunc: func(chan<- service.DIDCommAction) error {
					return expected
				},
			},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error when presentproof actions registration fails", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage:       memStorage(),
			PresentProofClient: &mockpresentproof.MockClient{
				RegisterActionFunc: func(chan<- service.DIDCommAction) error {
					return expected
				},
			},
			AriesStorageProvider: &mockAriesContextProvider{},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error when state msg registration fails", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				MsgEventFunc: func(chan<- service.StateMsg) error {
					return expected
				},
			},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error if cannot open store", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: &stubStorageProvider{storeCreateErr: expected},
				Transient:  memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error if cannot create transient store", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&Config{
			DIDExchClient:      &mockdidexchange.MockClient{},
			PresentProofClient: &mockpresentproof.MockClient{},
			Storage: &Storage{
				Persistent: memstore.NewProvider(),
				Transient:  &stubStorageProvider{storeCreateErr: expected},
			},
			AriesStorageProvider: &mockAriesContextProvider{},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error if cannot create transient store", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&Config{
			DIDExchClient:      &mockdidexchange.MockClient{},
			PresentProofClient: &mockpresentproof.MockClient{},
			Storage: &Storage{
				Persistent: memstore.NewProvider(),
				Transient:  &stubStorageProvider{storeOpenErr: expected},
			},
			AriesStorageProvider: &mockAriesContextProvider{},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error if cannot open aries transient store", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage:       memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{
				tstore: &ariesmockstorage.MockStoreProvider{ErrOpenStoreHandle: expected},
			},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func Test_HandleDIDExchangeRequests(t *testing.T) {
	t.Run("continues didcomm action for valid didexchange request", func(t *testing.T) {
		var incoming chan<- service.DIDCommAction
		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				ActionEventFunc: func(c chan<- service.DIDCommAction) error {
					incoming = c
					return nil
				},
			},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		require.NotNil(t, incoming)
		invitationID := uuid.New().String()
		continued := make(chan struct{})
		storePut(t, o.transientStore, invitationID, &consentRequestCtx{InvitationID: invitationID})
		go func() {
			incoming <- service.DIDCommAction{
				ProtocolName: didexchangesvc.DIDExchange,
				Message: service.NewDIDCommMsgMap(&didexchangesvc.Request{
					Type:   didexchangesvc.RequestMsgType,
					ID:     uuid.New().String(),
					Label:  "test",
					Thread: &decorator.Thread{PID: invitationID},
				}),
				Continue: func(args interface{}) {
					continued <- struct{}{}
				},
			}
		}()
		select {
		case <-continued:
		case <-time.After(time.Second):
			t.Errorf("timeout")
		}
	})

	t.Run("stops didcomm action for invalid parentThreadID", func(t *testing.T) {
		var incoming chan<- service.DIDCommAction
		_, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				ActionEventFunc: func(c chan<- service.DIDCommAction) error {
					incoming = c
					return nil
				},
			},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		require.NotNil(t, incoming)
		stopped := make(chan struct{})
		go func() {
			incoming <- service.DIDCommAction{
				ProtocolName: didexchangesvc.DIDExchange,
				Message: service.NewDIDCommMsgMap(&didexchangesvc.Request{
					Type:   didexchangesvc.RequestMsgType,
					ID:     uuid.New().String(),
					Label:  "test",
					Thread: &decorator.Thread{PID: "invalid"},
				}),
				Stop: func(err error) {
					stopped <- struct{}{}
				},
			}
		}()
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Errorf("timeout")
		}
	})

	t.Run("stops didcomm action for invalid didcomm message type", func(t *testing.T) {
		var incoming chan<- service.DIDCommAction
		_, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				ActionEventFunc: func(c chan<- service.DIDCommAction) error {
					incoming = c
					return nil
				},
			},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		require.NotNil(t, incoming)
		stopped := make(chan struct{})
		go func() {
			incoming <- service.DIDCommAction{
				ProtocolName: didexchangesvc.DIDExchange,
				Message: service.NewDIDCommMsgMap(&didexchangesvc.Request{
					Type:   "invalid",
					ID:     uuid.New().String(),
					Label:  "test",
					Thread: &decorator.Thread{PID: "invalid"},
				}),
				Stop: func(err error) {
					stopped <- struct{}{}
				},
			}
		}()
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Errorf("timeout")
		}
	})
}

func TestListenForConnectionCompleteEvents(t *testing.T) {
	t.Run("captures RP's peer DID when connection is complete", func(t *testing.T) {
		t.Parallel()
		record := &connection.Record{
			ConnectionID: uuid.New().String(),
			State:        didexchangesvc.StateIDCompleted,
			MyDID:        newDID(t).String(),
		}
		var msgs chan<- service.StateMsg
		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				MsgEventFunc: func(c chan<- service.StateMsg) error {
					msgs = c
					return nil
				},
			},
			Storage: memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{
				store: &ariesmockstorage.MockStoreProvider{
					Store: &ariesmockstorage.MockStore{
						Store: map[string][]byte{
							fmt.Sprintf("conn_%s", record.ConnectionID): toBytes(t, record),
						},
					},
				},
			},
			PresentProofClient: &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		invitationID := uuid.New().String()
		storePut(t, o.transientStore, invitationID, &consentRequestCtx{InvitationID: invitationID})

		msgs <- service.StateMsg{
			Type:    service.PostState,
			StateID: didexchangesvc.StateIDCompleted,
			Properties: &didexchangeEvent{
				connID: record.ConnectionID,
				invID:  invitationID,
			},
		}
	})

	t.Run("skips prestate msgs", func(t *testing.T) {
		t.Parallel()
		skipped := true
		var msgs chan<- service.StateMsg
		_, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				MsgEventFunc: func(c chan<- service.StateMsg) error {
					msgs = c
					return nil
				},
			},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		msgs <- service.StateMsg{
			Type:    service.PreState,
			StateID: didexchangesvc.StateIDCompleted,
			Properties: &didexchangeEvent{
				invIDFunc: func() string {
					skipped = false
					return ""
				},
			},
		}

		time.Sleep(100 * time.Millisecond)
		require.True(t, skipped)
	})

	t.Run("skips non-completion msgs", func(t *testing.T) {
		t.Parallel()
		skipped := true
		var msgs chan<- service.StateMsg
		_, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				MsgEventFunc: func(c chan<- service.StateMsg) error {
					msgs = c
					return nil
				},
			},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		msgs <- service.StateMsg{
			Type:    service.PostState,
			StateID: didexchangesvc.StateIDRequested,
			Properties: &didexchangeEvent{
				invIDFunc: func() string {
					skipped = false
					return ""
				},
			},
		}

		time.Sleep(100 * time.Millisecond)
		require.True(t, skipped)
	})

	t.Run("skips msgs with unrecognized invitation IDs", func(t *testing.T) {
		t.Parallel()
		var msgs chan<- service.StateMsg
		_, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				MsgEventFunc: func(c chan<- service.StateMsg) error {
					msgs = c
					return nil
				},
			},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		msgs <- service.StateMsg{
			Type:       service.PostState,
			StateID:    didexchangesvc.StateIDCompleted,
			Properties: &didexchangeEvent{},
		}
	})

	t.Run("skips if cannot fetch connection record", func(t *testing.T) {
		t.Parallel()
		var msgs chan<- service.StateMsg
		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				MsgEventFunc: func(c chan<- service.StateMsg) error {
					msgs = c
					return nil
				},
			},
			Storage: memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{
				store: &ariesmockstorage.MockStoreProvider{
					Store: &ariesmockstorage.MockStore{
						ErrGet: errors.New("test"),
					},
				},
			},
			PresentProofClient: &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		crCtx := &consentRequestCtx{InvitationID: uuid.New().String()}
		storePut(t, o.transientStore, crCtx.InvitationID, crCtx)

		msgs <- service.StateMsg{
			Type:    service.PostState,
			StateID: didexchangesvc.StateIDCompleted,
			Properties: &didexchangeEvent{
				connID: "test",
				invID:  crCtx.InvitationID,
			},
		}

		time.Sleep(100 * time.Millisecond)
		require.Empty(t, crCtx.RPPairwiseDID)
	})
}

func TestGetRESTHandlers(t *testing.T) {
	c, err := New(&Config{
		DIDExchClient:        &mockdidexchange.MockClient{},
		Storage:              memStorage(),
		AriesStorageProvider: &mockAriesContextProvider{},
		PresentProofClient:   &mockpresentproof.MockClient{},
	})
	require.NoError(t, err)

	require.Equal(t, 7, len(c.GetRESTHandlers()))
}

func TestHydraLoginHandlerIterOne(t *testing.T) {
	t.Run("redirects back to hydra", func(t *testing.T) {
		t.Run("with new user connection", func(t *testing.T) {
			tenant := &rp.Tenant{
				ClientID:  uuid.New().String(),
				PublicDID: newDID(t).String(),
				Label:     "test",
			}
			store := mockStore()
			rpStore, err := rp.New(store)
			require.NoError(t, err)
			err = rpStore.SaveRP(tenant)
			require.NoError(t, err)
			const redirectURL = "http://redirect.com"
			o, err := New(&Config{
				Hydra: &stubHydra{
					loginRequestFunc: func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
						return &admin.GetLoginRequestOK{
							Payload: &models.LoginRequest{
								Skip:   true,
								Client: &models.OAuth2Client{ClientID: tenant.ClientID},
							},
						}, nil
					},
					acceptLoginFunc: func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
						return &admin.AcceptLoginRequestOK{
							Payload: &models.CompletedRequest{
								RedirectTo: redirectURL,
							},
						}, nil
					},
				},
				DIDExchClient: &mockdidexchange.MockClient{},
				Storage: &Storage{
					Persistent: store,
					Transient:  memstore.NewProvider(),
				},
				AriesStorageProvider: &mockAriesContextProvider{},
				PresentProofClient:   &mockpresentproof.MockClient{},
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			o.hydraLoginHandlerIterOne(w, newHydraLoginRequest(t))
			require.Equal(t, http.StatusFound, w.Code)
			require.Equal(t, w.Header().Get("Location"), redirectURL)
		})
		t.Run("with existing user connection", func(t *testing.T) {
			tenant := &rp.Tenant{
				ClientID:  uuid.New().String(),
				PublicDID: newDID(t).String(),
				Label:     "test",
			}
			conn := &rp.UserConnection{
				User: &rp.User{
					Subject: uuid.New().String(),
				},
				RP:      tenant,
				Request: &rp.DataRequest{},
			}
			store := mockStore()
			rpStore, err := rp.New(store)
			require.NoError(t, err)
			err = rpStore.SaveRP(tenant)
			require.NoError(t, err)
			err = rpStore.SaveUserConnection(conn)
			require.NoError(t, err)
			const redirectURL = "http://redirect.com"
			o, err := New(&Config{
				Hydra: &stubHydra{
					loginRequestFunc: func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
						return &admin.GetLoginRequestOK{
							Payload: &models.LoginRequest{
								Skip:    true,
								Client:  &models.OAuth2Client{ClientID: tenant.ClientID},
								Subject: conn.User.Subject,
							},
						}, nil
					},
					acceptLoginFunc: func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
						return &admin.AcceptLoginRequestOK{
							Payload: &models.CompletedRequest{
								RedirectTo: redirectURL,
							},
						}, nil
					},
				},
				DIDExchClient: &mockdidexchange.MockClient{},
				Storage: &Storage{
					Persistent: store,
					Transient:  memstore.NewProvider(),
				},
				AriesStorageProvider: &mockAriesContextProvider{},
				PresentProofClient:   &mockpresentproof.MockClient{},
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			o.hydraLoginHandlerIterOne(w, newHydraLoginRequest(t))
			require.Equal(t, http.StatusFound, w.Code)
			require.Equal(t, w.Header().Get("Location"), redirectURL)
		})
	})
	t.Run("fails on missing login_challenge", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		r := newHydraRequestNoChallenge(t)
		r.URL.Query().Del("login_challenge")
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandlerIterOne(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("error while fetching hydra login request", func(t *testing.T) {
		o, err := New(&Config{
			Hydra: &stubHydra{
				loginRequestFunc: func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
					return nil, errors.New("test")
				},
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandlerIterOne(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("error while accepting login request at hydra", func(t *testing.T) {
		o, err := New(&Config{
			Hydra: &stubHydra{
				loginRequestFunc: func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
					return &admin.GetLoginRequestOK{
						Payload: &models.LoginRequest{
							Skip:   true,
							Client: &models.OAuth2Client{},
						},
					}, nil
				},
				acceptLoginFunc: func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
					return nil, errors.New("test")
				},
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandlerIterOne(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("internal server error on error saving user connection", func(t *testing.T) {
		tenant := &rp.Tenant{
			ClientID:  uuid.New().String(),
			PublicDID: newDID(t).String(),
			Label:     "test",
		}
		store := mockStore()
		rpStore, err := rp.New(store)
		require.NoError(t, err)
		err = rpStore.SaveRP(tenant)
		require.NoError(t, err)
		store.Store.ErrPut = errors.New("test")
		const redirectURL = "http://redirect.com"
		o, err := New(&Config{
			Hydra: &stubHydra{
				loginRequestFunc: func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
					return &admin.GetLoginRequestOK{
						Payload: &models.LoginRequest{
							Skip:   true,
							Client: &models.OAuth2Client{ClientID: tenant.ClientID},
						},
					}, nil
				},
				acceptLoginFunc: func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
					return &admin.AcceptLoginRequestOK{
						Payload: &models.CompletedRequest{
							RedirectTo: redirectURL,
						},
					}, nil
				},
			},
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandlerIterOne(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("internal server error if hydra fails to accept login", func(t *testing.T) {
		tenant := &rp.Tenant{
			ClientID:  uuid.New().String(),
			PublicDID: newDID(t).String(),
			Label:     "test",
		}
		store := mockStore()
		rpStore, err := rp.New(store)
		require.NoError(t, err)
		err = rpStore.SaveRP(tenant)
		require.NoError(t, err)
		o, err := New(&Config{
			Hydra: &stubHydra{
				loginRequestFunc: func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
					return &admin.GetLoginRequestOK{
						Payload: &models.LoginRequest{
							Skip:   true,
							Client: &models.OAuth2Client{ClientID: tenant.ClientID},
						},
					}, nil
				},
				acceptLoginFunc: func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
					return nil, errors.New("test")
				},
			},
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandlerIterOne(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestHydraLoginHandler(t *testing.T) {
	t.Run("TODO - implement redirect to OIDC provider", func(t *testing.T) {
		o, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{},
			Hydra: &stubHydra{
				loginRequestFunc: func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
					return &admin.GetLoginRequestOK{
						Payload: &models.LoginRequest{
							Skip: false,
						},
					}, nil
				},
				acceptLoginFunc: func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
					return &admin.AcceptLoginRequestOK{
						Payload: &models.CompletedRequest{
							RedirectTo: "http://test.hydra.com",
						},
					}, nil
				},
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		r := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(r, newHydraLoginRequest(t))

		require.Equal(t, http.StatusFound, r.Code)
	})
	t.Run("redirects back to hydra when skipping", func(t *testing.T) {
		const redirectURL = "http://redirect.com"
		o, err := New(&Config{
			Hydra: &stubHydra{
				loginRequestFunc: func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
					return &admin.GetLoginRequestOK{
						Payload: &models.LoginRequest{
							Skip: true,
						},
					}, nil
				},
				acceptLoginFunc: func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
					return &admin.AcceptLoginRequestOK{
						Payload: &models.CompletedRequest{
							RedirectTo: redirectURL,
						},
					}, nil
				},
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusFound, w.Code)
		require.Equal(t, w.Header().Get("Location"), redirectURL)
	})
	t.Run("fails on missing login_challenge", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		r := newHydraRequestNoChallenge(t)
		r.URL.Query().Del("login_challenge")
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("error while fetching hydra login request", func(t *testing.T) {
		o, err := New(&Config{
			Hydra: &stubHydra{
				loginRequestFunc: func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
					return nil, errors.New("test")
				},
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("error while accepting login request at hydra", func(t *testing.T) {
		o, err := New(&Config{
			Hydra: &stubHydra{
				loginRequestFunc: func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
					return &admin.GetLoginRequestOK{
						Payload: &models.LoginRequest{
							Skip: true,
						},
					}, nil
				},
				acceptLoginFunc: func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
					return nil, errors.New("test")
				},
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestOidcCallbackHandler(t *testing.T) {
	t.Run("redirects to hydra", func(t *testing.T) {
		const redirectURL = "http://hydra.example.com"
		const state = "123"
		const code = "test_code"
		const clientID = "test_client_id"

		store := mockStore()
		saveRP(t, store, &rp.Tenant{ClientID: clientID})

		c, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{clientID: clientID},
			OIDC: func(c string, _ context.Context) (*oidc.IDToken, error) {
				require.Equal(t, code, c)
				return &oidc.IDToken{Subject: "test"}, nil
			},
			Hydra: &stubHydra{
				acceptLoginFunc: func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
					return &admin.AcceptLoginRequestOK{
						Payload: &models.CompletedRequest{RedirectTo: redirectURL},
					}, nil
				},
			},
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		c.setLoginRequestForState(state, &models.LoginRequest{Client: &models.OAuth2Client{ClientID: clientID}})

		r := &httptest.ResponseRecorder{}
		c.oidcCallbackHandler(r, newOidcCallbackRequest(t, state, code))

		require.Equal(t, http.StatusFound, r.Code)
		require.Equal(t, redirectURL, r.Header().Get("Location"))
	})

	t.Run("bad request on invalid state", func(t *testing.T) {
		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		r := &httptest.ResponseRecorder{}
		c.oidcCallbackHandler(r, newOidcCallbackRequest(t, "invalid_state", "code"))

		require.Equal(t, http.StatusBadRequest, r.Code)
	})

	t.Run("internal error if exchanging code for id_token fails", func(t *testing.T) {
		c, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{},
			OIDC: func(string, context.Context) (*oidc.IDToken, error) {
				return nil, errors.New("test")
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		const state = "123"

		c.setLoginRequestForState(state, &models.LoginRequest{})

		r := &httptest.ResponseRecorder{}
		c.oidcCallbackHandler(r, newOidcCallbackRequest(t, state, "code"))

		require.Equal(t, http.StatusInternalServerError, r.Code)
	})

	t.Run("internal server error if hydra fails to accept login", func(t *testing.T) {
		c, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{},
			OIDC: func(c string, _ context.Context) (*oidc.IDToken, error) {
				return &oidc.IDToken{Subject: "test"}, nil
			},
			Hydra: &stubHydra{
				acceptLoginFunc: func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
					return nil, errors.New("test")
				},
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		const state = "123"

		c.setLoginRequestForState(state, &models.LoginRequest{Client: &models.OAuth2Client{}})

		r := &httptest.ResponseRecorder{}
		c.oidcCallbackHandler(r, newOidcCallbackRequest(t, state, "code"))

		require.Equal(t, http.StatusInternalServerError, r.Code)
	})
}

func TestSaveUserAndRequest(t *testing.T) {
	t.Run("error when fetching rp", func(t *testing.T) {
		clientID := uuid.New().String()
		store := mockStore()
		store.Store.ErrGet = errors.New("test")
		store.Store.ErrPut = errors.New("test")
		c, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{},
			OIDC: func(c string, _ context.Context) (*oidc.IDToken, error) {
				return &oidc.IDToken{Subject: "test"}, nil
			},
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		err = c.saveUserAndRequest(
			&models.LoginRequest{Client: &models.OAuth2Client{ClientID: clientID}},
			"sub",
		)
		require.Error(t, err)
	})

	t.Run("error when saving user connection", func(t *testing.T) {
		clientID := uuid.New().String()
		store := mockStore()
		saveRP(t, store, &rp.Tenant{ClientID: clientID})
		store.Store.ErrPut = errors.New("test")
		c, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{},
			OIDC: func(c string, _ context.Context) (*oidc.IDToken, error) {
				return &oidc.IDToken{Subject: "test"}, nil
			},
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		err = c.saveUserAndRequest(
			&models.LoginRequest{Client: &models.OAuth2Client{ClientID: clientID}},
			"sub",
		)
		require.Error(t, err)
	})
}

func TestHydraConsentHandler(t *testing.T) {
	t.Run("requiring user consent", func(t *testing.T) {
		t.Run("redirects to consent ui with handle", func(t *testing.T) {
			uiEndpoint := "http://ui.example.com"
			challenge := uuid.New().String()
			rpClientID := uuid.New().String()
			userSub := uuid.New().String()

			store := mockStore()
			saveUserConn(t, store, &rp.UserConnection{
				User: &rp.User{Subject: userSub},
				RP:   &rp.Tenant{ClientID: rpClientID},
			})

			c, err := New(&Config{
				UIEndpoint: uiEndpoint,
				Hydra: &stubHydra{
					getConsentRequestFunc: func(r *admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
						require.Equal(t, challenge, r.ConsentChallenge)
						return &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
							Skip:    false,
							Client:  &models.OAuth2Client{ClientID: rpClientID},
							Subject: userSub,
						}}, nil
					},
				},
				PresentationExProvider: mockPresentationDefinitionsProvider(),
				DIDExchClient:          &mockdidexchange.MockClient{},
				Storage: &Storage{
					Persistent: store,
					Transient:  memstore.NewProvider(),
				},
				AriesStorageProvider: &mockAriesContextProvider{},
				PresentProofClient:   &mockpresentproof.MockClient{},
			})
			require.NoError(t, err)

			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, challenge))

			require.Equal(t, http.StatusFound, w.Code)

			expected, err := url.Parse(uiEndpoint)
			require.NoError(t, err)
			redirectURL, err := url.Parse(w.Header().Get("location"))
			require.NoError(t, err)
			require.Equal(t, expected.Scheme, redirectURL.Scheme)
			require.Equal(t, expected.Host, redirectURL.Host)
			handle := redirectURL.Query().Get("pd")
			require.NotEmpty(t, handle)
		})

		t.Run("bad request if consent challenge is missing", func(t *testing.T) {
			c, err := New(&Config{
				DIDExchClient:        &mockdidexchange.MockClient{},
				Storage:              memStorage(),
				AriesStorageProvider: &mockAriesContextProvider{},
				PresentProofClient:   &mockpresentproof.MockClient{},
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraRequestNoChallenge(t))
			require.Equal(t, http.StatusBadRequest, w.Code)
		})

		t.Run("internal server error if hydra fails to deliver consent request details", func(t *testing.T) {
			c, err := New(&Config{
				Hydra: &stubHydra{getConsentRequestFunc: func(*admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
					return nil, errors.New("test")
				}},
				DIDExchClient:        &mockdidexchange.MockClient{},
				Storage:              memStorage(),
				AriesStorageProvider: &mockAriesContextProvider{},
				PresentProofClient:   &mockpresentproof.MockClient{},
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, "challenge"))
			require.Equal(t, http.StatusInternalServerError, w.Code)
		})

		t.Run("internal server error if presentation-exchange provider fails", func(t *testing.T) {
			c, err := New(&Config{
				Hydra: &stubHydra{getConsentRequestFunc: func(*admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
					return &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{Skip: false}}, nil
				}},
				PresentationExProvider: &mockPresentationExProvider{createErr: errors.New("test")},
				DIDExchClient:          &mockdidexchange.MockClient{},
				Storage:                memStorage(),
				AriesStorageProvider:   &mockAriesContextProvider{},
				PresentProofClient:     &mockpresentproof.MockClient{},
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, "challenge"))
			require.Equal(t, http.StatusInternalServerError, w.Code)
		})

		t.Run("internal server error if cannot find user connection", func(t *testing.T) {
			c, err := New(&Config{
				Hydra: &stubHydra{getConsentRequestFunc: func(*admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
					return &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
						Skip:   false,
						Client: &models.OAuth2Client{},
					}}, nil
				}},
				PresentationExProvider: &mockPresentationExProvider{
					createValue: &presexch.PresentationDefinitions{},
				},
				DIDExchClient:        &mockdidexchange.MockClient{},
				Storage:              memStorage(),
				AriesStorageProvider: &mockAriesContextProvider{},
				PresentProofClient:   &mockpresentproof.MockClient{},
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, "challenge"))
			require.Equal(t, http.StatusInternalServerError, w.Code)
		})
	})

	t.Run("internal server error on transient store PUT error", func(t *testing.T) {
		uiEndpoint := "http://ui.example.com"
		challenge := uuid.New().String()
		rpClientID := uuid.New().String()
		userSub := uuid.New().String()

		store := mockStore()
		saveUserConn(t, store, &rp.UserConnection{
			User: &rp.User{Subject: userSub},
			RP:   &rp.Tenant{ClientID: rpClientID},
		})

		c, err := New(&Config{
			UIEndpoint: uiEndpoint,
			Hydra: &stubHydra{
				getConsentRequestFunc: func(r *admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
					require.Equal(t, challenge, r.ConsentChallenge)
					return &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
						Skip:    false,
						Client:  &models.OAuth2Client{ClientID: rpClientID},
						Subject: userSub,
					}}, nil
				},
			},
			PresentationExProvider: mockPresentationDefinitionsProvider(),
			DIDExchClient:          &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient: &mockstorage.Provider{
					Store: &mockstorage.MockStore{
						Store:  make(map[string][]byte),
						ErrPut: errors.New("test"),
					},
				},
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		w := &httptest.ResponseRecorder{}
		c.hydraConsentHandler(w, newHydraConsentRequest(t, challenge))

		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("skipping user consent", func(t *testing.T) {
		t.Run("redirects to hydra", func(t *testing.T) {
			const redirectTo = "http://hydra.example.com"
			challenge := uuid.New().String()

			c, err := New(&Config{
				Hydra: &stubHydra{
					getConsentRequestFunc: func(r *admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
						require.Equal(t, challenge, r.ConsentChallenge)
						return &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
							Skip:      true,
							Challenge: challenge,
						}}, nil
					},
					acceptConsentRequestFunc: func(params *admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
						require.Equal(t, challenge, params.ConsentChallenge)
						return &admin.AcceptConsentRequestOK{Payload: &models.CompletedRequest{
							RedirectTo: redirectTo,
						}}, nil
					},
				},
				PresentationExProvider: mockPresentationDefinitionsProvider(),
				DIDExchClient:          &mockdidexchange.MockClient{},
				Storage:                memStorage(),
				AriesStorageProvider:   &mockAriesContextProvider{},
				PresentProofClient:     &mockpresentproof.MockClient{},
			})
			require.NoError(t, err)

			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, challenge))

			require.Equal(t, http.StatusFound, w.Code)
			require.Equal(t, redirectTo, w.Header().Get("location"))
		})

		t.Run("internal server error if hydra fails to accept consent request", func(t *testing.T) {
			c, err := New(&Config{
				Hydra: &stubHydra{
					getConsentRequestFunc: func(r *admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
						return &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
							Skip: true,
						}}, nil
					},
					acceptConsentRequestFunc: func(params *admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
						return nil, errors.New("test")
					},
				},
				DIDExchClient:        &mockdidexchange.MockClient{},
				Storage:              memStorage(),
				AriesStorageProvider: &mockAriesContextProvider{},
				PresentProofClient:   &mockpresentproof.MockClient{},
			})
			require.NoError(t, err)

			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, "challenge"))
			require.Equal(t, http.StatusInternalServerError, w.Code)
		})
	})
}

func TestSaveConsentRequest(t *testing.T) {
	t.Run("error if user connection does not exist", func(t *testing.T) {
		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		err = c.updateUserConnection(&consentRequestCtx{
			CR: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Client: &models.OAuth2Client{},
			}},
		})
		require.Error(t, err)
	})

	t.Run("error when saving user connection", func(t *testing.T) {
		clientID := uuid.New().String()
		userSub := uuid.New().String()
		store := mockStore()
		saveUserConn(t, store, &rp.UserConnection{
			User:    &rp.User{Subject: userSub},
			RP:      &rp.Tenant{ClientID: clientID},
			Request: &rp.DataRequest{},
		})
		store.Store.ErrPut = errors.New("test")
		c, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		err = c.updateUserConnection(&consentRequestCtx{
			CR: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Client:  &models.OAuth2Client{ClientID: clientID},
				Subject: userSub,
			}},
		})
		require.Error(t, err)
	})
}

func TestGetPresentationsRequest(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		userSubject := uuid.New().String()
		rpClientID := uuid.New().String()
		rpPublicDID := newDID(t)
		handle := uuid.New().String()
		presDefs := &presexch.PresentationDefinitions{
			InputDescriptors: []*presexch.InputDescriptor{{ID: uuid.New().String()}},
		}
		store := mockStore()
		saveUserConn(t, store, &rp.UserConnection{
			User:    &rp.User{Subject: userSubject},
			RP:      &rp.Tenant{ClientID: rpClientID},
			Request: &rp.DataRequest{},
		})

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{createValue: presDefs},
			OOBClient: &mockoutofband.MockClient{
				CreateInvVal: &outofband.Invitation{
					ID:        uuid.New().String(),
					Type:      outofband.InvitationMsgType,
					Label:     "test-label",
					Service:   []interface{}{rpPublicDID.String()},
					Protocols: []string{didexchangesvc.PIURI},
				},
			},
			DIDExchClient: &mockdidexchange.MockClient{
				CreateInvWithDIDFunc: func(label, didID string) (*didexchange.Invitation, error) {
					return &didexchange.Invitation{Invitation: &didexchangesvc.Invitation{
						ID:    uuid.New().String(),
						Type:  didexchange.InvitationMsgType,
						Label: "test-label",
						DID:   rpPublicDID.String(),
					}}, nil
				},
			},
			Storage: &Storage{
				Persistent: store,
				Transient:  memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		storePut(t, c.transientStore, handle, &consentRequestCtx{
			PD: presDefs,
			CR: &admin.GetConsentRequestOK{
				Payload: &models.ConsentRequest{
					Subject: userSubject,
					Client:  &models.OAuth2Client{ClientID: rpClientID},
				},
			},
			RPPublicDID: rpPublicDID.String(),
		})

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, handle))

		require.Equal(t, http.StatusOK, r.Code)

		var resp GetPresentationRequestResponse
		require.NoError(t, json.Unmarshal(r.Body.Bytes(), &resp))

		require.Equal(t, presDefs, resp.PD)
		require.NotNil(t, resp.Inv)
		require.Len(t, resp.Inv.Service, 1)
		require.Equal(t, rpPublicDID.String(), resp.Inv.Service[0])
	})

	t.Run("bad request if handle is invalid", func(t *testing.T) {
		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, "invalid"))

		require.Equal(t, http.StatusBadRequest, r.Code)
	})

	t.Run("bad request if handle is missing", func(t *testing.T) {
		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c.getPresentationsRequest(
			w, httptest.NewRequest(http.MethodGet, "http://adapter.example.com/createPresentation", nil))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("internal server error if failed to create didexchange invitation", func(t *testing.T) {
		userSubject := uuid.New().String()
		rpClientID := uuid.New().String()
		rpPublicDID := newDID(t)
		handle := uuid.New().String()
		presDefs := &presexch.PresentationDefinitions{
			InputDescriptors: []*presexch.InputDescriptor{{ID: uuid.New().String()}},
		}
		store := mockStore()
		saveUserConn(t, store, &rp.UserConnection{
			User:    &rp.User{Subject: userSubject},
			RP:      &rp.Tenant{ClientID: rpClientID},
			Request: &rp.DataRequest{},
		})

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{createValue: presDefs},
			OOBClient: &mockoutofband.MockClient{
				CreateInvErr: errors.New("test"),
			},
			Storage: &Storage{
				Persistent: store,
				Transient:  memstore.NewProvider(),
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		storePut(t, c.transientStore, handle, &consentRequestCtx{
			PD: presDefs,
			CR: &admin.GetConsentRequestOK{
				Payload: &models.ConsentRequest{
					Subject: userSubject,
					Client:  &models.OAuth2Client{ClientID: rpClientID},
				},
			},
			RPPublicDID: rpPublicDID.String(),
		})

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, handle))

		require.Equal(t, http.StatusInternalServerError, r.Code)
	})

	t.Run("internal server error on persistent store GET error", func(t *testing.T) {
		handle := uuid.New().String()

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{},
			DIDExchClient:          &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: &mockstorage.Provider{
					Store: &mockstorage.MockStore{
						Store:  make(map[string][]byte),
						ErrGet: errors.New("test"),
					},
				},
				Transient: memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		storePut(t, c.transientStore, handle, &consentRequestCtx{
			PD: &presexch.PresentationDefinitions{
				InputDescriptors: []*presexch.InputDescriptor{{ID: uuid.New().String()}},
			},
			CR: &admin.GetConsentRequestOK{
				Payload: &models.ConsentRequest{
					Subject: uuid.New().String(),
					Client:  &models.OAuth2Client{ClientID: uuid.New().String()},
				},
			},
			RPPublicDID: newDID(t).String(),
		})

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, handle))

		require.Equal(t, http.StatusInternalServerError, r.Code)
	})

	t.Run("internal server error on persistent store PUT error", func(t *testing.T) {
		handle := uuid.New().String()
		userSubject := uuid.New().String()
		rpClientID := uuid.New().String()

		store := mockStore()

		saveUserConn(t, store, &rp.UserConnection{
			User:    &rp.User{Subject: userSubject},
			RP:      &rp.Tenant{ClientID: rpClientID},
			Request: &rp.DataRequest{},
		})

		store.Store.ErrPut = errors.New("test")

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{},
			DIDExchClient:          &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient: &mockstorage.Provider{
					Store: &mockstorage.MockStore{
						Store: map[string][]byte{
							handle: toBytes(t, &consentRequestCtx{
								PD: &presexch.PresentationDefinitions{
									InputDescriptors: []*presexch.InputDescriptor{{ID: uuid.New().String()}},
								},
								CR: &admin.GetConsentRequestOK{
									Payload: &models.ConsentRequest{
										Subject: userSubject,
										Client:  &models.OAuth2Client{ClientID: rpClientID},
									},
								},
								RPPublicDID: newDID(t).String(),
							}),
						},
					},
				},
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, handle))

		require.Equal(t, http.StatusInternalServerError, r.Code)
	})

	t.Run("internal server error on transient store PUT error", func(t *testing.T) {
		handle := uuid.New().String()
		userSubject := uuid.New().String()
		rpClientID := uuid.New().String()

		store := mockStore()

		saveUserConn(t, store, &rp.UserConnection{
			User:    &rp.User{Subject: userSubject},
			RP:      &rp.Tenant{ClientID: rpClientID},
			Request: &rp.DataRequest{},
		})

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{},
			OOBClient:              &mockoutofband.MockClient{CreateInvVal: &outofband.Invitation{}},
			DIDExchClient:          &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient: &mockstorage.Provider{
					Store: &mockstorage.MockStore{
						Store: map[string][]byte{
							handle: toBytes(t, &consentRequestCtx{
								PD: &presexch.PresentationDefinitions{
									InputDescriptors: []*presexch.InputDescriptor{{ID: uuid.New().String()}},
								},
								CR: &admin.GetConsentRequestOK{
									Payload: &models.ConsentRequest{
										Subject: userSubject,
										Client:  &models.OAuth2Client{ClientID: rpClientID},
									},
								},
								RPPublicDID: newDID(t).String(),
							}),
						},
						ErrPut: errors.New("test"),
					},
				},
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, handle))

		require.Equal(t, http.StatusInternalServerError, r.Code)
	})
}

//nolint:gocyclo
func TestCHAPIResponseHandler(t *testing.T) {
	t.Run("valid chapi response", func(t *testing.T) {
		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		rpPeerDID := newPeerDID(t)
		issuerPeerDID := newPeerDID(t)
		userPeerDID := newDID(t).String()
		thid := uuid.New().String()
		var issuerResponse chan<- service.DIDCommAction = nil
		vp := newPresentationSubmissionVP(t, newUserAuthorizationVC(t, userPeerDID, rpPeerDID, issuerPeerDID))
		presDef := &presexch.PresentationDefinitions{}
		redirectURL := "http://hydra.example.com/accept"
		requestPresentationSent := make(chan struct{})
		acceptedAtHydra := make(chan struct{})

		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient: &mockpresentproof.MockClient{
				RegisterActionFunc: func(c chan<- service.DIDCommAction) error {
					issuerResponse = c

					return nil
				},
				RequestPresentationFunc: func(request *presentproof.RequestPresentation, myDID, theirDID string) (string, error) {
					require.Equal(t, rpPeerDID.ID, myDID)
					require.Equal(t, issuerPeerDID.ID, theirDID)
					require.Len(t, request.RequestPresentationsAttach, 1)
					checkPresentationDefinitionAttachment(t, presDef, request)

					go func() { requestPresentationSent <- struct{}{} }()

					return thid, nil
				},
			},
			Hydra: &stubHydra{
				acceptConsentRequestFunc: func(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
					go func() { acceptedAtHydra <- struct{}{} }()

					return &admin.AcceptConsentRequestOK{Payload: &models.CompletedRequest{RedirectTo: redirectURL}}, nil
				},
			},
		})
		require.NoError(t, err)

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{
			InvitationID:  invitationID,
			PD:            presDef,
			CR:            &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{Challenge: uuid.New().String()}},
			UserDID:       userPeerDID,
			RPPublicDID:   rpPublicDID,
			RPPairwiseDID: rpPeerDID.ID,
		})

		result := make(chan struct {
			code int
			body *HandleCHAPIResponseResult
		})

		go func() {
			w := httptest.NewRecorder()
			c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
			body := &HandleCHAPIResponseResult{}
			err := json.Unmarshal(w.Body.Bytes(), body)
			require.NoError(t, err)
			result <- struct {
				code int
				body *HandleCHAPIResponseResult
			}{
				code: w.Code,
				body: body,
			}
		}()

		select {
		case <-requestPresentationSent:
		case <-time.After(time.Second):
			t.Fatalf("timeout while waiting for request-presentation to be sent")
		}

		continued := make(chan struct{})
		stopped := make(chan error)

		go func() {
			issuerResponse <- service.DIDCommAction{
				Message: newIssuerResponse(t, thid, newPresentationSubmissionVP(t, newCreditCardStatementVC(t))),
				Continue: func(interface{}) {
					continued <- struct{}{}
				},
				Stop: func(err error) {
					stopped <- err
				},
			}
		}()

		select {
		case <-acceptedAtHydra:
			select {
			case <-continued:
			case err := <-stopped:
				t.Fatalf("didcomm action was stopped: %s", err)
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for didcomm action Continue()")
			}

			select {
			case r := <-result:
				require.Equal(t, http.StatusOK, r.code)
				require.Equal(t, redirectURL, r.body.RedirectURL)
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for the http response")
			}
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for acceptance at hydra")
		}
	})

	t.Run("bad request if body is malformed", func(t *testing.T) {
		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c.chapiResponseHandler(w,
			httptest.NewRequest(http.MethodPost, "/dummy", bytes.NewReader([]byte("invalid"))))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if invitationID is invalid", func(t *testing.T) {
		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c.chapiResponseHandler(w, newCHAPIResponse(t, "test", &verifiable.Presentation{}))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if verifiable presentation is invalid", func(t *testing.T) {
		invitationID := uuid.New().String()
		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{InvitationID: invitationID})

		w := httptest.NewRecorder()
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, &verifiable.Presentation{}))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if issuer did doc is malformed", func(t *testing.T) {
		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		rpPeerDID := newPeerDID(t)
		invalid := newPeerDID(t)

		invalid.Context = nil
		invalid.Service = nil
		invalid.PublicKey = nil

		vp := newPresentationSubmissionVP(t, newUserAuthorizationVC(t, newPeerDID(t).ID, rpPeerDID, invalid))

		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{
			InvitationID:  invitationID,
			RPPublicDID:   rpPublicDID,
			RPPairwiseDID: rpPeerDID.ID,
		})

		w := &httptest.ResponseRecorder{}
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("internal server error if error creating didcomm connection", func(t *testing.T) {
		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		rpPeerDID := newPeerDID(t)
		vp := newPresentationSubmissionVP(t, newUserAuthorizationVC(t, newPeerDID(t).ID, rpPeerDID, newPeerDID(t)))

		c, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				CreateConnectionFunc: func(string, *did.Doc, ...didexchange.ConnectionOption) (string, error) {
					return "", errors.New("test")
				},
			},
			Storage: memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{
				store: &ariesmockstorage.MockStoreProvider{
					Store: &ariesmockstorage.MockStore{},
				},
			},
			PresentProofClient: &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{
			InvitationID:  invitationID,
			RPPublicDID:   rpPublicDID,
			RPPairwiseDID: rpPeerDID.ID,
		})

		w := &httptest.ResponseRecorder{}
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error if cannot send request-presentation", func(t *testing.T) {
		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		rpPeerDID := newPeerDID(t)
		vp := newPresentationSubmissionVP(t, newUserAuthorizationVC(t, newPeerDID(t).ID, rpPeerDID, newPeerDID(t)))

		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient: &mockpresentproof.MockClient{
				RequestPresentationFunc: func(*presentproof.RequestPresentation, string, string) (string, error) {
					return "", errors.New("test")
				},
			},
		})
		require.NoError(t, err)

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{
			InvitationID:  invitationID,
			RPPublicDID:   rpPublicDID,
			RPPairwiseDID: rpPeerDID.ID,
		})

		w := &httptest.ResponseRecorder{}
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("gateway timeout if issuer does not respond on time", func(t *testing.T) {
		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		rpPeerDID := newPeerDID(t)
		issuerPeerDID := newPeerDID(t)
		userPeerDID := newDID(t).String()
		thid := uuid.New().String()
		vp := newPresentationSubmissionVP(t, newUserAuthorizationVC(t, userPeerDID, rpPeerDID, issuerPeerDID))
		presDef := &presexch.PresentationDefinitions{}

		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient: &mockpresentproof.MockClient{
				RequestPresentationFunc: func(request *presentproof.RequestPresentation, myDID, theirDID string) (string, error) {
					return thid, nil
				},
			},
			Hydra: &stubHydra{},
		})
		require.NoError(t, err)
		c.issuerCallbackTimeout = 500 * time.Millisecond

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{
			InvitationID: invitationID,
			PD:           presDef,
			CR: &admin.GetConsentRequestOK{
				Payload: &models.ConsentRequest{
					Challenge: uuid.New().String(),
				},
			},
			UserDID:       userPeerDID,
			RPPublicDID:   rpPublicDID,
			RPPairwiseDID: rpPeerDID.ID,
		})

		result := make(chan int)

		go func() {
			w := httptest.NewRecorder()
			c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
			result <- w.Code
		}()

		select {
		case r := <-result:
			require.Equal(t, http.StatusGatewayTimeout, r)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	})
}

func TestHandleIssuerCallback(t *testing.T) {
	t.Run("bad request if errInvalidCredential", func(t *testing.T) {
		c, err := New(&Config{
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			DIDExchClient:        &mockdidexchange.MockClient{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c.handleIssuerCallback(w, nil, &issuerResponseStatus{err: errInvalidCredential})
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("internal server error if error is generic", func(t *testing.T) {
		c, err := New(&Config{
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			DIDExchClient:        &mockdidexchange.MockClient{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c.handleIssuerCallback(w, nil, &issuerResponseStatus{err: errors.New("generic")})
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error if cannot map credential to issuer object", func(t *testing.T) {
		c, err := New(&Config{
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			DIDExchClient:        &mockdidexchange.MockClient{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		c.issuerCallbackTimeout = time.Second
		vp := newPresentationSubmissionVP(t)
		submission := &rp2.PresentationSubmissionPresentation{}
		err = adapterutil.DecodeJSONMarshaller(vp, submission)
		submission.Base = vp
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c.handleIssuerCallback(w, nil, &issuerResponseStatus{submission: submission})
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("bad gateway if cannot accept consent request at hydra", func(t *testing.T) {
		c, err := New(&Config{
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			DIDExchClient:        &mockdidexchange.MockClient{},
			PresentProofClient:   &mockpresentproof.MockClient{},
			Hydra: &stubHydra{
				acceptConsentRequestFunc: func(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
					return nil, errors.New("test")
				},
			},
		})
		require.NoError(t, err)
		c.issuerCallbackTimeout = time.Second
		vp := newPresentationSubmissionVP(t, newCreditCardStatementVC(t))
		submission := &rp2.PresentationSubmissionPresentation{}
		err = adapterutil.DecodeJSONMarshaller(vp, submission)
		submission.Base = vp
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c.handleIssuerCallback(w,
			newCHAPIResponse(t, "", vp),
			&issuerResponseStatus{
				submission: submission,
				walletResponseCtx: &walletResponseCtx{consentRequestCtx: &consentRequestCtx{
					CR: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{}},
				}},
			},
		)
		require.Equal(t, http.StatusBadGateway, w.Code)
	})
}

//nolint:gocyclo
func TestHandleIssuerPresentationMsg(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		thid := uuid.New().String()
		callback := make(chan *issuerResponseStatus)

		o.setWalletResponseContext(thid, &walletResponseCtx{
			threadID:             thid,
			consentRequestCtx:    &consentRequestCtx{PD: &presexch.PresentationDefinitions{}},
			issuerResponseStatus: callback,
		})

		go func() {
			err = o.handleIssuerPresentationMsg(
				newIssuerResponse(t, thid, newPresentationSubmissionVP(t, newCreditCardStatementVC(t))))
			require.NoError(t, err)
		}()

		select {
		case c := <-callback:
			require.NoError(t, c.err)
			require.NotNil(t, c.submission)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	})

	t.Run("error if invalid threadID", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		err = o.handleIssuerPresentationMsg(service.NewDIDCommMsgMap(&presentproof.Presentation{}))
		require.Error(t, err)
	})

	t.Run("error if no callback channel is registered", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		err = o.handleIssuerPresentationMsg(
			newIssuerResponse(t, "INVALID", newPresentationSubmissionVP(t, newCreditCardStatementVC(t))))
		require.Error(t, err)
	})

	t.Run("error if no thid->invitationID mapping is found", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		thid := uuid.New().String()
		callback := make(chan *issuerResponseStatus)

		o.setWalletResponseContext(thid, &walletResponseCtx{
			threadID:             thid,
			consentRequestCtx:    &consentRequestCtx{PD: &presexch.PresentationDefinitions{}},
			issuerResponseStatus: callback,
		})

		msg := service.NewDIDCommMsgMap(&presentproof.Presentation{})
		err = msg.SetID(thid)
		require.NoError(t, err)

		go func() {
			err = o.handleIssuerPresentationMsg(msg)
			require.Error(t, err)
		}()

		select {
		case c := <-callback:
			require.Error(t, c.err)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	})

	t.Run("error if no invitationData is found", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		thid := uuid.New().String()
		msg := service.NewDIDCommMsgMap(&presentproof.Presentation{})

		err = msg.SetID(thid)
		require.NoError(t, err)

		callback := make(chan *issuerResponseStatus)

		o.setWalletResponseContext(thid, &walletResponseCtx{
			threadID:             thid,
			consentRequestCtx:    &consentRequestCtx{PD: &presexch.PresentationDefinitions{}},
			issuerResponseStatus: callback,
		})

		go func() {
			err = o.handleIssuerPresentationMsg(msg)
			require.Error(t, err)
		}()

		select {
		case c := <-callback:
			require.Error(t, c.err)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	})

	t.Run("error on invalid presentation response", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		thid := uuid.New().String()
		msg := service.NewDIDCommMsgMap(&presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{},
		})
		err = msg.SetID(thid)
		require.NoError(t, err)

		callback := make(chan *issuerResponseStatus)

		o.setWalletResponseContext(thid, &walletResponseCtx{
			threadID:             thid,
			consentRequestCtx:    &consentRequestCtx{PD: &presexch.PresentationDefinitions{}},
			issuerResponseStatus: callback,
		})

		go func() {
			err = o.handleIssuerPresentationMsg(msg)
			require.Error(t, err)
		}()

		select {
		case c := <-callback:
			require.Error(t, c.err)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	})

	t.Run("error fetching attachment contents", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		attachID := uuid.New().String()
		msg := service.NewDIDCommMsgMap(&presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{{
				ID: attachID,
				Data: decorator.AttachmentData{
					Base64: "invalid",
				},
			}},
		})
		thid := uuid.New().String()

		err = msg.SetID(thid)
		require.NoError(t, err)

		o.setWalletResponseContext(thid, &walletResponseCtx{
			threadID:             thid,
			consentRequestCtx:    &consentRequestCtx{PD: &presexch.PresentationDefinitions{}},
			issuerResponseStatus: make(chan *issuerResponseStatus, 2),
		})

		err = o.handleIssuerPresentationMsg(msg)
		require.Error(t, err)
	})

	t.Run("error if response attachment contains an unparseable VP", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		thid := uuid.New().String()
		callback := make(chan *issuerResponseStatus)

		o.setWalletResponseContext(thid, &walletResponseCtx{
			threadID:             thid,
			consentRequestCtx:    &consentRequestCtx{PD: &presexch.PresentationDefinitions{}},
			issuerResponseStatus: callback,
		})

		go func() {
			err = o.handleIssuerPresentationMsg(newIssuerResponse(t, thid, map[string]interface{}{}))
			require.Error(t, err)
			require.True(t, errors.Is(err, errInvalidCredential))
		}()

		select {
		case c := <-callback:
			require.True(t, errors.Is(c.err, errInvalidCredential))
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	})
}

func TestUserInfoHandler(t *testing.T) {
	c, err := New(&Config{
		DIDExchClient:        &mockdidexchange.MockClient{},
		Storage:              memStorage(),
		AriesStorageProvider: &mockAriesContextProvider{},
		PresentProofClient:   &mockpresentproof.MockClient{},
	})
	require.NoError(t, err)

	r := &httptest.ResponseRecorder{}
	c.userInfoHandler(r, nil)

	require.Equal(t, http.StatusOK, r.Code)
}

func TestTestResponse(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		testResponse(&stubWriter{})
	})
}

func TestCreateRPTenant(t *testing.T) {
	t.Run("creates valid tenant", func(t *testing.T) {
		callback := "http://test.example.com"
		expected := &rp.Tenant{
			ClientID:  uuid.New().String(),
			PublicDID: newDID(t).String(),
			Label:     "test label",
			Scopes:    []string{creditCardStatementScope},
		}
		clientSecret := uuid.New().String()

		store := mockStore()
		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(params *admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					require.Contains(t, strings.Split(params.Body.Scope, " "), oidc.ScopeOpenID)
					require.Contains(t, strings.Split(params.Body.Scope, " "), creditCardStatementScope)
					require.Contains(t, params.Body.RedirectUris, callback)
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{
							ClientID:     expected.ClientID,
							ClientSecret: clientSecret,
							RequestUris:  []string{callback},
							Scope:        strings.Join([]string{oidc.ScopeOpenID, creditCardStatementScope}, " "),
						},
					}, nil
				},
			},
			PublicDIDCreator:   &stubPublicDIDCreator{createValue: &did.Doc{ID: expected.PublicDID}},
			PresentProofClient: &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label:    expected.Label,
			Callback: callback,
			Scopes:   []string{creditCardStatementScope},
		}))
		require.Equal(t, http.StatusCreated, w.Code)
		response := &CreateRPTenantResponse{}
		err = json.NewDecoder(w.Body).Decode(response)
		require.NoError(t, err)
		require.Equal(t, expected.ClientID, response.ClientID)
		require.Equal(t, expected.PublicDID, response.PublicDID)
		require.Equal(t, expected.Scopes, response.Scopes)
		require.Equal(t, clientSecret, response.ClientSecret)

		rpStore, err := rp.New(store)
		require.NoError(t, err)
		result, err := rpStore.GetRP(expected.ClientID)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("bad request", func(t *testing.T) {
		tests := []struct {
			desc    string
			request *http.Request
		}{
			{desc: "malformed json in body", request: newCreateRPRequestMalformed()},
			{desc: "missing label", request: newCreateRPRequest(t, &CreateRPTenantRequest{
				Label: "",
			})},
			{desc: "missing callback url", request: newCreateRPRequest(t, &CreateRPTenantRequest{
				Label:    "test",
				Callback: "",
			})},
			{desc: "missing scopes", request: newCreateRPRequest(t, &CreateRPTenantRequest{
				Label:    "test",
				Callback: "http://example/.com",
			})},
		}

		for _, test := range tests {
			o, err := New(&Config{
				DIDExchClient:        &mockdidexchange.MockClient{},
				Storage:              memStorage(),
				AriesStorageProvider: &mockAriesContextProvider{},
				Hydra: &stubHydra{
					createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
						return &admin.CreateOAuth2ClientCreated{Payload: &models.OAuth2Client{}}, nil
					},
				},
				PublicDIDCreator:   &stubPublicDIDCreator{createValue: &did.Doc{}},
				PresentProofClient: &mockpresentproof.MockClient{},
			})
			require.NoError(t, err)

			w := httptest.NewRecorder()
			o.createRPTenant(w, test.request)
			require.Equal(t, http.StatusBadRequest, w.Code, test.desc)
		}
	})

	t.Run("internal server error rp already exists", func(t *testing.T) {
		existing := &rp.Tenant{
			ClientID:  uuid.New().String(),
			PublicDID: newDID(t).String(),
			Label:     uuid.New().String(),
		}
		store := mockStore()
		rpStore, err := rp.New(store)
		require.NoError(t, err)
		err = rpStore.SaveRP(existing)
		require.NoError(t, err)
		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{ClientID: existing.ClientID},
					}, nil
				},
			},
			PresentProofClient: &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label:    existing.Label,
			Callback: "http://test.com",
			Scopes:   []string{creditCardStatementScope},
		}))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error on generic store GET error", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: &stubStorageProvider{
					storeGetErr: errors.New("generic"),
				},
				Transient: memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{},
					}, nil
				},
			},
			PresentProofClient: &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label:    "test",
			Callback: "http://test.com",
			Scopes:   []string{creditCardStatementScope},
		}))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error on generic store PUT error", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: &stubStorageProvider{
					storeGetErr: storage.ErrValueNotFound,
					storePutErr: errors.New("generic"),
				},
				Transient: memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{},
					}, nil
				},
			},
			PublicDIDCreator:   &stubPublicDIDCreator{createValue: &did.Doc{}},
			PresentProofClient: &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label:    "test",
			Callback: "http://test.com",
			Scopes:   []string{creditCardStatementScope},
		}))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error if hydra fails to create oauth2 client", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: &stubStorageProvider{
					storeGetErr: storage.ErrValueNotFound,
				},
				Transient: memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return nil, errors.New("test")
				},
			},
			PresentProofClient: &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label:    "test",
			Callback: "http://test.com",
			Scopes:   []string{creditCardStatementScope},
		}))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error if public did creation fails", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: &stubStorageProvider{
					storeGetErr: storage.ErrValueNotFound,
					storePutErr: errors.New("generic"),
				},
				Transient: memstore.NewProvider(),
			},
			AriesStorageProvider: &mockAriesContextProvider{},
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{},
					}, nil
				},
			},
			PublicDIDCreator:   &stubPublicDIDCreator{createErr: errors.New("test")},
			PresentProofClient: &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label:    "test",
			Callback: "http://test.com",
			Scopes:   []string{creditCardStatementScope},
		}))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestRemoveOIDCScope(t *testing.T) {
	t.Run("removes oidc scope", func(t *testing.T) {
		scopes := []string{oidc.ScopeOpenID, uuid.New().String(), uuid.New().String(), uuid.New().String()}
		result := removeOIDCScope(scopes)
		require.NotContains(t, result, oidc.ScopeOpenID)
		for _, scope := range scopes {
			if scope == oidc.ScopeOpenID {
				continue
			}

			require.Contains(t, result, scope)
		}
	})
}

type stubWriter struct {
}

func (s *stubWriter) Write(p []byte) (n int, err error) {
	return -1, errors.New("test")
}

type mockPresentationExProvider struct {
	createValue *presexch.PresentationDefinitions
	createErr   error
}

func (m *mockPresentationExProvider) Create(scopes []string) (*presexch.PresentationDefinitions, error) {
	return m.createValue, m.createErr
}

func newHydraLoginRequest(t *testing.T) *http.Request {
	u, err := url.Parse("http://example.com?login_challenge=" + uuid.New().String())
	require.NoError(t, err)

	return &http.Request{URL: u}
}

func newHydraConsentRequest(t *testing.T, challenge string) *http.Request {
	u, err := url.Parse("http://example.com?consent_challenge=" + challenge)
	require.NoError(t, err)

	return &http.Request{URL: u}
}

func newOidcCallbackRequest(t *testing.T, state, code string) *http.Request {
	u, err := url.Parse(fmt.Sprintf("http://example.com?state=%s&code=%s", state, code))
	require.NoError(t, err)

	return &http.Request{URL: u}
}

func newHydraRequestNoChallenge(t *testing.T) *http.Request {
	u, err := url.Parse("http://example.com")
	require.NoError(t, err)

	return &http.Request{
		URL: u,
	}
}

func newCreatePresentationDefinitionRequest(t *testing.T, handle string) *http.Request {
	u, err := url.Parse(fmt.Sprintf("http://adapter.example.com?pd=%s", handle))
	require.NoError(t, err)

	return &http.Request{URL: u}
}

type stubHydra struct {
	loginRequestFunc         func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error)
	acceptLoginFunc          func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error)
	getConsentRequestFunc    func(*admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error)
	acceptConsentRequestFunc func(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error)
	createOauth2ClientFunc   func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error)
}

func (s *stubHydra) GetLoginRequest(params *admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
	return s.loginRequestFunc(params)
}

func (s *stubHydra) AcceptLoginRequest(params *admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
	return s.acceptLoginFunc(params)
}

func (s *stubHydra) GetConsentRequest(params *admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
	return s.getConsentRequestFunc(params)
}

func (s *stubHydra) AcceptConsentRequest(
	params *admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
	return s.acceptConsentRequestFunc(params)
}

func (s *stubHydra) CreateOAuth2Client(
	params *admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
	return s.createOauth2ClientFunc(params)
}

type stubOAuth2Config struct {
	clientID    string
	authCodeURL string
}

func (s *stubOAuth2Config) ClientID() string {
	return s.clientID
}

func (s *stubOAuth2Config) AuthCodeURL(_ string) string {
	return s.authCodeURL
}

func mockPresentationDefinitionsProvider() presentationExProvider {
	return &mockPresentationExProvider{
		createValue: &presexch.PresentationDefinitions{
			InputDescriptors: []*presexch.InputDescriptor{{ID: "1"}},
		},
	}
}

func newDID(t *testing.T) *did.DID {
	d, err := did.Parse("did:example:" + uuid.New().String())
	require.NoError(t, err)

	return d
}

func mockStore() *mockstorage.Provider {
	return &mockstorage.Provider{
		Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		},
	}
}

func saveRP(t *testing.T, p storage.Provider, r *rp.Tenant) {
	s, err := rp.New(p)
	require.NoError(t, err)

	err = s.SaveRP(r)
	require.NoError(t, err)
}

func saveUserConn(t *testing.T, p storage.Provider, u *rp.UserConnection) {
	s, err := rp.New(p)
	require.NoError(t, err)

	err = s.SaveUserConnection(u)
	require.NoError(t, err)
}

func newCreateRPRequest(t *testing.T, request *CreateRPTenantRequest) *http.Request {
	bits, err := json.Marshal(request)
	require.NoError(t, err)

	return httptest.NewRequest(http.MethodPost, "/dummy", bytes.NewReader(bits))
}

func newCreateRPRequestMalformed() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/dummy", nil)
}

func newCHAPIResponse(t *testing.T, invID string, vp *verifiable.Presentation) *http.Request {
	vpBytes, err := json.Marshal(vp)
	require.NoError(t, err)

	body := &HandleCHAPIResponse{
		InvitationID:           invID,
		VerifiablePresentation: vpBytes,
	}
	bits, err := json.Marshal(body)
	require.NoError(t, err)

	return httptest.NewRequest(http.MethodPost, "/dummy", bytes.NewReader(bits))
}

type stubStorageProvider struct {
	storeCreateErr error
	storeOpenErr   error
	storeGetErr    error
	storePutErr    error
}

func (s *stubStorageProvider) CreateStore(name string) error {
	return s.storeCreateErr
}

func (s *stubStorageProvider) OpenStore(name string) (storage.Store, error) {
	if s.storeOpenErr != nil {
		return nil, s.storeOpenErr
	}

	return &stubStore{
		errPut: s.storePutErr,
		errGet: s.storeGetErr,
	}, nil
}

func (s *stubStorageProvider) CloseStore(name string) error {
	panic("implement me")
}

func (s *stubStorageProvider) Close() error {
	panic("implement me")
}

type stubStore struct {
	errPut error
	errGet error
}

func (s *stubStore) Put(k string, v []byte) error {
	return s.errPut
}

func (s *stubStore) Get(k string) ([]byte, error) {
	return nil, s.errGet
}

func (s *stubStore) CreateIndex(createIndexRequest storage.CreateIndexRequest) error {
	panic("implement me")
}

func (s *stubStore) Query(query string) (storage.ResultsIterator, error) {
	panic("implement me")
}

func (s *stubStore) Delete(k string) error {
	panic("implement me")
}

type stubPublicDIDCreator struct {
	createValue *did.Doc
	createErr   error
}

func (s *stubPublicDIDCreator) Create() (*did.Doc, error) {
	return s.createValue, s.createErr
}

type mockAriesContextProvider struct {
	store   ariesstorage.Provider
	tstore  ariesstorage.Provider
	vdriReg vdriapi.Registry
}

func (m *mockAriesContextProvider) StorageProvider() ariesstorage.Provider {
	if m.store != nil {
		return m.store
	}

	return ariesmockstorage.NewMockStoreProvider()
}

func (m *mockAriesContextProvider) ProtocolStateStorageProvider() ariesstorage.Provider {
	if m.tstore != nil {
		return m.tstore
	}

	return ariesmockstorage.NewMockStoreProvider()
}

func (m *mockAriesContextProvider) VDRIRegistry() vdriapi.Registry {
	return m.vdriReg
}

func toBytes(t *testing.T, v interface{}) []byte {
	bits, err := json.Marshal(v)
	require.NoError(t, err)

	return bits
}

func parseDIDDoc(t *testing.T, contents []byte) *did.Doc {
	t.Helper()

	d, err := did.ParseDocument(contents)
	require.NoError(t, err)

	return d
}

func marshalVP(t *testing.T, vp adapterutil.JSONMarshaller) []byte {
	bits, err := vp.MarshalJSON()
	require.NoError(t, err)

	return bits
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

func checkPresentationDefinitionAttachment(
	t *testing.T, presDef *presexch.PresentationDefinitions, request *presentproof.RequestPresentation) {
	require.Len(t, request.RequestPresentationsAttach, 1)

	bits, err := request.RequestPresentationsAttach[0].Data.Fetch()
	require.NoError(t, err)

	result := &presexch.PresentationDefinitions{}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(result)
	require.NoError(t, err)
	require.Equal(t, presDef, result)
}

func newIssuerResponse(t *testing.T, thid string, payload interface{}) service.DIDCommMsg {
	response := service.NewDIDCommMsgMap(&presentproof.Presentation{
		Type: presentproofsvc.PresentationMsgType,
		PresentationsAttach: []decorator.Attachment{{
			ID:       "123",
			MimeType: "application/ld+json",
			Data: decorator.AttachmentData{
				JSON: payload,
			},
		}},
	})
	err := response.SetID(thid)
	require.NoError(t, err)

	return response
}

func memStorage() *Storage {
	return &Storage{
		Persistent: memstore.NewProvider(),
		Transient:  memstore.NewProvider(),
	}
}

func storePut(t *testing.T, s storage.Store, k string, v interface{}) {
	bits, err := json.Marshal(v)
	require.NoError(t, err)

	err = s.Put(k, bits)
	require.NoError(t, err)
}
