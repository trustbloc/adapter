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
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	didexchangesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
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
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/mockpresentproof"
	"github.com/trustbloc/edge-adapter/pkg/presentationex"
	rp2 "github.com/trustbloc/edge-adapter/pkg/vc/rp"
)

func TestNew(t *testing.T) {
	t.Run("registers for didcomm events", func(t *testing.T) {
		registeredDIDExchActions := false
		registeredPresentProofActions := false
		registeredMsgs := false
		_, err := New(&Config{
			DIDExchClient: &stubDIDClient{
				actionEventFunc: func(chan<- service.DIDCommAction) error {
					registeredDIDExchActions = true
					return nil
				},
				msgEventFunc: func(chan<- service.StateMsg) error {
					registeredMsgs = true
					return nil
				},
			},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient: &mockpresentproof.Client{
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
			DIDExchClient: &stubDIDClient{
				actionEventFunc: func(chan<- service.DIDCommAction) error {
					return expected
				},
			},
			Store: memstore.NewProvider(),
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error when presentproof actions registration fails", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&Config{
			DIDExchClient: &stubDIDClient{
				actionEventFunc: func(chan<- service.DIDCommAction) error {
					return expected
				},
			},
			Store: memstore.NewProvider(),
			PresentProofClient: &mockpresentproof.Client{
				RegisterActionFunc: func(chan<- service.DIDCommAction) error {
					return expected
				},
			},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error when state msg registration fails", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&Config{
			DIDExchClient: &stubDIDClient{
				msgEventFunc: func(chan<- service.StateMsg) error {
					return expected
				},
			},
			Store: memstore.NewProvider(),
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error if cannot open store", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&Config{
			DIDExchClient: &stubDIDClient{},
			Store:         &stubStorageProvider{storeCreateErr: expected},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error if cannot open transient store", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&Config{
			DIDExchClient: &stubDIDClient{},
			Store:         memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{
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
			DIDExchClient: &stubDIDClient{
				actionEventFunc: func(c chan<- service.DIDCommAction) error {
					incoming = c
					return nil
				},
			},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		require.NotNil(t, incoming)
		invitationID := uuid.New().String()
		continued := make(chan struct{})
		o.setInvitationData(&invitationData{
			id: invitationID,
		})
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
			DIDExchClient: &stubDIDClient{
				actionEventFunc: func(c chan<- service.DIDCommAction) error {
					incoming = c
					return nil
				},
			},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient: &stubDIDClient{
				actionEventFunc: func(c chan<- service.DIDCommAction) error {
					incoming = c
					return nil
				},
			},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient: &stubDIDClient{
				msgEventFunc: func(c chan<- service.StateMsg) error {
					msgs = c
					return nil
				},
			},
			Store: memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{
				store: &ariesmockstorage.MockStoreProvider{
					Store: &ariesmockstorage.MockStore{
						Store: map[string][]byte{
							fmt.Sprintf("conn_%s", record.ConnectionID): toBytes(t, record),
						},
					},
				},
			},
			PresentProofClient: &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		invData := &invitationData{
			id: uuid.New().String(),
		}
		o.setInvitationData(invData)

		msgs <- service.StateMsg{
			Type:    service.PostState,
			StateID: didexchangesvc.StateIDCompleted,
			Properties: &didexchangeEvent{
				connID: record.ConnectionID,
				invID:  invData.id,
			},
		}
	})

	t.Run("skips prestate msgs", func(t *testing.T) {
		t.Parallel()
		skipped := true
		var msgs chan<- service.StateMsg
		_, err := New(&Config{
			DIDExchClient: &stubDIDClient{
				msgEventFunc: func(c chan<- service.StateMsg) error {
					msgs = c
					return nil
				},
			},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient: &stubDIDClient{
				msgEventFunc: func(c chan<- service.StateMsg) error {
					msgs = c
					return nil
				},
			},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient: &stubDIDClient{
				msgEventFunc: func(c chan<- service.StateMsg) error {
					msgs = c
					return nil
				},
			},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient: &stubDIDClient{
				msgEventFunc: func(c chan<- service.StateMsg) error {
					msgs = c
					return nil
				},
			},
			Store: memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{
				store: &ariesmockstorage.MockStoreProvider{
					Store: &ariesmockstorage.MockStore{
						ErrGet: errors.New("test"),
					},
				},
			},
			PresentProofClient: &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		invData := &invitationData{
			id: uuid.New().String(),
		}
		o.setInvitationData(invData)

		msgs <- service.StateMsg{
			Type:    service.PostState,
			StateID: didexchangesvc.StateIDCompleted,
			Properties: &didexchangeEvent{
				connID: "test",
				invID:  invData.id,
			},
		}

		time.Sleep(100 * time.Millisecond)
		require.Empty(t, invData.rpPeerDID)
	})
}

func TestGetRESTHandlers(t *testing.T) {
	c, err := New(&Config{
		DIDExchClient:        &stubDIDClient{},
		Store:                memstore.NewProvider(),
		AriesStorageProvider: &mockAriesStorageProvider{},
		PresentProofClient:   &mockpresentproof.Client{},
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
				DIDExchClient:        &stubDIDClient{},
				Store:                store,
				AriesStorageProvider: &mockAriesStorageProvider{},
				PresentProofClient:   &mockpresentproof.Client{},
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
				DIDExchClient:        &stubDIDClient{},
				Store:                store,
				AriesStorageProvider: &mockAriesStorageProvider{},
				PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                store,
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                store,
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusFound, w.Code)
		require.Equal(t, w.Header().Get("Location"), redirectURL)
	})
	t.Run("fails on missing login_challenge", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                store,
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                store,
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                store,
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
				DIDExchClient:          &stubDIDClient{},
				Store:                  store,
				AriesStorageProvider:   &mockAriesStorageProvider{},
				PresentProofClient:     &mockpresentproof.Client{},
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
				DIDExchClient:        &stubDIDClient{},
				Store:                memstore.NewProvider(),
				AriesStorageProvider: &mockAriesStorageProvider{},
				PresentProofClient:   &mockpresentproof.Client{},
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
				DIDExchClient:        &stubDIDClient{},
				Store:                memstore.NewProvider(),
				AriesStorageProvider: &mockAriesStorageProvider{},
				PresentProofClient:   &mockpresentproof.Client{},
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
				DIDExchClient:          &stubDIDClient{},
				Store:                  memstore.NewProvider(),
				AriesStorageProvider:   &mockAriesStorageProvider{},
				PresentProofClient:     &mockpresentproof.Client{},
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
					createValue: &presentationex.PresentationDefinitions{},
				},
				DIDExchClient:        &stubDIDClient{},
				Store:                memstore.NewProvider(),
				AriesStorageProvider: &mockAriesStorageProvider{},
				PresentProofClient:   &mockpresentproof.Client{},
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, "challenge"))
			require.Equal(t, http.StatusInternalServerError, w.Code)
		})
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
				DIDExchClient:          &stubDIDClient{},
				Store:                  memstore.NewProvider(),
				AriesStorageProvider:   &mockAriesStorageProvider{},
				PresentProofClient:     &mockpresentproof.Client{},
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
				DIDExchClient:        &stubDIDClient{},
				Store:                memstore.NewProvider(),
				AriesStorageProvider: &mockAriesStorageProvider{},
				PresentProofClient:   &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		err = c.saveConsentRequest(&consentRequest{
			cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
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
			DIDExchClient:        &stubDIDClient{},
			Store:                store,
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		err = c.saveConsentRequest(&consentRequest{
			cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Client:  &models.OAuth2Client{ClientID: clientID},
				Subject: userSub,
			}},
		})
		require.Error(t, err)
	})
}

func TestCreatePresentationDefinition(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		userSubject := uuid.New().String()
		rpClientID := uuid.New().String()
		rpDID := newDID(t)
		handle := uuid.New().String()
		presDefs := &presentationex.PresentationDefinitions{
			InputDescriptors: []presentationex.InputDescriptors{{ID: uuid.New().String()}},
		}
		store := mockStore()
		saveUserConn(t, store, &rp.UserConnection{
			User:    &rp.User{Subject: userSubject},
			RP:      &rp.Tenant{ClientID: rpClientID},
			Request: &rp.DataRequest{},
		})

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{createValue: presDefs},
			DIDExchClient: &stubDIDClient{
				createInvWithDIDFunc: func(label, did string) (*didexchange.Invitation, error) {
					require.Equal(t, rpDID.String(), did)
					return &didexchange.Invitation{Invitation: &didexchangesvc.Invitation{
						ID:    uuid.New().String(),
						Type:  didexchange.InvitationMsgType,
						Label: "test-label",
						DID:   rpDID.String(),
					}}, nil
				},
			},
			Store:                store,
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		c.setConsentRequest(handle, &consentRequest{
			pd: presDefs,
			cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Subject: userSubject,
				Client:  &models.OAuth2Client{ClientID: rpClientID},
			}},
			rpDID: rpDID.String(),
		})

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, handle))

		require.Equal(t, http.StatusOK, r.Code)

		var resp GetPresentationRequestResponse
		require.NoError(t, json.Unmarshal(r.Body.Bytes(), &resp))

		require.Equal(t, presDefs, resp.PD)
		require.Equal(t, rpDID.String(), resp.Inv.DID)
	})

	t.Run("bad request if handle is invalid", func(t *testing.T) {
		c, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		c.setConsentRequest(uuid.New().String(), &consentRequest{
			pd: &presentationex.PresentationDefinitions{},
			cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Subject: uuid.New().String(),
				Client:  &models.OAuth2Client{ClientID: uuid.New().String()},
			}},
		})

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, "invalid"))

		require.Equal(t, http.StatusBadRequest, r.Code)
		require.Contains(t, r.Body.String(), "invalid request")
	})

	t.Run("bad request if handle is missing", func(t *testing.T) {
		c, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
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
		rpDID := newDID(t)
		handle := uuid.New().String()
		presDefs := &presentationex.PresentationDefinitions{
			InputDescriptors: []presentationex.InputDescriptors{{ID: uuid.New().String()}},
		}
		store := mockStore()
		saveUserConn(t, store, &rp.UserConnection{
			User:    &rp.User{Subject: userSubject},
			RP:      &rp.Tenant{ClientID: rpClientID},
			Request: &rp.DataRequest{},
		})

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{createValue: presDefs},
			DIDExchClient: &stubDIDClient{
				createInvWithDIDFunc: func(label, did string) (*didexchange.Invitation, error) {
					return nil, errors.New("test")
				},
			},
			Store:                store,
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		c.setConsentRequest(handle, &consentRequest{
			pd: presDefs,
			cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Subject: userSubject,
				Client:  &models.OAuth2Client{ClientID: rpClientID},
			}},
			rpDID: rpDID.String(),
		})

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
		vp := newPresentationSubmissionVP(t, newUserConsentVC(t, userPeerDID, rpPeerDID, issuerPeerDID))
		presDef := &presentationex.PresentationDefinitions{}
		redirectURL := "http://hydra.example.com/accept"
		requestPresentationSent := make(chan struct{})
		acceptedAtHydra := make(chan struct{})

		c, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient: &mockpresentproof.Client{
				RegisterActionFunc: func(c chan<- service.DIDCommAction) error {
					issuerResponse = c

					return nil
				},
				RequestPresentationFunc: func(request *presentproof.RequestPresentation, myDID, theirDID string) (string, error) {
					require.Equal(t, rpPeerDID.ID, myDID)
					require.Equal(t, issuerPeerDID.ID, theirDID)
					require.Len(t, request.RequestPresentationsAttach, 2)
					checkDIDAttachment(t, userPeerDID, request)
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

		c.setInvitationData(&invitationData{
			id:          invitationID,
			rpPublicDID: rpPublicDID,
			rpPeerDID:   rpPeerDID.ID,
			userDID:     userPeerDID,
			pd:          presDef,
			cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Challenge: uuid.New().String(),
			}},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c.chapiResponseHandler(w,
			httptest.NewRequest(http.MethodPost, "/dummy", bytes.NewReader([]byte("invalid"))))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if invitationID is invalid", func(t *testing.T) {
		c, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c.chapiResponseHandler(w, newCHAPIResponse(t, "test", &verifiable.Presentation{}))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if verifiable presentation is invalid", func(t *testing.T) {
		invitationID := uuid.New().String()
		c, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		c.setInvitationData(&invitationData{
			id: invitationID,
		})

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

		vp := newPresentationSubmissionVP(t, newUserConsentVC(t, newPeerDID(t).ID, rpPeerDID, invalid))

		c, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		c.setInvitationData(&invitationData{
			id:          invitationID,
			rpPublicDID: rpPublicDID,
			rpPeerDID:   rpPeerDID.ID,
		})

		w := &httptest.ResponseRecorder{}
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if issuer's did doc does not have a didcomm service endpoint", func(t *testing.T) {
		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		rpPeerDID := newPeerDID(t)
		invalid := newPeerDID(t)
		invalid.Service[0].Type = "invalid"

		vp := newPresentationSubmissionVP(t, newUserConsentVC(t, newPeerDID(t).ID, rpPeerDID, invalid))

		c, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		c.setInvitationData(&invitationData{
			id:          invitationID,
			rpPublicDID: rpPublicDID,
			rpPeerDID:   rpPeerDID.ID,
		})

		w := &httptest.ResponseRecorder{}
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("internal server error if error saving connection record", func(t *testing.T) {
		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		rpPeerDID := newPeerDID(t)
		vp := newPresentationSubmissionVP(t, newUserConsentVC(t, newPeerDID(t).ID, rpPeerDID, newPeerDID(t)))

		c, err := New(&Config{
			DIDExchClient: &stubDIDClient{},
			Store:         &stubStorageProvider{storePutErr: errors.New("test")},
			AriesStorageProvider: &mockAriesStorageProvider{
				store: &ariesmockstorage.MockStoreProvider{
					Store: &ariesmockstorage.MockStore{ErrPut: errors.New("test")},
				},
			},
			PresentProofClient: &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		c.setInvitationData(&invitationData{
			id:          invitationID,
			rpPublicDID: rpPublicDID,
			rpPeerDID:   rpPeerDID.ID,
		})

		w := &httptest.ResponseRecorder{}
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error if cannot send request-presentation", func(t *testing.T) {
		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		rpPeerDID := newPeerDID(t)
		vp := newPresentationSubmissionVP(t, newUserConsentVC(t, newPeerDID(t).ID, rpPeerDID, newPeerDID(t)))

		c, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient: &mockpresentproof.Client{
				RequestPresentationFunc: func(*presentproof.RequestPresentation, string, string) (string, error) {
					return "", errors.New("test")
				},
			},
		})
		require.NoError(t, err)

		c.setInvitationData(&invitationData{
			id:          invitationID,
			rpPublicDID: rpPublicDID,
			rpPeerDID:   rpPeerDID.ID,
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
		vp := newPresentationSubmissionVP(t, newUserConsentVC(t, userPeerDID, rpPeerDID, issuerPeerDID))
		presDef := &presentationex.PresentationDefinitions{}

		c, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient: &mockpresentproof.Client{
				RequestPresentationFunc: func(request *presentproof.RequestPresentation, myDID, theirDID string) (string, error) {
					return thid, nil
				},
			},
			Hydra: &stubHydra{},
		})
		require.NoError(t, err)
		c.issuerCallbackTimeout = 500 * time.Millisecond

		c.setInvitationData(&invitationData{
			id:          invitationID,
			rpPublicDID: rpPublicDID,
			rpPeerDID:   rpPeerDID.ID,
			userDID:     userPeerDID,
			pd:          presDef,
			cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Challenge: uuid.New().String(),
			}},
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
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			DIDExchClient:        &stubDIDClient{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c.handleIssuerCallback(w, nil, nil, &issuerResponseStatus{err: errInvalidCredential})
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("internal server error if error is generic", func(t *testing.T) {
		c, err := New(&Config{
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			DIDExchClient:        &stubDIDClient{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c.handleIssuerCallback(w, nil, nil, &issuerResponseStatus{err: errors.New("generic")})
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error if cannot map credential to issuer object", func(t *testing.T) {
		c, err := New(&Config{
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			DIDExchClient:        &stubDIDClient{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		c.issuerCallbackTimeout = time.Second
		vp := newPresentationSubmissionVP(t)
		submission := &rp2.PresentationSubmissionPresentation{}
		err = adapterutil.DecodeJSONMarshaller(vp, submission)
		submission.Base = vp
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c.handleIssuerCallback(w, nil, nil, &issuerResponseStatus{submission: submission})
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("bad gateway if cannot accept consent request at hydra", func(t *testing.T) {
		c, err := New(&Config{
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			DIDExchClient:        &stubDIDClient{},
			PresentProofClient:   &mockpresentproof.Client{},
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
			&invitationData{cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{}}},
			&issuerResponseStatus{submission: submission})
		require.Equal(t, http.StatusBadGateway, w.Code)
	})
}

func TestHandleIssuerPresentationMsg(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		invitationID := uuid.New().String()
		thid := uuid.New().String()

		o.setThidInvitationData(&thidInvitationData{
			threadID:         thid,
			invitationDataID: invitationID,
		})

		o.setInvitationData(&invitationData{
			id: invitationID,
		})

		callback := make(chan *issuerResponseStatus)

		o.setIssuerCallbackCh(thid, callback)

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
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		err = o.handleIssuerPresentationMsg(service.NewDIDCommMsgMap(&presentproof.Presentation{}))
		require.Error(t, err)
	})

	t.Run("error if not thid->invitationID mapping is found", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		msg := service.NewDIDCommMsgMap(&presentproof.Presentation{})
		err = msg.SetID(uuid.New().String())
		require.NoError(t, err)
		err = o.handleIssuerPresentationMsg(msg)
		require.Error(t, err)
	})

	t.Run("error if no invitationData is found", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		msg := service.NewDIDCommMsgMap(&presentproof.Presentation{})
		err = msg.SetID(uuid.New().String())
		require.NoError(t, err)
		o.setThidInvitationData(&thidInvitationData{
			threadID: msg.ID(),
		})
		err = o.handleIssuerPresentationMsg(msg)
		require.Error(t, err)
	})

	t.Run("error on invalid presentation response", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		invitationID := uuid.New().String()
		msg := service.NewDIDCommMsgMap(&presentproof.Presentation{})
		err = msg.SetID(uuid.New().String())
		require.NoError(t, err)
		o.setThidInvitationData(&thidInvitationData{
			threadID:         msg.ID(),
			invitationDataID: invitationID,
		})
		o.setInvitationData(&invitationData{
			id: invitationID,
		})
		err = o.handleIssuerPresentationMsg(msg)
		require.Error(t, err)
	})

	t.Run("error on mismatched attachment IDs", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		invitationID := uuid.New().String()
		msg := service.NewDIDCommMsgMap(&presentproof.Presentation{
			Formats: []presentproofsvc.Format{{
				AttachID: uuid.New().String(),
				Format:   presentationSubmissionFormat,
			}},
			PresentationsAttach: []decorator.Attachment{{
				ID: uuid.New().String(),
			}},
		})
		err = msg.SetID(uuid.New().String())
		require.NoError(t, err)
		o.setThidInvitationData(&thidInvitationData{
			threadID:         msg.ID(),
			invitationDataID: invitationID,
		})
		o.setInvitationData(&invitationData{
			id: invitationID,
		})
		err = o.handleIssuerPresentationMsg(msg)
		require.Error(t, err)
	})

	t.Run("error fetching attachment contents", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		invitationID := uuid.New().String()
		attachID := uuid.New().String()
		msg := service.NewDIDCommMsgMap(&presentproof.Presentation{
			Formats: []presentproofsvc.Format{{
				AttachID: attachID,
				Format:   presentationSubmissionFormat,
			}},
			PresentationsAttach: []decorator.Attachment{{
				ID: attachID,
				Data: decorator.AttachmentData{
					Base64: "invalid",
				},
			}},
		})
		err = msg.SetID(uuid.New().String())
		require.NoError(t, err)
		o.setThidInvitationData(&thidInvitationData{
			threadID:         msg.ID(),
			invitationDataID: invitationID,
		})
		o.setInvitationData(&invitationData{
			id: invitationID,
		})
		err = o.handleIssuerPresentationMsg(msg)
		require.Error(t, err)
	})

	t.Run("error if response attachment contains an unparseable VP", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
			PresentProofClient:   &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		invitationID := uuid.New().String()
		thid := uuid.New().String()

		o.setThidInvitationData(&thidInvitationData{
			threadID:         thid,
			invitationDataID: invitationID,
		})

		o.setInvitationData(&invitationData{
			id: invitationID,
		})

		callback := make(chan *issuerResponseStatus)

		o.setIssuerCallbackCh(thid, callback)

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
		DIDExchClient:        &stubDIDClient{},
		Store:                memstore.NewProvider(),
		AriesStorageProvider: &mockAriesStorageProvider{},
		PresentProofClient:   &mockpresentproof.Client{},
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
		expected := &rp.Tenant{
			ClientID:  uuid.New().String(),
			PublicDID: newDID(t).String(),
			Label:     "test label",
		}
		clientSecret := uuid.New().String()

		store := mockStore()
		o, err := New(&Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                store,
			AriesStorageProvider: &mockAriesStorageProvider{},
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{
							ClientID:     expected.ClientID,
							ClientSecret: clientSecret,
						},
					}, nil
				},
			},
			PublicDIDCreator:   &stubPublicDIDCreator{createValue: &did.Doc{ID: expected.PublicDID}},
			PresentProofClient: &mockpresentproof.Client{},
		})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label: expected.Label,
		}))
		require.Equal(t, http.StatusCreated, w.Code)
		response := &CreateRPTenantResponse{}
		err = json.NewDecoder(w.Body).Decode(response)
		require.NoError(t, err)
		require.Equal(t, expected.ClientID, response.ClientID)
		require.Equal(t, expected.PublicDID, response.PublicDID)
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
		}

		for _, test := range tests {
			o, err := New(&Config{
				DIDExchClient:        &stubDIDClient{},
				Store:                memstore.NewProvider(),
				AriesStorageProvider: &mockAriesStorageProvider{},
				Hydra: &stubHydra{
					createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
						return &admin.CreateOAuth2ClientCreated{Payload: &models.OAuth2Client{}}, nil
					},
				},
				PublicDIDCreator:   &stubPublicDIDCreator{createValue: &did.Doc{}},
				PresentProofClient: &mockpresentproof.Client{},
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
			DIDExchClient:        &stubDIDClient{},
			Store:                store,
			AriesStorageProvider: &mockAriesStorageProvider{},
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{ClientID: existing.ClientID},
					}, nil
				},
			},
			PresentProofClient: &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label: existing.Label,
		}))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error on generic store GET error", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient: &stubDIDClient{},
			Store: &stubStorageProvider{
				storeGetErr: errors.New("generic"),
			},
			AriesStorageProvider: &mockAriesStorageProvider{},
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{},
					}, nil
				},
			},
			PresentProofClient: &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label: "test",
		}))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error on generic store PUT error", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient: &stubDIDClient{},
			Store: &stubStorageProvider{
				storeGetErr: storage.ErrValueNotFound,
				storePutErr: errors.New("generic"),
			},
			AriesStorageProvider: &mockAriesStorageProvider{},
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{},
					}, nil
				},
			},
			PublicDIDCreator:   &stubPublicDIDCreator{createValue: &did.Doc{}},
			PresentProofClient: &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label: "test",
		}))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error if hydra fails to create oauth2 client", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient: &stubDIDClient{},
			Store: &stubStorageProvider{
				storeGetErr: storage.ErrValueNotFound,
			},
			AriesStorageProvider: &mockAriesStorageProvider{},
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return nil, errors.New("test")
				},
			},
			PresentProofClient: &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label: "test",
		}))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error if public did creation fails", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient: &stubDIDClient{},
			Store: &stubStorageProvider{
				storeGetErr: storage.ErrValueNotFound,
				storePutErr: errors.New("generic"),
			},
			AriesStorageProvider: &mockAriesStorageProvider{},
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{},
					}, nil
				},
			},
			PublicDIDCreator:   &stubPublicDIDCreator{createErr: errors.New("test")},
			PresentProofClient: &mockpresentproof.Client{},
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label: "test",
		}))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

type stubWriter struct {
}

func (s *stubWriter) Write(p []byte) (n int, err error) {
	return -1, errors.New("test")
}

type mockPresentationExProvider struct {
	createValue *presentationex.PresentationDefinitions
	createErr   error
}

func (m *mockPresentationExProvider) Create(scopes []string) (*presentationex.PresentationDefinitions, error) {
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
		createValue: &presentationex.PresentationDefinitions{
			InputDescriptors: []presentationex.InputDescriptors{{ID: "1"}},
		},
	}
}

func newDID(t *testing.T) *did.DID {
	d, err := did.Parse("did:example:" + uuid.New().String())
	require.NoError(t, err)

	return d
}

type stubDIDClient struct {
	actionEventFunc      func(chan<- service.DIDCommAction) error
	msgEventFunc         func(chan<- service.StateMsg) error
	createInvWithDIDFunc func(string, string) (*didexchange.Invitation, error)
}

func (s *stubDIDClient) RegisterActionEvent(actions chan<- service.DIDCommAction) error {
	if s.actionEventFunc != nil {
		return s.actionEventFunc(actions)
	}

	return nil
}

func (s *stubDIDClient) RegisterMsgEvent(msgs chan<- service.StateMsg) error {
	if s.msgEventFunc != nil {
		return s.msgEventFunc(msgs)
	}

	return nil
}

func (s *stubDIDClient) CreateInvitationWithDID(label, didID string) (*didexchange.Invitation, error) {
	return s.createInvWithDIDFunc(label, didID)
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

type stubPublicDIDCreator struct {
	createValue *did.Doc
	createErr   error
}

func (s *stubPublicDIDCreator) Create() (*did.Doc, error) {
	return s.createValue, s.createErr
}

type mockAriesStorageProvider struct {
	store  ariesstorage.Provider
	tstore ariesstorage.Provider
}

func (m *mockAriesStorageProvider) StorageProvider() ariesstorage.Provider {
	if m.store != nil {
		return m.store
	}

	return ariesmockstorage.NewMockStoreProvider()
}

func (m *mockAriesStorageProvider) TransientStorageProvider() ariesstorage.Provider {
	if m.tstore != nil {
		return m.tstore
	}

	return ariesmockstorage.NewMockStoreProvider()
}

func toBytes(t *testing.T, v interface{}) []byte {
	bits, err := json.Marshal(v)
	require.NoError(t, err)

	return bits
}

func marshalDID(t *testing.T, d *did.Doc) []byte {
	bits, err := d.JSONBytes()
	require.NoError(t, err)

	return bits
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

func checkDIDAttachment(t *testing.T, didID string, request *presentproof.RequestPresentation) {
	var attachID string

	for i := range request.Formats {
		if request.Formats[i].Format == "w3c/did-core@v1.0-draft" {
			attachID = request.Formats[i].AttachID

			break
		}
	}

	require.NotEmpty(t, attachID)

	attach := getAttachmentByID(attachID, request.RequestPresentationsAttach)
	require.NotNil(t, attach)

	bits, err := attach.Data.Fetch()
	require.NoError(t, err)
	require.Equal(t, didID, string(bits))
}

func checkPresentationDefinitionAttachment(
	t *testing.T, presDef *presentationex.PresentationDefinitions, request *presentproof.RequestPresentation) {
	var attachID string

	for i := range request.Formats {
		if request.Formats[i].Format == "dif/presentation_definition@0.0.1" {
			attachID = request.Formats[i].AttachID

			break
		}
	}

	require.NotEmpty(t, attachID)

	attach := getAttachmentByID(attachID, request.RequestPresentationsAttach)
	require.NotNil(t, attach)

	bits, err := attach.Data.Fetch()
	require.NoError(t, err)

	result := &presentationex.PresentationDefinitions{}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(result)
	require.NoError(t, err)
	require.Equal(t, presDef, result)
}

func newIssuerResponse(t *testing.T, thid string, payload interface{}) service.DIDCommMsg {
	response := service.NewDIDCommMsgMap(&presentproof.Presentation{
		Type: presentproofsvc.PresentationMsgType,
		Formats: []presentproofsvc.Format{{
			AttachID: "123",
			Format:   presentationSubmissionFormat,
		}},
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
