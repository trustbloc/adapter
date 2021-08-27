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
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	didexchangesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	outofbandsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockdidexsvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	ariesmockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-adapter/pkg/aries/message"
	"github.com/trustbloc/edge-adapter/pkg/db/rp"
	mockconn "github.com/trustbloc/edge-adapter/pkg/internal/mock/connection"
	mockdidexchange "github.com/trustbloc/edge-adapter/pkg/internal/mock/didexchange"
	mockgovernance "github.com/trustbloc/edge-adapter/pkg/internal/mock/governance"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/messenger"
	mockoutofband "github.com/trustbloc/edge-adapter/pkg/internal/mock/outofband"
	mockpresentproof "github.com/trustbloc/edge-adapter/pkg/internal/mock/presentproof"
	"github.com/trustbloc/edge-adapter/pkg/internal/testutil"
	mockprovider "github.com/trustbloc/edge-adapter/pkg/restapi/internal/mocks/provider"
	"github.com/trustbloc/edge-adapter/pkg/vc"
)

const (
	creditCardStatementScope = "CreditCardStatement"
	// authorizationCredentialURIID is the non-fragment URI portion of the AuthorizationCredential JSON-LD context ID.
	authorizationCredentialURIID = "https://example.org/examples"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("registers for didcomm events", func(t *testing.T) {
		t.Parallel()

		registeredDIDExchActions := false
		registeredPresentProofActions := false
		registeredMsgs := false

		config := config(t)
		config.DIDExchClient = &mockdidexchange.MockClient{
			ActionEventFunc: func(chan<- service.DIDCommAction) error {
				registeredDIDExchActions = true
				return nil
			},
			MsgEventFunc: func(chan<- service.StateMsg) error {
				registeredMsgs = true
				return nil
			},
		}
		config.PresentProofClient = &mockpresentproof.MockClient{
			RegisterActionFunc: func(chan<- service.DIDCommAction) error {
				registeredPresentProofActions = true
				return nil
			},
		}

		_, err := New(config)
		require.NoError(t, err)
		require.True(t, registeredDIDExchActions)
		require.True(t, registeredMsgs)
		require.True(t, registeredPresentProofActions)
	})

	t.Run("wraps error when didexchange actions registration fails", func(t *testing.T) {
		t.Parallel()

		expected := errors.New("test")

		config := config(t)
		config.DIDExchClient = &mockdidexchange.MockClient{
			ActionEventFunc: func(chan<- service.DIDCommAction) error {
				return expected
			},
		}

		_, err := New(config)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error when presentproof actions registration fails", func(t *testing.T) {
		t.Parallel()

		expected := errors.New("test")

		config := config(t)
		config.PresentProofClient = &mockpresentproof.MockClient{
			RegisterActionFunc: func(chan<- service.DIDCommAction) error {
				return expected
			},
		}

		_, err := New(config)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error when state msg registration fails", func(t *testing.T) {
		t.Parallel()

		expected := errors.New("test")

		config := config(t)
		config.DIDExchClient = &mockdidexchange.MockClient{
			MsgEventFunc: func(chan<- service.StateMsg) error {
				return expected
			},
		}

		_, err := New(config)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error if cannot open store", func(t *testing.T) {
		t.Parallel()

		expected := errors.New("test")

		config := config(t)
		config.Storage = &Storage{
			Persistent: &stubStorageProvider{storeOpenErr: expected},
			Transient:  mem.NewProvider(),
		}

		_, err := New(config)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error if cannot open transient store", func(t *testing.T) {
		t.Parallel()

		expected := errors.New("test")

		config := config(t)
		config.Storage = &Storage{
			Persistent: mem.NewProvider(),
			Transient:  &stubStorageProvider{storeOpenErr: expected},
		}

		_, err := New(config)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error if cannot open aries transient store", func(t *testing.T) {
		t.Parallel()

		expected := errors.New("test")

		config := config(t)
		config.AriesContextProvider = &mockprovider.MockProvider{
			Provider: &ariesmockprovider.Provider{
				ProtocolStateStorageProviderValue: &ariesmockstorage.MockStoreProvider{ErrOpenStoreHandle: expected},
				StorageProviderValue:              mem.NewProvider(),
			},
		}

		_, err := New(config)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("create route service", func(t *testing.T) {
		t.Parallel()

		conf := config(t)
		conf.AriesContextProvider = &mockprovider.MockProvider{
			Provider: &ariesmockprovider.Provider{
				ProtocolStateStorageProviderValue: mem.NewProvider(),
				StorageProviderValue:              mem.NewProvider(),
			},
		}

		_, err := New(conf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to cast mediator service")

		conf.AriesContextProvider = &mockprovider.MockProvider{
			Provider: &ariesmockprovider.Provider{
				ProtocolStateStorageProviderValue: mem.NewProvider(),
				StorageProviderValue:              mem.NewProvider(),
				ServiceErr:                        errors.New("invalid service"),
			},
		}

		_, err = New(conf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "mediator service lookup")

		conf = config(t)
		conf.Storage.Transient = &mockstorage.Provider{
			ErrOpenStore: errors.New("open error"),
		}
		_, err = createRouteSvc(conf, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create service")
	})

	t.Run("wraps error if cannot initialize wallet bridge", func(t *testing.T) {
		t.Parallel()

		config := config(t)
		config.AriesContextProvider = &mockprovider.MockProvider{
			Provider: &ariesmockprovider.Provider{
				ProtocolStateStorageProviderValue: mem.NewProvider(),
				StorageProviderValue:              mem.NewProvider(),
				ServiceMap: map[string]interface{}{
					mediator.Coordination:      &mockroute.MockMediatorSvc{},
					didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
				},
			},
		}

		_, err := New(config)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to initialize wallet bridge")
	})
}

func Test_HandleDIDExchangeRequests(t *testing.T) {
	t.Parallel()

	t.Run("continues didcomm action for valid didexchange request", func(t *testing.T) {
		t.Parallel()

		var incoming chan<- service.DIDCommAction

		config := config(t)
		config.DIDExchClient = &mockdidexchange.MockClient{
			ActionEventFunc: func(c chan<- service.DIDCommAction) error {
				incoming = c
				return nil
			},
		}

		o, err := New(config)
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
		t.Parallel()

		var incoming chan<- service.DIDCommAction

		config := config(t)
		config.DIDExchClient = &mockdidexchange.MockClient{
			ActionEventFunc: func(c chan<- service.DIDCommAction) error {
				incoming = c
				return nil
			},
		}

		_, err := New(config)
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
		t.Parallel()

		var incoming chan<- service.DIDCommAction

		config := config(t)
		config.DIDExchClient = &mockdidexchange.MockClient{
			ActionEventFunc: func(c chan<- service.DIDCommAction) error {
				incoming = c
				return nil
			},
		}

		_, err := New(config)
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
	t.Parallel()

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
			AriesContextProvider: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue: &ariesmockstorage.MockStoreProvider{
						Store: &ariesmockstorage.MockStore{
							Store: map[string]ariesmockstorage.DBEntry{
								fmt.Sprintf("conn_%s", record.ConnectionID): {Value: marshal(t, record)},
							},
						},
					},
					ProtocolStateStorageProviderValue: mem.NewProvider(),
					ServiceMap: map[string]interface{}{
						mediator.Coordination:      &mockroute.MockMediatorSvc{},
						didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
						outofbandsvc.Name:          &mockoutofband.MockService{},
					},
				},
			},
			PresentProofClient: &mockpresentproof.MockClient{},
			MsgRegistrar:       msghandler.NewRegistrar(),
			AriesMessenger:     &messenger.MockMessenger{},
			OOBClient:          &mockoutofband.MockClient{},
		})
		require.NoError(t, err)
		invitationID := uuid.New().String()
		storePut(t, o.transientStore, invitationID, &consentRequestCtx{
			InvitationID: invitationID,
			CR: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Client: &models.OAuth2Client{ClientID: uuid.New().String()},
			}},
		})

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

		config := config(t)
		config.DIDExchClient = &mockdidexchange.MockClient{
			MsgEventFunc: func(c chan<- service.StateMsg) error {
				msgs = c
				return nil
			},
		}

		_, err := New(config)
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

		config := config(t)
		config.DIDExchClient = &mockdidexchange.MockClient{
			MsgEventFunc: func(c chan<- service.StateMsg) error {
				msgs = c
				return nil
			},
		}

		_, err := New(config)
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

		config := config(t)
		config.DIDExchClient = &mockdidexchange.MockClient{
			MsgEventFunc: func(c chan<- service.StateMsg) error {
				msgs = c
				return nil
			},
		}

		_, err := New(config)
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

		config := config(t)
		config.DIDExchClient = &mockdidexchange.MockClient{
			MsgEventFunc: func(c chan<- service.StateMsg) error {
				msgs = c
				return nil
			},
		}
		config.AriesContextProvider = &mockprovider.MockProvider{
			Provider: &ariesmockprovider.Provider{
				StorageProviderValue: &ariesmockstorage.MockStoreProvider{
					Store: &ariesmockstorage.MockStore{
						ErrGet: errors.New("test"),
					},
				},
				ProtocolStateStorageProviderValue: mem.NewProvider(),
				ServiceMap: map[string]interface{}{
					mediator.Coordination:      &mockroute.MockMediatorSvc{},
					didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
					outofbandsvc.Name:          &mockoutofband.MockService{},
				},
			},
		}
		config.OOBClient = &mockoutofband.MockClient{}

		o, err := New(config)
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
	t.Parallel()
	c, err := New(config(t))
	require.NoError(t, err)

	require.NotEmpty(t, c.GetRESTHandlers())
}

func TestHydraLoginHandlerIterOne(t *testing.T) {
	t.Parallel()
	t.Run("redirects back to hydra", func(t *testing.T) {
		t.Parallel()
		t.Run("with new user connection", func(t *testing.T) {
			t.Parallel()
			tenant := &rp.Tenant{
				ClientID:  uuid.New().String(),
				PublicDID: newDID(t).String(),
				Label:     "test",
			}

			provider := mem.NewProvider()

			rpStore, err := rp.New(provider)
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
					Persistent: provider,
					Transient:  mem.NewProvider(),
				},
				AriesContextProvider: agent(t),
				PresentProofClient:   &mockpresentproof.MockClient{},
				MsgRegistrar:         msghandler.NewRegistrar(),
				AriesMessenger:       &messenger.MockMessenger{},
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			o.hydraLoginHandlerIterOne(w, newHydraLoginRequest(t))
			require.Equal(t, http.StatusFound, w.Code)
			require.Equal(t, w.Header().Get("Location"), redirectURL)
		})
		t.Run("with existing user connection", func(t *testing.T) {
			t.Parallel()
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

			provider := mem.NewProvider()

			rpStore, err := rp.New(provider)
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
					Persistent: provider,
					Transient:  mem.NewProvider(),
				},
				AriesContextProvider: agent(t),
				PresentProofClient:   &mockpresentproof.MockClient{},
				MsgRegistrar:         msghandler.NewRegistrar(),
				AriesMessenger:       &messenger.MockMessenger{},
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			o.hydraLoginHandlerIterOne(w, newHydraLoginRequest(t))
			require.Equal(t, http.StatusFound, w.Code)
			require.Equal(t, w.Header().Get("Location"), redirectURL)
		})
	})
	t.Run("fails on missing login_challenge", func(t *testing.T) {
		t.Parallel()
		o, err := New(config(t))
		require.NoError(t, err)
		r := newHydraRequestNoChallenge(t)
		r.URL.Query().Del("login_challenge")
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandlerIterOne(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("error while fetching hydra login request", func(t *testing.T) {
		t.Parallel()
		o, err := New(&Config{
			Hydra: &stubHydra{
				loginRequestFunc: func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
					return nil, errors.New("test")
				},
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandlerIterOne(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("error while accepting login request at hydra", func(t *testing.T) {
		t.Parallel()
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
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandlerIterOne(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("internal server error on error saving user connection", func(t *testing.T) {
		t.Parallel()
		tenant := &rp.Tenant{
			ClientID:  uuid.New().String(),
			PublicDID: newDID(t).String(),
			Label:     "test",
		}

		mockStore := &mockstorage.Store{}
		provider := &mockstorage.Provider{OpenStoreReturn: mockStore}
		rpStore, err := rp.New(provider)
		require.NoError(t, err)
		err = rpStore.SaveRP(tenant)
		require.NoError(t, err)
		mockStore.ErrPut = errors.New("test")
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
				Persistent: provider,
				Transient:  mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandlerIterOne(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("internal server error if hydra fails to accept login", func(t *testing.T) {
		t.Parallel()
		tenant := &rp.Tenant{
			ClientID:  uuid.New().String(),
			PublicDID: newDID(t).String(),
			Label:     "test",
		}
		store := mem.NewProvider()
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
				Transient:  mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandlerIterOne(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestHydraLoginHandler(t *testing.T) {
	t.Parallel()
	t.Run("TODO - implement redirect to OIDC provider", func(t *testing.T) {
		t.Parallel()
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
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)

		r := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(r, newHydraLoginRequest(t))

		require.Equal(t, http.StatusFound, r.Code)
	})
	t.Run("redirects back to hydra when skipping", func(t *testing.T) {
		t.Parallel()
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
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusFound, w.Code)
		require.Equal(t, w.Header().Get("Location"), redirectURL)
	})
	t.Run("fails on missing login_challenge", func(t *testing.T) {
		t.Parallel()
		o, err := New(config(t))
		require.NoError(t, err)
		r := newHydraRequestNoChallenge(t)
		r.URL.Query().Del("login_challenge")
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("error while fetching hydra login request", func(t *testing.T) {
		t.Parallel()
		o, err := New(&Config{
			Hydra: &stubHydra{
				loginRequestFunc: func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
					return nil, errors.New("test")
				},
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("error while accepting login request at hydra", func(t *testing.T) {
		t.Parallel()
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
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestOidcCallbackHandler(t *testing.T) {
	t.Parallel()
	t.Run("redirects to hydra", func(t *testing.T) {
		t.Parallel()
		const redirectURL = "http://hydra.example.com"
		const state = "123"
		const code = "test_code"
		const clientID = "test_client_id"

		store := mem.NewProvider()
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
				Transient:  mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)

		c.setLoginRequestForState(state, &models.LoginRequest{Client: &models.OAuth2Client{ClientID: clientID}})

		r := &httptest.ResponseRecorder{}
		c.oidcCallbackHandler(r, newOidcCallbackRequest(t, state, code))

		require.Equal(t, http.StatusFound, r.Code)
		require.Equal(t, redirectURL, r.Header().Get("Location"))
	})

	t.Run("bad request on invalid state", func(t *testing.T) {
		t.Parallel()
		c, err := New(config(t))
		require.NoError(t, err)

		r := &httptest.ResponseRecorder{}
		c.oidcCallbackHandler(r, newOidcCallbackRequest(t, "invalid_state", "code"))

		require.Equal(t, http.StatusBadRequest, r.Code)
	})

	t.Run("internal error if exchanging code for id_token fails", func(t *testing.T) {
		t.Parallel()
		c, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{},
			OIDC: func(string, context.Context) (*oidc.IDToken, error) {
				return nil, errors.New("test")
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)

		const state = "123"

		c.setLoginRequestForState(state, &models.LoginRequest{})

		r := &httptest.ResponseRecorder{}
		c.oidcCallbackHandler(r, newOidcCallbackRequest(t, state, "code"))

		require.Equal(t, http.StatusInternalServerError, r.Code)
	})

	t.Run("internal server error if hydra fails to accept login", func(t *testing.T) {
		t.Parallel()
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
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
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
	t.Parallel()
	t.Run("error when fetching rp", func(t *testing.T) {
		t.Parallel()
		clientID := uuid.New().String()
		mockStore := &mockstorage.Store{}
		store := &mockstorage.Provider{OpenStoreReturn: mockStore}
		mockStore.ErrGet = errors.New("test")
		mockStore.ErrPut = errors.New("test")
		c, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{},
			OIDC: func(c string, _ context.Context) (*oidc.IDToken, error) {
				return &oidc.IDToken{Subject: "test"}, nil
			},
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)

		err = c.saveUserAndRequest(
			&models.LoginRequest{Client: &models.OAuth2Client{ClientID: clientID}},
			"sub",
		)
		require.Error(t, err)
	})

	t.Run("error when saving user connection", func(t *testing.T) {
		t.Parallel()
		clientID := uuid.New().String()
		mockStore := &mockstorage.Store{}
		store := &mockstorage.Provider{OpenStoreReturn: mockStore}
		saveRP(t, store, &rp.Tenant{ClientID: clientID})
		mockStore.ErrPut = errors.New("test")
		c, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{},
			OIDC: func(c string, _ context.Context) (*oidc.IDToken, error) {
				return &oidc.IDToken{Subject: "test"}, nil
			},
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
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
	t.Parallel()
	t.Run("requiring user consent", func(t *testing.T) {
		t.Parallel()
		t.Run("redirects to consent ui with handle", func(t *testing.T) {
			t.Parallel()
			uiEndpoint := "http://ui.example.com"
			challenge := uuid.New().String()
			rpClientID := uuid.New().String()
			userSub := uuid.New().String()

			store := mem.NewProvider()
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
					Transient:  mem.NewProvider(),
				},
				AriesContextProvider: agent(t),
				PresentProofClient:   &mockpresentproof.MockClient{},
				MsgRegistrar:         msghandler.NewRegistrar(),
				AriesMessenger:       &messenger.MockMessenger{},
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
			handle := redirectURL.Query().Get("h")
			require.NotEmpty(t, handle)
		})

		t.Run("bad request if consent challenge is missing", func(t *testing.T) {
			t.Parallel()
			c, err := New(config(t))
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraRequestNoChallenge(t))
			require.Equal(t, http.StatusBadRequest, w.Code)
		})

		t.Run("internal server error if hydra fails to deliver consent request details", func(t *testing.T) {
			t.Parallel()
			c, err := New(&Config{
				Hydra: &stubHydra{getConsentRequestFunc: func(*admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
					return nil, errors.New("test")
				}},
				DIDExchClient:        &mockdidexchange.MockClient{},
				Storage:              memStorage(),
				AriesContextProvider: agent(t),
				PresentProofClient:   &mockpresentproof.MockClient{},
				MsgRegistrar:         msghandler.NewRegistrar(),
				AriesMessenger:       &messenger.MockMessenger{},
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, "challenge"))
			require.Equal(t, http.StatusInternalServerError, w.Code)
		})

		t.Run("internal server error if presentation-exchange provider fails", func(t *testing.T) {
			t.Parallel()
			c, err := New(&Config{
				Hydra: &stubHydra{getConsentRequestFunc: func(*admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
					return &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{Skip: false}}, nil
				}},
				PresentationExProvider: &mockPresentationExProvider{createErr: errors.New("test")},
				DIDExchClient:          &mockdidexchange.MockClient{},
				Storage:                memStorage(),
				AriesContextProvider:   agent(t),
				PresentProofClient:     &mockpresentproof.MockClient{},
				MsgRegistrar:           msghandler.NewRegistrar(),
				AriesMessenger:         &messenger.MockMessenger{},
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, "challenge"))
			require.Equal(t, http.StatusInternalServerError, w.Code)
		})

		t.Run("internal server error if cannot find user connection", func(t *testing.T) {
			t.Parallel()
			c, err := New(&Config{
				Hydra: &stubHydra{getConsentRequestFunc: func(*admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
					return &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
						Skip:   false,
						Client: &models.OAuth2Client{},
					}}, nil
				}},
				PresentationExProvider: &mockPresentationExProvider{
					createValue: &presexch.PresentationDefinition{},
				},
				DIDExchClient:        &mockdidexchange.MockClient{},
				Storage:              memStorage(),
				AriesContextProvider: agent(t),
				PresentProofClient:   &mockpresentproof.MockClient{},
				MsgRegistrar:         msghandler.NewRegistrar(),
				AriesMessenger:       &messenger.MockMessenger{},
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, "challenge"))
			require.Equal(t, http.StatusInternalServerError, w.Code)
		})
	})

	t.Run("internal server error on transient store PUT error", func(t *testing.T) {
		t.Parallel()
		uiEndpoint := "http://ui.example.com"
		challenge := uuid.New().String()
		rpClientID := uuid.New().String()
		userSub := uuid.New().String()

		store := &mockstorage.Provider{OpenStoreReturn: &mockstorage.Store{}}
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
					OpenStoreReturn: &mockstorage.Store{ErrPut: errors.New("test")},
				},
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)

		w := &httptest.ResponseRecorder{}
		c.hydraConsentHandler(w, newHydraConsentRequest(t, challenge))

		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("skipping user consent", func(t *testing.T) {
		t.Parallel()
		t.Run("redirects to hydra", func(t *testing.T) {
			t.Parallel()
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
				AriesContextProvider:   agent(t),
				PresentProofClient:     &mockpresentproof.MockClient{},
				MsgRegistrar:           msghandler.NewRegistrar(),
				AriesMessenger:         &messenger.MockMessenger{},
			})
			require.NoError(t, err)

			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, challenge))

			require.Equal(t, http.StatusFound, w.Code)
			require.Equal(t, redirectTo, w.Header().Get("location"))
		})

		t.Run("internal server error if hydra fails to accept consent request", func(t *testing.T) {
			t.Parallel()
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
				AriesContextProvider: agent(t),
				PresentProofClient:   &mockpresentproof.MockClient{},
				MsgRegistrar:         msghandler.NewRegistrar(),
				AriesMessenger:       &messenger.MockMessenger{},
			})
			require.NoError(t, err)

			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, "challenge"))
			require.Equal(t, http.StatusInternalServerError, w.Code)
		})
	})
}

func TestSaveConsentRequest(t *testing.T) {
	t.Parallel()
	t.Run("error if user connection does not exist", func(t *testing.T) {
		t.Parallel()
		c, err := New(config(t))
		require.NoError(t, err)

		err = c.updateUserConnection(&consentRequestCtx{
			CR: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Client: &models.OAuth2Client{},
			}},
		})
		require.Error(t, err)
	})

	t.Run("error when saving user connection", func(t *testing.T) {
		t.Parallel()
		clientID := uuid.New().String()
		userSub := uuid.New().String()
		mockStore := &mockstorage.Store{}
		provider := &mockstorage.Provider{OpenStoreReturn: mockStore}
		saveUserConn(t, provider, &rp.UserConnection{
			User:    &rp.User{Subject: userSub},
			RP:      &rp.Tenant{ClientID: clientID},
			Request: &rp.DataRequest{},
		})
		mockStore.ErrPut = errors.New("test")
		c, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: provider,
				Transient:  mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
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
	t.Parallel()
	t.Run("test success", func(t *testing.T) {
		t.Parallel()
		userSubject := uuid.New().String()
		rpClientID := uuid.New().String()
		rpPublicDID := newDID(t)
		handle := uuid.New().String()
		presDefs := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{{ID: uuid.New().String()}},
		}
		provider := mem.NewProvider()
		saveUserConn(t, provider, &rp.UserConnection{
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
					Services:  []interface{}{rpPublicDID.String()},
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
				Persistent: provider,
				Transient:  mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			GovernanceProvider: &mockgovernance.MockProvider{GetCredentialFunc: func(profileID string) ([]byte, error) {
				return []byte(`{"key":"value"}`), nil
			}},
			MsgRegistrar:   msghandler.NewRegistrar(),
			AriesMessenger: &messenger.MockMessenger{},
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
		require.Len(t, resp.Inv.Services, 1)
		require.Equal(t, rpPublicDID.String(), resp.Inv.Services[0])
		require.Len(t, resp.Credentials, 1)
		require.Equal(t, `{"key":"value"}`, string(resp.Credentials[0]))
	})

	t.Run("test waci success", func(t *testing.T) {
		t.Parallel()
		userSubject := uuid.New().String()
		rpClientID := uuid.New().String()
		rpPublicDID := newDID(t)
		handle := uuid.New().String()
		presDefs := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{{ID: uuid.New().String()}},
		}
		provider := mem.NewProvider()
		saveUserConn(t, provider, &rp.UserConnection{
			User:    &rp.User{Subject: userSubject},
			RP:      &rp.Tenant{ClientID: rpClientID, SupportsWACI: true},
			Request: &rp.DataRequest{},
		})

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{createValue: presDefs},
			OOBClient: &mockoutofband.MockClient{
				CreateInvVal: &outofband.Invitation{
					ID:        uuid.New().String(),
					Type:      outofband.InvitationMsgType,
					Label:     "test-label",
					Services:  []interface{}{rpPublicDID.String()},
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
				Persistent: provider,
				Transient:  mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			GovernanceProvider: &mockgovernance.MockProvider{GetCredentialFunc: func(profileID string) ([]byte, error) {
				return []byte(`{"key":"value"}`), nil
			}},
			MsgRegistrar:   msghandler.NewRegistrar(),
			AriesMessenger: &messenger.MockMessenger{},
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
			RPPublicDID:  rpPublicDID.String(),
			SupportsWACI: true,
		})

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, handle))

		require.Equal(t, http.StatusOK, r.Code)

		var res GetPresentationRequestResponse
		require.NoError(t, json.Unmarshal(r.Body.Bytes(), &res))

		require.True(t, res.WACI)
		require.NotNil(t, res.Inv)
		require.NotEmpty(t, res.Inv.ID)
		require.Len(t, res.Inv.Services, 1)
		require.Equal(t, rpPublicDID.String(), res.Inv.Services[0])
	})

	t.Run("test get governance - failed", func(t *testing.T) {
		t.Parallel()
		userSubject := uuid.New().String()
		rpClientID := uuid.New().String()
		rpPublicDID := newDID(t)
		handle := uuid.New().String()
		presDefs := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{{ID: uuid.New().String()}},
		}
		store := mem.NewProvider()
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
					Services:  []interface{}{rpPublicDID.String()},
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
				Transient:  mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			GovernanceProvider: &mockgovernance.MockProvider{GetCredentialFunc: func(profileID string) ([]byte, error) {
				return nil, fmt.Errorf("failed to get vc")
			}},
			MsgRegistrar:   msghandler.NewRegistrar(),
			AriesMessenger: &messenger.MockMessenger{},
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
		require.Contains(t, r.Body.String(), "error retrieving governance vc : failed to get vc")
	})

	t.Run("bad request if handle is invalid", func(t *testing.T) {
		t.Parallel()
		c, err := New(config(t))
		require.NoError(t, err)

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, "invalid"))

		require.Equal(t, http.StatusBadRequest, r.Code)
	})

	t.Run("bad request if handle is missing", func(t *testing.T) {
		t.Parallel()
		c, err := New(config(t))
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c.getPresentationsRequest(
			w, httptest.NewRequest(http.MethodGet, "http://adapter.example.com/createPresentation", nil))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("internal server error if failed to create didexchange invitation", func(t *testing.T) {
		t.Parallel()
		userSubject := uuid.New().String()
		rpClientID := uuid.New().String()
		rpPublicDID := newDID(t)
		handle := uuid.New().String()
		presDefs := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{{ID: uuid.New().String()}},
		}
		store := mem.NewProvider()
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
				Transient:  mem.NewProvider(),
			},
			DIDExchClient:        &mockdidexchange.MockClient{},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
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
		t.Parallel()
		handle := uuid.New().String()

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{},
			DIDExchClient:          &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: &mockstorage.Provider{
					OpenStoreReturn: &mockstorage.Store{
						ErrGet: errors.New("test"),
					},
				},
				Transient: mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)

		storePut(t, c.transientStore, handle, &consentRequestCtx{
			PD: &presexch.PresentationDefinition{
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
		t.Parallel()
		handle := uuid.New().String()
		userSubject := uuid.New().String()
		rpClientID := uuid.New().String()

		mockStore := &mockstorage.Store{}
		store := &mockstorage.Provider{OpenStoreReturn: mockStore}

		saveUserConn(t, store, &rp.UserConnection{
			User:    &rp.User{Subject: userSubject},
			RP:      &rp.Tenant{ClientID: rpClientID},
			Request: &rp.DataRequest{},
		})

		mockStore.ErrPut = errors.New("test")

		mockStoreReturn, err := mem.NewProvider().OpenStore("mockstorereturn")
		require.NoError(t, err)

		err = mockStoreReturn.Put(handle, marshal(t, &consentRequestCtx{
			PD: &presexch.PresentationDefinition{
				InputDescriptors: []*presexch.InputDescriptor{{ID: uuid.New().String()}},
			},
			CR: &admin.GetConsentRequestOK{
				Payload: &models.ConsentRequest{
					Subject: userSubject,
					Client:  &models.OAuth2Client{ClientID: rpClientID},
				},
			},
			RPPublicDID: newDID(t).String(),
		}))
		require.NoError(t, err)

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{},
			DIDExchClient:          &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient: &mockstorage.Provider{
					OpenStoreReturn: mockStoreReturn,
				},
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, handle))

		require.Equal(t, http.StatusInternalServerError, r.Code)
	})

	t.Run("internal server error on transient store PUT error", func(t *testing.T) {
		t.Parallel()
		handle := uuid.New().String()
		userSubject := uuid.New().String()
		rpClientID := uuid.New().String()

		store := mem.NewProvider()

		saveUserConn(t, store, &rp.UserConnection{
			User:    &rp.User{Subject: userSubject},
			RP:      &rp.Tenant{ClientID: rpClientID},
			Request: &rp.DataRequest{},
		})

		mockStoreReturn, err := mem.NewProvider().OpenStore("mockstorereturn")
		require.NoError(t, err)

		err = mockStoreReturn.Put(handle, marshal(t, &consentRequestCtx{
			PD: &presexch.PresentationDefinition{
				InputDescriptors: []*presexch.InputDescriptor{{ID: uuid.New().String()}},
			},
			CR: &admin.GetConsentRequestOK{
				Payload: &models.ConsentRequest{
					Subject: userSubject,
					Client:  &models.OAuth2Client{ClientID: rpClientID},
				},
			},
			RPPublicDID: newDID(t).String(),
		}))
		require.NoError(t, err)

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{},
			OOBClient:              &mockoutofband.MockClient{CreateInvVal: &outofband.Invitation{}},
			DIDExchClient:          &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient: &mockstorage.Provider{
					OpenStoreReturn: mockStoreReturn,
				},
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, handle))

		require.Equal(t, http.StatusInternalServerError, r.Code)
	})
}

func TestCHAPIResponseHandler(t *testing.T) {
	t.Parallel()

	redirectURL := "http://hydra.example.com/accept"

	t.Run("valid chapi response", func(t *testing.T) {
		t.Parallel()

		relyingParty, subject, issuer := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		subjectDID := newPeerDID(t, subject)
		issuerDID := newPeerDID(t, issuer)
		rpAuthZDID := newPeerDID(t, relyingParty)

		simulateDIDExchange(t, relyingParty, rpDID, subject, subjectDID)

		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		thid := uuid.New().String()
		definitions := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{
				{
					ID: uuid.New().String(),
					Schema: []*presexch.Schema{{
						URI: authorizationCredentialURIID + "#AuthorizationCredential",
					}},
				},
				{
					ID: uuid.New().String(),
					Schema: []*presexch.Schema{{
						URI: "https://example.org/examples#UniversityDegreeCredential",
					}},
				},
			},
		}
		authz := newAuthorizationVC(t, subjectDID.ID, rpAuthZDID, issuerDID)
		degree := newUniversityDegreeVC(t, issuer, issuerDID)
		vp := newPresentationSubmissionVP(t,
			subject,
			subjectDID,
			&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{
				{
					ID:   definitions.InputDescriptors[0].ID,
					Path: "$.verifiableCredential[0]",
				},
				{
					ID:   definitions.InputDescriptors[1].ID,
					Path: "$.verifiableCredential[1]",
				},
			}},
			authz, degree)
		requestPresentationSent := make(chan struct{})

		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesContextProvider: relyingParty,
			PresentProofClient: &mockpresentproof.MockClient{
				RegisterActionFunc: func(c chan<- service.DIDCommAction) error {
					return nil
				},
				RequestPresentationFunc: func(request *presentproof.RequestPresentation, myDID, theirDID string) (string, error) {
					require.Equal(t, rpAuthZDID.ID, myDID)
					require.Equal(t, issuerDID.ID, theirDID)
					require.Len(t, request.RequestPresentationsAttach, 1)
					checkPresentationDefinitionAttachment(t, authz, request)

					go func() { requestPresentationSent <- struct{}{} }()

					return thid, nil
				},
			},
			Hydra: &stubHydra{
				acceptConsentRequestFunc: func(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
					return &admin.AcceptConsentRequestOK{Payload: &models.CompletedRequest{RedirectTo: redirectURL}}, nil
				},
			},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
			JSONLDDocumentLoader: testutil.DocumentLoader(t),
		})
		require.NoError(t, err)

		rpWalletConnID := uuid.New().String()

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{
			InvitationID:  invitationID,
			PD:            definitions,
			CR:            &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{Challenge: uuid.New().String()}},
			UserDID:       subjectDID.ID,
			RPPublicDID:   rpPublicDID,
			RPPairwiseDID: rpDID.ID,
			ConnectionID:  rpWalletConnID,
		})

		err = c.transientStore.Put(getConnectionToAuthZDIDMappingDBKey(rpWalletConnID), []byte(rpAuthZDID.ID))
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusAccepted, w.Code)

		select {
		case <-requestPresentationSent:
		case <-time.After(time.Second):
			t.Fatalf("timeout while waiting for request-presentation to be sent")
		}
	})

	t.Run("bad request if body is malformed", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c.chapiResponseHandler(w,
			httptest.NewRequest(http.MethodPost, "/dummy", bytes.NewReader([]byte("invalid"))))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if invitationID is invalid", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c.chapiResponseHandler(w, newCHAPIResponse(t, "test", &verifiable.Presentation{}))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if verifiable presentation is invalid", func(t *testing.T) {
		t.Parallel()

		invitationID := uuid.New().String()
		c, err := New(config(t))
		require.NoError(t, err)

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{InvitationID: invitationID})

		w := httptest.NewRecorder()
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, &verifiable.Presentation{}))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if issuer did doc is malformed", func(t *testing.T) {
		t.Parallel()

		relyingParty, subject, _ := trio(t)
		rpPublicDID := newDID(t).String()
		rpDID := newPeerDID(t, relyingParty)
		subjectDID := newPeerDID(t, subject)

		simulateDIDExchange(t, relyingParty, rpDID, subject, subjectDID)

		invitationID := uuid.New().String()
		invalid := newPeerDID(t, agent(t))

		invalid.Context = nil
		invalid.Service = nil
		invalid.VerificationMethod = nil

		definitions := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*presexch.Schema{{
					URI: authorizationCredentialURIID, // TODO (Filip): https://example.org/examples ??
				}},
			}},
		}

		vp := newPresentationSubmissionVP(t,
			subject,
			subjectDID,
			&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{{
				ID:   definitions.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newAuthorizationVC(t, subjectDID.ID, rpDID, invalid))

		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesContextProvider: relyingParty,
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
			JSONLDDocumentLoader: testutil.DocumentLoader(t),
		})
		require.NoError(t, err)

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{
			InvitationID:  invitationID,
			RPPublicDID:   rpPublicDID,
			RPPairwiseDID: rpDID.ID,
			PD:            definitions,
		})

		w := &httptest.ResponseRecorder{}
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("internal server error if error creating didcomm connection", func(t *testing.T) {
		t.Parallel()

		relyingParty, subject, _ := trio(t)
		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		rpPeerDID := newPeerDID(t, relyingParty)
		subjectDID := newPeerDID(t, subject)
		issuerDID := newPeerDID(t, agent(t))

		simulateDIDExchange(t, relyingParty, rpPeerDID, subject, subjectDID)

		definitions := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*presexch.Schema{{
					URI: authorizationCredentialURIID + "#" + vc.AuthorizationCredentialType,
				}},
			}},
		}
		vp := newPresentationSubmissionVP(t,
			subject,
			subjectDID,
			&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{{
				ID:   definitions.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newAuthorizationVC(t, subjectDID.ID, rpPeerDID, issuerDID))

		c, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{
				CreateConnectionFunc: func(string, *did.Doc, ...didexchange.ConnectionOption) (string, error) {
					return "", errors.New("test")
				},
			},
			Storage:              memStorage(),
			AriesContextProvider: relyingParty,
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
			JSONLDDocumentLoader: testutil.DocumentLoader(t),
		})
		require.NoError(t, err)

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{
			InvitationID:  invitationID,
			RPPublicDID:   rpPublicDID,
			RPPairwiseDID: rpPeerDID.ID,
			PD:            definitions,
		})

		w := &httptest.ResponseRecorder{}
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("rp authz did validation error", func(t *testing.T) {
		t.Parallel()

		relyingParty, subject, issuer := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		subjectDID := newPeerDID(t, subject)
		issuerDID := newPeerDID(t, issuer)
		rpAuthZDID := newPeerDID(t, relyingParty)

		simulateDIDExchange(t, relyingParty, rpDID, subject, subjectDID)

		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		thid := uuid.New().String()
		definitions := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{
				{
					ID: uuid.New().String(),
					Schema: []*presexch.Schema{{
						URI: authorizationCredentialURIID + "#" + vc.AuthorizationCredentialType,
					}},
				},
				{
					ID: uuid.New().String(),
					Schema: []*presexch.Schema{{
						URI: "https://example.org/examples#UniversityDegreeCredential",
					}},
				},
			},
		}
		authz := newAuthorizationVC(t, subjectDID.ID, rpAuthZDID, issuerDID)
		degree := newUniversityDegreeVC(t, issuer, issuerDID)
		vp := newPresentationSubmissionVP(t,
			subject,
			subjectDID,
			&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{
				{
					ID:   definitions.InputDescriptors[0].ID,
					Path: "$.verifiableCredential[0]",
				},
				{
					ID:   definitions.InputDescriptors[1].ID,
					Path: "$.verifiableCredential[1]",
				},
			}},
			authz, degree)
		requestPresentationSent := make(chan struct{})

		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesContextProvider: relyingParty,
			PresentProofClient: &mockpresentproof.MockClient{
				RegisterActionFunc: func(c chan<- service.DIDCommAction) error {
					return nil
				},
				RequestPresentationFunc: func(request *presentproof.RequestPresentation, myDID, theirDID string) (string, error) {
					require.Equal(t, rpAuthZDID.ID, myDID)
					require.Equal(t, issuerDID.ID, theirDID)
					require.Len(t, request.RequestPresentationsAttach, 1)
					checkPresentationDefinitionAttachment(t, authz, request)

					go func() { requestPresentationSent <- struct{}{} }()

					return thid, nil
				},
			},
			Hydra: &stubHydra{
				acceptConsentRequestFunc: func(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
					return &admin.AcceptConsentRequestOK{Payload: &models.CompletedRequest{RedirectTo: redirectURL}}, nil
				},
			},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
			JSONLDDocumentLoader: testutil.DocumentLoader(t),
		})
		require.NoError(t, err)

		rpWalletConnID := uuid.New().String()

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{
			InvitationID:  invitationID,
			PD:            definitions,
			CR:            &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{Challenge: uuid.New().String()}},
			UserDID:       subjectDID.ID,
			RPPublicDID:   rpPublicDID,
			RPPairwiseDID: rpDID.ID,
			ConnectionID:  rpWalletConnID,
		})

		// no conn to rpAuthZ mapping
		w := httptest.NewRecorder()
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusInternalServerError, w.Code)

		// conn authz did doesnt match to the did in authz credential
		err = c.transientStore.Put(rpWalletConnID, []byte("invalid"))
		require.NoError(t, err)
		w = httptest.NewRecorder()
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error if cannot send request-presentation", func(t *testing.T) {
		t.Parallel()

		relyingParty, subject, _ := trio(t)
		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		rpPeerDID := newPeerDID(t, relyingParty)
		subjectDID := newPeerDID(t, subject)
		issuerDID := newPeerDID(t, agent(t))

		simulateDIDExchange(t, relyingParty, rpPeerDID, subject, subjectDID)

		definitions := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*presexch.Schema{{
					URI: authorizationCredentialURIID + "#" + vc.AuthorizationCredentialType,
				}},
			}},
		}
		vp := newPresentationSubmissionVP(t,
			subject,
			subjectDID,
			&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{{
				ID:   definitions.InputDescriptors[0].ID,
				Path: "$.verifiableCredential[0]",
			}}},
			newAuthorizationVC(t, subjectDID.ID, rpPeerDID, issuerDID))

		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesContextProvider: relyingParty,
			PresentProofClient: &mockpresentproof.MockClient{
				RequestPresentationFunc: func(*presentproof.RequestPresentation, string, string) (string, error) {
					return "", errors.New("test")
				},
			},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
			JSONLDDocumentLoader: testutil.DocumentLoader(t),
		})
		require.NoError(t, err)

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{
			InvitationID:  invitationID,
			RPPublicDID:   rpPublicDID,
			RPPairwiseDID: rpPeerDID.ID,
			PD:            definitions,
		})

		w := &httptest.ResponseRecorder{}
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error if cannot update consent request context in transient storage", func(t *testing.T) {
		t.Parallel()

		relyingParty, subject, issuer := trio(t)
		invitationID := uuid.New().String()
		rpPublicDID := newDID(t).String()
		rpPeerDID := newPeerDID(t, relyingParty)
		issuerDID := newPeerDID(t, issuer)
		subjectDID := newPeerDID(t, subject)

		simulateDIDExchange(t, relyingParty, rpPeerDID, subject, subjectDID)

		thid := uuid.New().String()
		definitions := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{
				{
					ID: uuid.New().String(),
					Schema: []*presexch.Schema{{
						URI: authorizationCredentialURIID + "#" + vc.AuthorizationCredentialType,
					}},
				},
				{
					ID: uuid.New().String(),
					Schema: []*presexch.Schema{{
						URI: "https://example.org/examples#UniversityDegreeCredential",
					}},
				},
			},
		}
		authz := newAuthorizationVC(t, subjectDID.ID, rpPeerDID, issuerDID)
		degree := newUniversityDegreeVC(t, issuer, issuerDID)
		vp := newPresentationSubmissionVP(t,
			subject,
			subjectDID,
			&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{
				{
					ID:   definitions.InputDescriptors[0].ID,
					Path: "$.verifiableCredential[0]",
				},
				{
					ID:   definitions.InputDescriptors[1].ID,
					Path: "$.verifiableCredential[1]",
				},
			}},
			authz, degree)

		mockStorage := memStorage()

		mockStorage.Transient = &mockstorage.Provider{
			OpenStoreReturn: &mockstorage.Store{
				GetReturn: marshal(t, &consentRequestCtx{
					InvitationID: invitationID,
					PD:           definitions,
					CR: &admin.GetConsentRequestOK{
						Payload: &models.ConsentRequest{Challenge: uuid.New().String()},
					},
					UserDID:       subjectDID.ID,
					RPPublicDID:   rpPublicDID,
					RPPairwiseDID: rpPeerDID.ID,
				}),
				ErrPut: errors.New("test"),
			},
		}

		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              mockStorage,
			AriesContextProvider: relyingParty,
			PresentProofClient: &mockpresentproof.MockClient{
				RequestPresentationFunc: func(request *presentproof.RequestPresentation, myDID, theirDID string) (string, error) {
					return thid, nil
				},
			},
			Hydra: &stubHydra{
				acceptConsentRequestFunc: func(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
					return &admin.AcceptConsentRequestOK{
						Payload: &models.CompletedRequest{RedirectTo: "http://hydra.example.com/accept"},
					}, nil
				},
			},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
			JSONLDDocumentLoader: testutil.DocumentLoader(t),
		})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c.chapiResponseHandler(w, newCHAPIResponse(t, invitationID, vp))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestToMarshalledVP(t *testing.T) {
	t.Parallel()

	t.Run("error if cannot resolve rp tenant's DID", func(t *testing.T) {
		t.Parallel()

		relyingParty, issuer, subject := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		issuerDID := newPeerDID(t, issuer)
		subjectDID := newPeerDID(t, subject)

		o, err := New(config(t))
		require.NoError(t, err)

		authZ := newAuthorizationVC(t, subjectDID.ID, rpDID, issuerDID)

		_, err = o.toMarshalledVP(authZ, newPeerDID(t, agent(t)).ID)
		require.Error(t, err)
	})

	t.Run("error if rp tenant's DID does not declare an authentication method", func(t *testing.T) {
		t.Parallel()

		relyingParty, issuer, subject := trio(t)
		issuerDID := newPeerDID(t, issuer)
		subjectDID := newPeerDID(t, subject)
		rpDID := newPeerDID(t, agent(t))
		rpDID.Authentication = nil
		_, err := relyingParty.VDRegistry().Create(peer.DIDMethod, rpDID, vdrapi.WithOption("store", true))
		require.NoError(t, err)

		o, err := New(config(t))
		require.NoError(t, err)

		authZ := newAuthorizationVC(t, subjectDID.ID, rpDID, issuerDID)

		_, err = o.toMarshalledVP(authZ, rpDID.ID)
		require.Error(t, err)
	})
}

func TestGetPresentationResponseResultHandler(t *testing.T) {
	t.Parallel()

	t.Run("returns redirectURL if user data has been collected", func(t *testing.T) {
		t.Parallel()

		relyingParty, issuer, _ := trio(t)
		issuerDID := newPeerDID(t, issuer)
		redirectURL := "http://hydra.example.com/accept"
		invitationID := uuid.New().String()
		thid := uuid.New().String()

		local := map[string][]byte{
			uuid.New().String(): marshal(t, newUniversityDegreeVC(t, issuer, issuerDID)),
		}

		remote := map[string]string{
			uuid.New().String(): thid,
		}

		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesContextProvider: relyingParty,
			PresentProofClient:   &mockpresentproof.MockClient{},
			Hydra: &stubHydra{
				acceptConsentRequestFunc: func(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
					return &admin.AcceptConsentRequestOK{Payload: &models.CompletedRequest{RedirectTo: redirectURL}}, nil
				},
			},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
			JSONLDDocumentLoader: testutil.DocumentLoader(t),
		})
		require.NoError(t, err)

		storePut(t, o.transientStore, invitationID, &consentRequestCtx{
			InvitationID: invitationID,
			CR: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Challenge:                    uuid.New().String(),
				RequestedAccessTokenAudience: []string{uuid.New().String()},
				RequestedScope:               []string{uuid.New().String()},
			}},
			UserData: &userDataCollection{
				Local:  local,
				Remote: remote,
			},
		})

		// simulate response from remote issuer
		storePut(t, o.transientStore, thid, newCreditCardStatementVC(t, issuer, issuerDID))

		w := httptest.NewRecorder()
		o.getPresentationResponseResultHandler(w, newGetPresentationResponseResult(invitationID))

		require.Equal(t, http.StatusOK, w.Code)

		result := &HandleCHAPIResponseResult{}

		err = json.NewDecoder(w.Body).Decode(result)
		require.NoError(t, err)

		require.Equal(t, redirectURL, result.RedirectURL)
	})

	t.Run("bad request error if handle query param is missing", func(t *testing.T) {
		t.Parallel()

		o, err := New(config(t))
		require.NoError(t, err)

		w := httptest.NewRecorder()
		o.getPresentationResponseResultHandler(w, httptest.NewRequest(http.MethodGet, "/dummy", nil))

		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request error if handle is invalid", func(t *testing.T) {
		t.Parallel()

		o, err := New(config(t))
		require.NoError(t, err)

		w := httptest.NewRecorder()
		o.getPresentationResponseResultHandler(w, newGetPresentationResponseResult(uuid.New().String()))

		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("internal server error if remote threadID not found", func(t *testing.T) {
		t.Parallel()

		issuer := agent(t)
		issuerDID := newPeerDID(t, issuer)
		invitationID := uuid.New().String()
		thid := uuid.New().String()

		local := map[string][]byte{
			uuid.New().String(): marshal(t, newUniversityDegreeVC(t, issuer, issuerDID)),
		}

		remote := map[string]string{
			uuid.New().String(): thid,
		}

		o, err := New(config(t))
		require.NoError(t, err)

		storePut(t, o.transientStore, invitationID, &consentRequestCtx{
			InvitationID: invitationID,
			UserData: &userDataCollection{
				Local:  local,
				Remote: remote,
			},
		})

		// simulate response from remote issuer
		storePut(t, o.transientStore, uuid.New().String(), newCreditCardStatementVC(t, issuer, issuerDID))

		w := httptest.NewRecorder()
		o.getPresentationResponseResultHandler(w, newGetPresentationResponseResult(invitationID))

		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error if cannot parse local credential", func(t *testing.T) {
		t.Parallel()

		invitationID := uuid.New().String()
		thid := uuid.New().String()

		local := map[string][]byte{
			uuid.New().String(): []byte("{INVALID"),
		}

		remote := map[string]string{
			uuid.New().String(): thid,
		}

		o, err := New(config(t))
		require.NoError(t, err)

		storePut(t, o.transientStore, invitationID, &consentRequestCtx{
			InvitationID: invitationID,
			UserData: &userDataCollection{
				Local:  local,
				Remote: remote,
			},
		})

		// simulate response from remote issuer
		issuer := agent(t)
		issuerDID := newPeerDID(t, issuer)
		storePut(t, o.transientStore, thid, newCreditCardStatementVC(t, issuer, issuerDID))

		w := httptest.NewRecorder()
		o.getPresentationResponseResultHandler(w, newGetPresentationResponseResult(invitationID))

		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("internal server error if cannot parse remote credential", func(t *testing.T) {
		t.Parallel()

		issuer := agent(t)
		issuerDID := newPeerDID(t, issuer)
		invitationID := uuid.New().String()
		thid := uuid.New().String()

		local := map[string][]byte{
			uuid.New().String(): marshal(t, newUniversityDegreeVC(t, issuer, issuerDID)),
		}

		remote := map[string]string{
			uuid.New().String(): thid,
		}

		o, err := New(config(t))
		require.NoError(t, err)

		storePut(t, o.transientStore, invitationID, &consentRequestCtx{
			InvitationID: invitationID,
			UserData: &userDataCollection{
				Local:  local,
				Remote: remote,
			},
		})

		// simulate response from remote issuer
		remoteVC := newCreditCardStatementVC(t, issuer, issuerDID)
		remoteVC.Types = nil
		remoteVC.Context = nil
		storePut(t, o.transientStore, thid, remoteVC)

		w := httptest.NewRecorder()
		o.getPresentationResponseResultHandler(w, newGetPresentationResponseResult(invitationID))

		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("bad gateway error if hydra fails to accept consent", func(t *testing.T) {
		t.Parallel()

		relyingParty, issuer, _ := trio(t)
		issuerDID := newPeerDID(t, issuer)
		invitationID := uuid.New().String()
		thid := uuid.New().String()

		local := map[string][]byte{
			uuid.New().String(): marshal(t, newUniversityDegreeVC(t, issuer, issuerDID)),
		}

		remote := map[string]string{
			uuid.New().String(): thid,
		}

		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesContextProvider: relyingParty,
			PresentProofClient:   &mockpresentproof.MockClient{},
			Hydra: &stubHydra{
				acceptConsentRequestFunc: func(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
					return nil, errors.New("test")
				},
			},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
			JSONLDDocumentLoader: testutil.DocumentLoader(t),
		})
		require.NoError(t, err)

		storePut(t, o.transientStore, invitationID, &consentRequestCtx{
			InvitationID: invitationID,
			CR: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Challenge:                    uuid.New().String(),
				RequestedAccessTokenAudience: []string{uuid.New().String()},
				RequestedScope:               []string{uuid.New().String()},
			}},
			UserData: &userDataCollection{
				Local:  local,
				Remote: remote,
			},
		})

		// simulate response from remote issuer
		storePut(t, o.transientStore, thid, newCreditCardStatementVC(t, issuer, issuerDID))

		w := httptest.NewRecorder()
		o.getPresentationResponseResultHandler(w, newGetPresentationResponseResult(invitationID))

		require.Equal(t, http.StatusBadGateway, w.Code)
	})
}

func TestHandleIssuerPresentationMsg(t *testing.T) {
	t.Parallel()

	t.Run("valid response", func(t *testing.T) {
		t.Parallel()

		relyingParty, issuer, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		issuerDID := newPeerDID(t, issuer)

		simulateDIDExchange(t, relyingParty, rpDID, issuer, issuerDID)

		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesContextProvider: relyingParty,
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
			JSONLDDocumentLoader: testutil.DocumentLoader(t),
		})
		require.NoError(t, err)

		thid := uuid.New().String()
		expected := newCreditCardStatementVC(t, issuer, issuerDID)

		err = o.handleIssuerPresentationMsg(
			newIssuerResponse(t, thid, newPresentationSubmissionVP(t, issuer, issuerDID, nil, expected)))
		require.NoError(t, err)

		bits, err := o.transientStore.Get(thid)
		require.NoError(t, err)

		actual, err := verifiable.ParseCredential(
			bits,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
		)
		require.NoError(t, err)

		require.Equal(t, expected.ID, actual.ID)
	})

	t.Run("error if invalid threadID", func(t *testing.T) {
		t.Parallel()

		o, err := New(config(t))
		require.NoError(t, err)

		err = o.handleIssuerPresentationMsg(service.NewDIDCommMsgMap(&presentproof.Presentation{}))
		require.Error(t, err)
	})

	t.Run("error on invalid presentation response", func(t *testing.T) {
		t.Parallel()

		o, err := New(config(t))
		require.NoError(t, err)
		thid := uuid.New().String()
		msg := service.NewDIDCommMsgMap(&presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{},
		})
		err = msg.SetID(thid)
		require.NoError(t, err)

		err = o.handleIssuerPresentationMsg(msg)
		require.Error(t, err)
	})

	t.Run("error fetching attachment contents", func(t *testing.T) {
		t.Parallel()

		o, err := New(config(t))
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

		err = o.handleIssuerPresentationMsg(msg)
		require.Error(t, err)
	})

	t.Run("error if response attachment contains an unparseable VP", func(t *testing.T) {
		t.Parallel()

		o, err := New(config(t))
		require.NoError(t, err)

		thid := uuid.New().String()

		err = o.handleIssuerPresentationMsg(newIssuerResponse(t, thid, map[string]interface{}{}))
		require.Error(t, err)
		require.True(t, errors.Is(err, errInvalidCredential))
	})

	t.Run("error on transient store PUT error", func(t *testing.T) {
		t.Parallel()

		issuer := agent(t)
		issuerDID := newPeerDID(t, issuer)

		mockStorage := memStorage()
		mockStorage.Transient = &mockstorage.Provider{
			OpenStoreReturn: &mockstorage.Store{
				ErrPut: errors.New("test"),
			},
		}

		o, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              mockStorage,
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)

		thid := uuid.New().String()
		expected := newCreditCardStatementVC(t, issuer, issuerDID)

		err = o.handleIssuerPresentationMsg(
			newIssuerResponse(t, thid, newPresentationSubmissionVP(t, issuer, issuerDID, nil, expected)))
		require.Error(t, err)
	})
}

func TestUserInfoHandler(t *testing.T) {
	t.Parallel()

	c, err := New(config(t))
	require.NoError(t, err)

	r := &httptest.ResponseRecorder{}
	c.userInfoHandler(r, nil)

	require.Equal(t, http.StatusOK, r.Code)
}

func TestTestResponse(t *testing.T) {
	t.Parallel()

	t.Run("error", func(t *testing.T) {
		t.Parallel()

		testResponse(&stubWriter{})
	})
}

func TestCreateRPTenant(t *testing.T) {
	t.Parallel()

	t.Run("creates valid tenant", func(t *testing.T) {
		t.Parallel()

		callback := "http://test.example.com"
		expected := &rp.Tenant{
			ClientID:             uuid.New().String(),
			PublicDID:            newDID(t).String(),
			Label:                "test label",
			Scopes:               []string{creditCardStatementScope},
			RequiresBlindedRoute: true,
			SupportsWACI:         true,
		}
		clientSecret := uuid.New().String()

		store := mem.NewProvider()
		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
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
			GovernanceProvider: &mockgovernance.MockProvider{},
			MsgRegistrar:       msghandler.NewRegistrar(),
			AriesMessenger:     &messenger.MockMessenger{},
		})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label:                expected.Label,
			Callback:             callback,
			Scopes:               []string{creditCardStatementScope},
			RequiresBlindedRoute: true,
			SupportsWACI:         true,
		}))
		require.Equal(t, http.StatusCreated, w.Code)
		response := &CreateRPTenantResponse{}
		err = json.NewDecoder(w.Body).Decode(response)
		require.NoError(t, err)
		require.Equal(t, expected.ClientID, response.ClientID)
		require.Equal(t, expected.PublicDID, response.PublicDID)
		require.Equal(t, expected.Scopes, response.Scopes)
		require.Equal(t, clientSecret, response.ClientSecret)
		require.Equal(t, expected.RequiresBlindedRoute, response.RequiresBlindedRoute)
		require.Equal(t, expected.SupportsWACI, response.SupportsWACI)

		rpStore, err := rp.New(store)
		require.NoError(t, err)
		result, err := rpStore.GetRP(expected.ClientID)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("bad request", func(t *testing.T) {
		t.Parallel()

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
				AriesContextProvider: agent(t),
				Hydra: &stubHydra{
					createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
						return &admin.CreateOAuth2ClientCreated{Payload: &models.OAuth2Client{}}, nil
					},
				},
				PublicDIDCreator:   &stubPublicDIDCreator{createValue: &did.Doc{}},
				PresentProofClient: &mockpresentproof.MockClient{},
				MsgRegistrar:       msghandler.NewRegistrar(),
				AriesMessenger:     &messenger.MockMessenger{},
			})
			require.NoError(t, err)

			w := httptest.NewRecorder()
			o.createRPTenant(w, test.request)
			require.Equal(t, http.StatusBadRequest, w.Code, test.desc)
		}
	})

	t.Run("internal server error rp already exists", func(t *testing.T) {
		t.Parallel()

		existing := &rp.Tenant{
			ClientID:  uuid.New().String(),
			PublicDID: newDID(t).String(),
			Label:     uuid.New().String(),
		}
		store := mem.NewProvider()
		rpStore, err := rp.New(store)
		require.NoError(t, err)
		err = rpStore.SaveRP(existing)
		require.NoError(t, err)
		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{ClientID: existing.ClientID},
					}, nil
				},
			},
			PresentProofClient: &mockpresentproof.MockClient{},
			MsgRegistrar:       msghandler.NewRegistrar(),
			AriesMessenger:     &messenger.MockMessenger{},
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
		t.Parallel()

		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: &stubStorageProvider{
					storeGetErr: errors.New("generic"),
				},
				Transient: mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{},
					}, nil
				},
			},
			PresentProofClient: &mockpresentproof.MockClient{},
			MsgRegistrar:       msghandler.NewRegistrar(),
			AriesMessenger:     &messenger.MockMessenger{},
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
		t.Parallel()

		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: &stubStorageProvider{
					storeGetErr: storage.ErrDataNotFound,
					storePutErr: errors.New("generic"),
				},
				Transient: mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{},
					}, nil
				},
			},
			PublicDIDCreator:   &stubPublicDIDCreator{createValue: &did.Doc{}},
			PresentProofClient: &mockpresentproof.MockClient{},
			MsgRegistrar:       msghandler.NewRegistrar(),
			AriesMessenger:     &messenger.MockMessenger{},
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
		t.Parallel()

		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: &stubStorageProvider{
					storeGetErr: storage.ErrDataNotFound,
				},
				Transient: mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return nil, errors.New("test")
				},
			},
			PresentProofClient: &mockpresentproof.MockClient{},
			MsgRegistrar:       msghandler.NewRegistrar(),
			AriesMessenger:     &messenger.MockMessenger{},
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
		t.Parallel()

		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: &stubStorageProvider{
					storeGetErr: storage.ErrDataNotFound,
					storePutErr: errors.New("generic"),
				},
				Transient: mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
			Hydra: &stubHydra{
				createOauth2ClientFunc: func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
					return &admin.CreateOAuth2ClientCreated{
						Payload: &models.OAuth2Client{},
					}, nil
				},
			},
			PublicDIDCreator:   &stubPublicDIDCreator{createErr: errors.New("test")},
			PresentProofClient: &mockpresentproof.MockClient{},
			MsgRegistrar:       msghandler.NewRegistrar(),
			AriesMessenger:     &messenger.MockMessenger{},
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

	t.Run("failed to issue governance vc", func(t *testing.T) {
		t.Parallel()

		callback := "http://test.example.com"
		expected := &rp.Tenant{
			ClientID:  uuid.New().String(),
			PublicDID: newDID(t).String(),
			Label:     "test label",
			Scopes:    []string{creditCardStatementScope},
		}
		clientSecret := uuid.New().String()

		store := mem.NewProvider()
		o, err := New(&Config{
			DIDExchClient: &mockdidexchange.MockClient{},
			Storage: &Storage{
				Persistent: store,
				Transient:  mem.NewProvider(),
			},
			AriesContextProvider: agent(t),
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
			GovernanceProvider: &mockgovernance.MockProvider{
				IssueCredentialFunc: func(didID, profileID string) ([]byte, error) {
					return nil, fmt.Errorf("failed to issue governance vc")
				},
			},
			MsgRegistrar:   msghandler.NewRegistrar(),
			AriesMessenger: &messenger.MockMessenger{},
		})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		o.createRPTenant(w, newCreateRPRequest(t, &CreateRPTenantRequest{
			Label:    expected.Label,
			Callback: callback,
			Scopes:   []string{creditCardStatementScope},
		}))
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Contains(t, w.Body.String(), "failed to issue governance vc")
	})
}

func TestRemoveOIDCScope(t *testing.T) {
	t.Parallel()

	t.Run("removes oidc scope", func(t *testing.T) {
		t.Parallel()

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

func TestHandlePresentProofMsg(t *testing.T) { // nolint: gocyclo,cyclop
	t.Parallel()

	t.Run("unsupported message type", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		actionCh := make(chan service.DIDCommAction, 1)

		done := make(chan struct{})

		go c.presentProofListener(actionCh)

		actionCh <- service.DIDCommAction{
			Message: service.NewDIDCommMsgMap(struct {
				Type string `json:"@type,omitempty"`
			}{Type: "unsupported-message-type"}),
			Stop: func(err error) {
				require.Contains(t, err.Error(), "unsupported present-proof message : unsupported-message-type")
				done <- struct{}{}
			},
		}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("issuer presentation message - success", func(t *testing.T) {
		t.Parallel()

		relyingParty, issuer, _ := trio(t)
		rpDID := newPeerDID(t, relyingParty)
		issuerDID := newPeerDID(t, issuer)

		simulateDIDExchange(t, relyingParty, rpDID, issuer, issuerDID)

		c, err := New(&Config{
			DIDExchClient:        &mockdidexchange.MockClient{},
			Storage:              memStorage(),
			AriesContextProvider: relyingParty,
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
			JSONLDDocumentLoader: testutil.DocumentLoader(t),
		})
		require.NoError(t, err)

		rpClientID := uuid.NewString()
		err = c.rpStore.SaveRP(&rp.Tenant{ClientID: rpClientID, SupportsWACI: false})
		require.NoError(t, err)

		connID := uuid.New().String()
		c.connections = &mockconn.MockConnectionsLookup{ConnIDByDIDs: connID}

		err = c.persistenceStore.Put(getConnToTenantMappingDBKey(connID), []byte(rpClientID))
		require.NoError(t, err)

		actionCh := make(chan service.DIDCommAction, 1)

		done := make(chan struct{})

		go c.presentProofListener(actionCh)

		expected := newCreditCardStatementVC(t, issuer, issuerDID)

		actionCh <- service.DIDCommAction{
			Message: newIssuerResponse(t, uuid.NewString(), newPresentationSubmissionVP(t, issuer, issuerDID, nil, expected)),
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

	t.Run("waci presentation message - success", func(t *testing.T) {
		t.Parallel()
		_, issuer, _ := trio(t)
		issuerDID := newPeerDID(t, issuer)

		c, err := New(config(t))
		require.NoError(t, err)

		rpClientID := uuid.NewString()
		err = c.rpStore.SaveRP(&rp.Tenant{ClientID: rpClientID, SupportsWACI: true})
		require.NoError(t, err)

		connID := uuid.New().String()
		c.connections = &mockconn.MockConnectionsLookup{ConnIDByDIDs: connID}

		err = c.persistenceStore.Put(getConnToTenantMappingDBKey(connID), []byte(rpClientID))
		require.NoError(t, err)

		invitationID := uuid.New().String()

		definitions := &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{
				{
					ID: uuid.New().String(),
					Schema: []*presexch.Schema{{
						URI: "https://example.org/examples#CreditCardStatement",
					}},
				},
			},
		}

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{InvitationID: invitationID, PD: definitions})

		err = c.persistenceStore.Put(getConnToCtxMappingDBKey(connID), []byte(invitationID))
		require.NoError(t, err)

		actionCh := make(chan service.DIDCommAction, 1)

		done := make(chan struct{})

		go c.presentProofListener(actionCh)

		actionCh <- service.DIDCommAction{
			Message: newIssuerResponse(t, invitationID,
				newPresentationSubmissionVP(t, issuer, issuerDID,
					&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{
						{
							ID:   definitions.InputDescriptors[0].ID,
							Path: "$.verifiableCredential[0]",
						},
					}}, newCreditCardStatementVC(t, issuer, issuerDID),
				),
			),
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

	t.Run("presentation message - invalid connid", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		actionCh := make(chan service.DIDCommAction, 1)

		done := make(chan struct{})

		go c.presentProofListener(actionCh)

		actionCh <- service.DIDCommAction{
			Message: service.NewDIDCommMsgMap(&presentproof.Presentation{
				Type: presentproofsvc.PresentationMsgType,
			}),
			Stop: func(err error) {
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

	t.Run("handle propose message - success", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		invitationID := uuid.New().String()

		storePut(t, c.transientStore, invitationID, &consentRequestCtx{InvitationID: invitationID})

		connID := uuid.New().String()
		c.connections = &mockconn.MockConnectionsLookup{ConnIDByDIDs: connID}

		err = c.persistenceStore.Put(getConnToCtxMappingDBKey(connID), []byte(invitationID))
		require.NoError(t, err)

		actionCh := make(chan service.DIDCommAction, 1)

		done := make(chan struct{})

		go c.presentProofListener(actionCh)

		actionCh <- service.DIDCommAction{
			Message: service.NewDIDCommMsgMap(struct {
				Type string `json:"@type,omitempty"`
			}{Type: presentproofsvc.ProposePresentationMsgType}),
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

	t.Run("handle propose message error", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		actionCh := make(chan service.DIDCommAction, 1)

		done := make(chan struct{})

		go c.presentProofListener(actionCh)

		actionCh <- service.DIDCommAction{
			Message: service.NewDIDCommMsgMap(struct {
				Type string `json:"@type,omitempty"`
			}{Type: presentproofsvc.ProposePresentationMsgType}),
			Stop: func(err error) {
				require.Contains(t, err.Error(), "get connection id from event")
				done <- struct{}{}
			},
		}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})
}

func TestDIDDocReq(t *testing.T) { // nolint:gocyclo,cyclop
	t.Parallel()

	t.Run("unsupported message type", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		done := make(chan struct{})

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &DIDDocResp{}
				err = msg.Decode(pMsg)
				require.NoError(t, err)

				require.Contains(t, pMsg.Data.ErrorMsg, "unsupported message service type : unsupported-message-type")
				require.Empty(t, pMsg.Data.DIDDoc)

				done <- struct{}{}

				return nil
			},
		}

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(struct {
			Type string `json:"@type,omitempty"`
		}{Type: "unsupported-message-type"})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("messenger reply error", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				return errors.New("reply error")
			},
		}

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(struct {
			Type string `json:"@type,omitempty"`
		}{Type: "unsupported-message-type"})}
	})

	t.Run("did doc request", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		done := make(chan struct{})

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &DIDDocResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)

				didDoc, dErr := did.ParseDocument(pMsg.Data.DIDDoc)
				require.NoError(t, dErr)

				require.Contains(t, didDoc.ID, "did:")
				require.Equal(t, pMsg.Type, didDocResp)

				done <- struct{}{}

				return nil
			},
		}

		rpClientID := uuid.New().String()
		err = c.rpStore.SaveRP(&rp.Tenant{ClientID: rpClientID, RequiresBlindedRoute: false})
		require.NoError(t, err)

		connID := uuid.New().String()
		c.connections = &mockconn.MockConnectionsLookup{ConnIDByDIDs: connID}

		err = c.persistenceStore.Put(getConnToTenantMappingDBKey(connID), []byte(rpClientID))
		require.NoError(t, err)

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
			ID:   uuid.New().String(),
			Type: didDocReq,
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("invalid connection", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		done := make(chan struct{})

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, didDocResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "get connection by DIDs")

				done <- struct{}{}

				return nil
			},
		}
		c.connections = &mockconn.MockConnectionsLookup{ConnIDByDIDsErr: errors.New("conn by dids error")}

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
			ID:   uuid.New().String(),
			Type: didDocReq,
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("create did doc error", func(t *testing.T) {
		t.Parallel()

		conf := config(t)

		done := make(chan struct{})
		conf.AriesContextProvider = &mockprovider.MockProvider{
			Provider: &ariesmockprovider.Provider{
				ProtocolStateStorageProviderValue: mem.NewProvider(),
				StorageProviderValue:              mem.NewProvider(),
				VDRegistryValue:                   &mockvdr.MockVDRegistry{CreateErr: errors.New("create did error")},
				ServiceMap: map[string]interface{}{
					mediator.Coordination:      &mockroute.MockMediatorSvc{},
					didexchangesvc.DIDExchange: &mockdidexsvc.MockDIDExchangeSvc{},
					outofbandsvc.Name:          &mockoutofband.MockService{},
				},
				KMSValue: newKMS(t),
			},
		}

		conf.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, didDocResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "create new peer did")

				done <- struct{}{}

				return nil
			},
		}

		c, err := New(conf)
		require.NoError(t, err)

		rpClientID := uuid.New().String()
		err = c.rpStore.SaveRP(&rp.Tenant{ClientID: rpClientID, RequiresBlindedRoute: false})
		require.NoError(t, err)

		connID := uuid.New().String()
		c.connections = &mockconn.MockConnectionsLookup{ConnIDByDIDs: connID}

		err = c.persistenceStore.Put(getConnToTenantMappingDBKey(connID), []byte(rpClientID))
		require.NoError(t, err)

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
			ID:   uuid.New().String(),
			Type: didDocReq,
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("mapping save error", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		done := make(chan struct{})

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, didDocResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "save connection-authzDID mapping")

				done <- struct{}{}

				return nil
			},
		}

		rpClientID := uuid.New().String()
		err = c.rpStore.SaveRP(&rp.Tenant{ClientID: rpClientID, RequiresBlindedRoute: false})
		require.NoError(t, err)

		connID := uuid.New().String()
		c.connections = &mockconn.MockConnectionsLookup{ConnIDByDIDs: connID}

		err = c.persistenceStore.Put(getConnToTenantMappingDBKey(connID), []byte(rpClientID))
		require.NoError(t, err)

		mockStore := &mockstorage.Store{ErrPut: errors.New("save error")}
		c.transientStore = mockStore

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
			ID:   uuid.New().String(),
			Type: didDocReq,
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("connection to rp tenant mapping not found", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		done := make(chan struct{})

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, didDocResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "get connection to rp tenant mapping")

				done <- struct{}{}

				return nil
			},
		}

		connID := uuid.New().String()
		c.connections = &mockconn.MockConnectionsLookup{ConnIDByDIDs: connID}

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
			ID:   uuid.New().String(),
			Type: didDocReq,
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("rp tenant not found", func(t *testing.T) {
		t.Parallel()

		c, err := New(config(t))
		require.NoError(t, err)

		done := make(chan struct{})

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, didDocResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "get rp tenant data")

				done <- struct{}{}

				return nil
			},
		}

		connID := uuid.New().String()
		c.connections = &mockconn.MockConnectionsLookup{ConnIDByDIDs: connID}

		err = c.persistenceStore.Put(getConnToTenantMappingDBKey(connID), []byte(uuid.New().String()))
		require.NoError(t, err)

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
			ID:   uuid.New().String(),
			Type: didDocReq,
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})
}

type stubWriter struct {
}

func (s *stubWriter) Write(p []byte) (n int, err error) {
	return -1, errors.New("test")
}

type mockPresentationExProvider struct {
	createValue *presexch.PresentationDefinition
	createErr   error
}

func (m *mockPresentationExProvider) Create(scopes []string) (*presexch.PresentationDefinition, error) {
	return m.createValue, m.createErr
}

func newHydraLoginRequest(t *testing.T) *http.Request {
	t.Helper()

	u, err := url.Parse("http://example.com?login_challenge=" + uuid.New().String())
	require.NoError(t, err)

	return &http.Request{URL: u}
}

func newHydraConsentRequest(t *testing.T, challenge string) *http.Request {
	t.Helper()

	u, err := url.Parse("http://example.com?consent_challenge=" + challenge)
	require.NoError(t, err)

	return &http.Request{URL: u}
}

func newOidcCallbackRequest(t *testing.T, state, code string) *http.Request {
	t.Helper()

	u, err := url.Parse(fmt.Sprintf("http://example.com?state=%s&code=%s", state, code))
	require.NoError(t, err)

	return &http.Request{URL: u}
}

func newHydraRequestNoChallenge(t *testing.T) *http.Request {
	t.Helper()

	u, err := url.Parse("http://example.com")
	require.NoError(t, err)

	return &http.Request{
		URL: u,
	}
}

func newCreatePresentationDefinitionRequest(t *testing.T, handle string) *http.Request {
	t.Helper()

	u, err := url.Parse(fmt.Sprintf("http://adapter.example.com?h=%s", handle))
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
		createValue: &presexch.PresentationDefinition{
			InputDescriptors: []*presexch.InputDescriptor{{ID: "1"}},
		},
	}
}

func newDID(t *testing.T) *did.DID {
	t.Helper()

	d, err := did.Parse("did:example:" + uuid.New().String())
	require.NoError(t, err)

	return d
}

func saveRP(t *testing.T, p storage.Provider, r *rp.Tenant) {
	t.Helper()

	s, err := rp.New(p)
	require.NoError(t, err)

	err = s.SaveRP(r)
	require.NoError(t, err)
}

func saveUserConn(t *testing.T, p storage.Provider, u *rp.UserConnection) {
	t.Helper()

	s, err := rp.New(p)
	require.NoError(t, err)

	err = s.SaveUserConnection(u)
	require.NoError(t, err)
}

func newCreateRPRequest(t *testing.T, request *CreateRPTenantRequest) *http.Request {
	t.Helper()

	bits, err := json.Marshal(request)
	require.NoError(t, err)

	return httptest.NewRequest(http.MethodPost, "/dummy", bytes.NewReader(bits))
}

func newCreateRPRequestMalformed() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/dummy", nil)
}

func newCHAPIResponse(t *testing.T, invID string, vp *verifiable.Presentation) *http.Request {
	t.Helper()

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

func newGetPresentationResponseResult(h string) *http.Request {
	return httptest.NewRequest(http.MethodGet, fmt.Sprintf("/dummy?h=%s", h), nil)
}

type stubStorageProvider struct {
	storeOpenErr error
	storeGetErr  error
	storePutErr  error
}

func (s *stubStorageProvider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	panic("implement me")
}

func (s *stubStorageProvider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	panic("implement me")
}

func (s *stubStorageProvider) GetOpenStores() []storage.Store {
	panic("implement me")
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

func (s *stubStorageProvider) Close() error {
	panic("implement me")
}

type stubStore struct {
	errPut error
	errGet error
}

func (s *stubStore) GetTags(key string) ([]storage.Tag, error) {
	panic("implement me")
}

func (s *stubStore) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	panic("implement me")
}

func (s *stubStore) Batch(operations []storage.Operation) error {
	panic("implement me")
}

func (s *stubStore) Flush() error {
	panic("implement me")
}

func (s *stubStore) Close() error {
	panic("implement me")
}

func (s *stubStore) Put(k string, v []byte, _ ...storage.Tag) error {
	return s.errPut
}

func (s *stubStore) Get(k string) ([]byte, error) {
	return nil, s.errGet
}

func (s *stubStore) GetBulk(k ...string) ([][]byte, error) {
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

func marshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	bits, err := json.Marshal(v)
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
	t *testing.T, authz *verifiable.Credential, request *presentproof.RequestPresentation) {
	t.Helper()

	require.Len(t, request.RequestPresentationsAttach, 1)

	bits, err := request.RequestPresentationsAttach[0].Data.Fetch()
	require.NoError(t, err)

	vp, err := verifiable.ParsePresentation(
		bits,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(testutil.DocumentLoader(t)),
	)
	require.NoError(t, err)

	require.Len(t, vp.Credentials(), 1)

	authzBits, err := vp.MarshalledCredentials()
	require.NoError(t, err)

	result, err := verifiable.ParseCredential(
		authzBits[0],
		verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
	)
	require.NoError(t, err)

	actual, ok := result.Subject.([]verifiable.Subject)
	require.True(t, ok)

	require.Equal(t, authz.Subject, &actual[0])
}

func newIssuerResponse(t *testing.T, thid string, payload interface{}) service.DIDCommMsg {
	t.Helper()

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
		Persistent: mem.NewProvider(),
		Transient:  mem.NewProvider(),
	}
}

func storePut(t *testing.T, s storage.Store, k string, v interface{}) {
	t.Helper()

	bits, err := json.Marshal(v)
	require.NoError(t, err)

	err = s.Put(k, bits)
	require.NoError(t, err)
}

func newKMS(t *testing.T) kms.KeyManager {
	t.Helper()

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx.KMS()
}
