/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	didexchangesvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-adapter/pkg/db"
	"github.com/trustbloc/edge-adapter/pkg/presentationex"
)

func TestNew(t *testing.T) {
	t.Run("registers for didexchange events", func(t *testing.T) {
		registeredActions := false
		registeredMsgs := false
		_, err := New(&Config{
			DIDExchClient: &stubDIDClient{
				actionEventFunc: func(chan<- service.DIDCommAction) error {
					registeredActions = true
					return nil
				},
				msgEventFunc: func(chan<- service.StateMsg) error {
					registeredMsgs = true
					return nil
				},
			},
		})
		require.NoError(t, err)
		require.True(t, registeredActions)
		require.True(t, registeredMsgs)
	})

	t.Run("wraps error when actions registration fails", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&Config{
			DIDExchClient: &stubDIDClient{
				actionEventFunc: func(chan<- service.DIDCommAction) error {
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

func TestGetRESTHandlers(t *testing.T) {
	c, err := New(&Config{
		DIDExchClient: &stubDIDClient{},
	})
	require.NoError(t, err)

	require.Equal(t, 6, len(c.GetRESTHandlers()))
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
			DIDExchClient: &stubDIDClient{},
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
			DIDExchClient: &stubDIDClient{},
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusFound, w.Code)
		require.Equal(t, w.Header().Get("Location"), redirectURL)
	})
	t.Run("fails on missing login_challenge", func(t *testing.T) {
		o, err := New(&Config{
			DIDExchClient: &stubDIDClient{},
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
			DIDExchClient: &stubDIDClient{},
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
			DIDExchClient: &stubDIDClient{},
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

		c, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{
				clientID: clientID,
			},
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
			TrxProvider: func(context.Context, *sql.TxOptions) (Trx, error) {
				return &stubTrx{}, nil
			},
			UsersDAO:        &stubUsersDAO{},
			OIDCRequestsDAO: &stubOidcRequestsDAO{},
			RelyingPartiesDAO: &stubRelyingPartiesDAO{
				findByClientIDFunc: func(id string) (*db.RelyingParty, error) {
					require.Equal(t, clientID, id)
					return &db.RelyingParty{ClientID: id}, nil
				},
			},
			DIDExchClient: &stubDIDClient{},
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
			DIDExchClient: &stubDIDClient{},
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
			DIDExchClient: &stubDIDClient{},
		})
		require.NoError(t, err)

		const state = "123"

		c.setLoginRequestForState(state, &models.LoginRequest{})

		r := &httptest.ResponseRecorder{}
		c.oidcCallbackHandler(r, newOidcCallbackRequest(t, state, "code"))

		require.Equal(t, http.StatusInternalServerError, r.Code)
	})

	t.Run("internal error if cannot open DB transaction", func(t *testing.T) {
		c, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{},
			OIDC: func(string, context.Context) (*oidc.IDToken, error) {
				return &oidc.IDToken{Subject: "test"}, nil
			},
			TrxProvider: func(context.Context, *sql.TxOptions) (Trx, error) {
				return nil, errors.New("test")
			},
			DIDExchClient: &stubDIDClient{},
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
			TrxProvider:     func(context.Context, *sql.TxOptions) (Trx, error) { return &stubTrx{}, nil },
			UsersDAO:        &stubUsersDAO{},
			OIDCRequestsDAO: &stubOidcRequestsDAO{},
			RelyingPartiesDAO: &stubRelyingPartiesDAO{
				findByClientIDFunc: func(id string) (*db.RelyingParty, error) {
					return &db.RelyingParty{}, nil
				},
			},
			DIDExchClient: &stubDIDClient{},
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
	t.Run("error when inserting user", func(t *testing.T) {
		c, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{},
			OIDC: func(c string, _ context.Context) (*oidc.IDToken, error) {
				return &oidc.IDToken{Subject: "test"}, nil
			},
			TrxProvider: func(context.Context, *sql.TxOptions) (Trx, error) { return &stubTrx{}, nil },
			UsersDAO: &stubUsersDAO{
				insertErr: errors.New("test"),
			},
			RelyingPartiesDAO: &stubRelyingPartiesDAO{
				findByClientIDFunc: func(id string) (*db.RelyingParty, error) {
					return &db.RelyingParty{}, nil
				},
			},
			DIDExchClient: &stubDIDClient{},
		})
		require.NoError(t, err)

		err = c.saveUserAndRequest(
			context.Background(),
			&models.LoginRequest{Client: &models.OAuth2Client{}},
			"sub",
		)
		require.Error(t, err)
	})

	t.Run("error when inserting oidc request", func(t *testing.T) {
		c, err := New(&Config{
			OAuth2Config: &stubOAuth2Config{},
			OIDC: func(c string, _ context.Context) (*oidc.IDToken, error) {
				return &oidc.IDToken{Subject: "test"}, nil
			},
			TrxProvider: func(context.Context, *sql.TxOptions) (Trx, error) { return &stubTrx{}, nil },
			UsersDAO:    &stubUsersDAO{},
			OIDCRequestsDAO: &stubOidcRequestsDAO{
				insertErr: errors.New("test"),
			},
			RelyingPartiesDAO: &stubRelyingPartiesDAO{
				findByClientIDFunc: func(id string) (*db.RelyingParty, error) {
					return &db.RelyingParty{}, nil
				},
			},
			DIDExchClient: &stubDIDClient{},
		})
		require.NoError(t, err)

		err = c.saveUserAndRequest(
			context.Background(),
			&models.LoginRequest{Client: &models.OAuth2Client{}},
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

			c, err := New(&Config{
				UIEndpoint: uiEndpoint,
				Hydra: &stubHydra{
					getConsentRequestFunc: func(r *admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
						require.Equal(t, challenge, r.ConsentChallenge)
						return &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
							Skip:   false,
							Client: &models.OAuth2Client{ClientID: rpClientID},
						}}, nil
					},
				},
				PresentationExProvider: mockPresentationDefinitionsProvider(),
				RelyingPartiesDAO: &stubRelyingPartiesDAO{
					findByClientIDFunc: func(id string) (*db.RelyingParty, error) {
						require.Equal(t, rpClientID, id)
						return &db.RelyingParty{ClientID: rpClientID}, nil
					},
				},
				DIDExchClient: &stubDIDClient{},
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
				DIDExchClient: &stubDIDClient{},
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
				DIDExchClient: &stubDIDClient{},
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
			})
			require.NoError(t, err)
			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, "challenge"))
			require.Equal(t, http.StatusInternalServerError, w.Code)
		})

		t.Run("internal server error if cannot find relying party", func(t *testing.T) {
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
				RelyingPartiesDAO: &stubRelyingPartiesDAO{
					findByClientIDFunc: func(string) (*db.RelyingParty, error) {
						return nil, sql.ErrNoRows
					},
				},
				DIDExchClient: &stubDIDClient{},
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
				DIDExchClient: &stubDIDClient{},
			})
			require.NoError(t, err)

			w := &httptest.ResponseRecorder{}
			c.hydraConsentHandler(w, newHydraConsentRequest(t, "challenge"))
			require.Equal(t, http.StatusInternalServerError, w.Code)
		})
	})
}

func TestSaveConsentRequest(t *testing.T) {
	t.Run("wraps error from trx provider", func(t *testing.T) {
		expected := errors.New("test")
		c, err := New(&Config{
			TrxProvider: func(context.Context, *sql.TxOptions) (Trx, error) {
				return nil, expected
			},
			DIDExchClient: &stubDIDClient{},
		})
		require.NoError(t, err)

		err = c.saveConsentRequest(context.Background(), &consentRequest{})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error from user DAO", func(t *testing.T) {
		expected := errors.New("test")
		c, err := New(&Config{
			TrxProvider: func(context.Context, *sql.TxOptions) (Trx, error) {
				return &stubTrx{}, nil
			},
			UsersDAO: &stubUsersDAO{
				findBySubFunc: func(string) (*db.EndUser, error) {
					return nil, expected
				},
			},
			DIDExchClient: &stubDIDClient{},
		})
		require.NoError(t, err)

		err = c.saveConsentRequest(context.Background(), &consentRequest{
			cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{}},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error from oidcrequests DAO", func(t *testing.T) {
		t.Run("when searching", func(t *testing.T) {
			expected := errors.New("test")
			c, err := New(&Config{
				TrxProvider: func(context.Context, *sql.TxOptions) (Trx, error) {
					return &stubTrx{}, nil
				},
				UsersDAO: &stubUsersDAO{
					findBySubFunc: func(string) (*db.EndUser, error) {
						return &db.EndUser{}, nil
					},
				},
				OIDCRequestsDAO: &stubOidcRequestsDAO{
					findBySubAndClientIDFunc: func(string, string, []string) (*db.OIDCRequest, error) {
						return nil, expected
					},
				},
				DIDExchClient: &stubDIDClient{},
			})
			require.NoError(t, err)

			err = c.saveConsentRequest(context.Background(), &consentRequest{
				cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
					Client: &models.OAuth2Client{},
				}},
			})
			require.Error(t, err)
			require.True(t, errors.Is(err, expected))
		})

		t.Run("when updating", func(t *testing.T) {
			expected := errors.New("test")
			c, err := New(&Config{
				TrxProvider: func(context.Context, *sql.TxOptions) (Trx, error) {
					return &stubTrx{}, nil
				},
				UsersDAO: &stubUsersDAO{
					findBySubFunc: func(string) (*db.EndUser, error) {
						return &db.EndUser{}, nil
					},
				},
				OIDCRequestsDAO: &stubOidcRequestsDAO{
					findBySubAndClientIDFunc: func(string, string, []string) (*db.OIDCRequest, error) {
						return &db.OIDCRequest{}, nil
					},
					updateFunc: func(*db.OIDCRequest) error {
						return expected
					},
				},
				DIDExchClient: &stubDIDClient{},
			})
			require.NoError(t, err)

			err = c.saveConsentRequest(context.Background(), &consentRequest{
				cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
					Client: &models.OAuth2Client{},
				}},
			})
			require.Error(t, err)
			require.True(t, errors.Is(err, expected))
		})
	})
}

func TestCreatePresentationDefinition(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		userSubject := uuid.New().String()
		rpClientID := uuid.New().String()
		rpDID := newDID(t)
		scopes := []string{uuid.New().String(), uuid.New().String()}
		handle := uuid.New().String()
		presDefs := &presentationex.PresentationDefinitions{
			InputDescriptors: []presentationex.InputDescriptors{{ID: uuid.New().String()}},
		}
		invitation := &didexchange.Invitation{Invitation: &didexchangesvc.Invitation{
			ID:    uuid.New().String(),
			Type:  didexchange.InvitationMsgType,
			Label: "test-label",
			DID:   rpDID.String(),
		}}

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{createValue: presDefs},
			TrxProvider: func(context.Context, *sql.TxOptions) (Trx, error) {
				return &stubTrx{}, nil
			},
			UsersDAO: &stubUsersDAO{
				findBySubFunc: func(sub string) (*db.EndUser, error) {
					require.Equal(t, userSubject, sub)
					return &db.EndUser{Sub: sub}, nil
				},
			},
			OIDCRequestsDAO: &stubOidcRequestsDAO{
				findBySubAndClientIDFunc: func(sub, clientID string, scopesIn []string) (*db.OIDCRequest, error) {
					require.Equal(t, userSubject, sub)
					require.Equal(t, rpClientID, clientID)
					require.Equal(t, scopes, scopesIn)
					return &db.OIDCRequest{
						ID:             rand.Int63(),
						EndUserID:      rand.Int63(),
						RelyingPartyID: rand.Int63(),
						Scopes:         scopes,
					}, nil
				},
				updateFunc: func(r *db.OIDCRequest) error {
					require.Equal(t, presDefs, r.PresDef)
					return nil
				},
			},
			RelyingPartiesDAO: &stubRelyingPartiesDAO{
				findByClientIDFunc: func(id string) (*db.RelyingParty, error) {
					require.Equal(t, rpClientID, id)
					return &db.RelyingParty{
						ClientID: rpClientID,
						DID:      rpDID,
					}, nil
				},
			},
			DIDExchClient: &stubDIDClient{
				createInvWithDIDFunc: func(label, did string) (*didexchange.Invitation, error) {
					require.Equal(t, rpDID.String(), did)
					return invitation, nil
				},
			},
		})
		require.NoError(t, err)

		c.setConsentRequest(handle, &consentRequest{
			pd: presDefs,
			cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Subject:        userSubject,
				Client:         &models.OAuth2Client{ClientID: rpClientID},
				RequestedScope: scopes,
			}},
			rpDID: rpDID,
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
			DIDExchClient: &stubDIDClient{},
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
			DIDExchClient: &stubDIDClient{},
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
		scopes := []string{uuid.New().String(), uuid.New().String()}
		handle := uuid.New().String()
		presDefs := &presentationex.PresentationDefinitions{
			InputDescriptors: []presentationex.InputDescriptors{{ID: uuid.New().String()}},
		}

		c, err := New(&Config{
			PresentationExProvider: &mockPresentationExProvider{createValue: presDefs},
			TrxProvider: func(context.Context, *sql.TxOptions) (Trx, error) {
				return &stubTrx{}, nil
			},
			UsersDAO: &stubUsersDAO{
				findBySubFunc: func(sub string) (*db.EndUser, error) {
					require.Equal(t, userSubject, sub)
					return &db.EndUser{Sub: sub}, nil
				},
			},
			OIDCRequestsDAO: &stubOidcRequestsDAO{
				findBySubAndClientIDFunc: func(sub, clientID string, scopesIn []string) (*db.OIDCRequest, error) {
					return &db.OIDCRequest{
						ID:             rand.Int63(),
						EndUserID:      rand.Int63(),
						RelyingPartyID: rand.Int63(),
						Scopes:         scopes,
					}, nil
				},
				updateFunc: func(r *db.OIDCRequest) error {
					return nil
				},
			},
			RelyingPartiesDAO: &stubRelyingPartiesDAO{
				findByClientIDFunc: func(id string) (*db.RelyingParty, error) {
					return &db.RelyingParty{
						ClientID: rpClientID,
						DID:      rpDID,
					}, nil
				},
			},
			DIDExchClient: &stubDIDClient{
				createInvWithDIDFunc: func(label, did string) (*didexchange.Invitation, error) {
					return nil, errors.New("test")
				},
			},
		})
		require.NoError(t, err)

		c.setConsentRequest(handle, &consentRequest{
			pd: presDefs,
			cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Subject:        userSubject,
				Client:         &models.OAuth2Client{ClientID: rpClientID},
				RequestedScope: scopes,
			}},
			rpDID: rpDID,
		})

		r := httptest.NewRecorder()
		c.getPresentationsRequest(r, newCreatePresentationDefinitionRequest(t, handle))

		require.Equal(t, http.StatusInternalServerError, r.Code)
	})
}

func TestPresentationResponseHandler(t *testing.T) {
	c, err := New(&Config{
		DIDExchClient: &stubDIDClient{},
	})
	require.NoError(t, err)

	r := &httptest.ResponseRecorder{}
	c.presentationResponseHandler(r, nil)

	require.Equal(t, http.StatusOK, r.Code)
}

func TestUserInfoHandler(t *testing.T) {
	c, err := New(&Config{
		DIDExchClient: &stubDIDClient{},
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

type stubTrx struct {
	commitErr   error
	rollbackErr error
}

func (s *stubTrx) Commit() error {
	return s.commitErr
}

func (s stubTrx) Rollback() error {
	return s.rollbackErr
}

type stubUsersDAO struct {
	insertErr     error
	insertFunc    func(*db.EndUser) error
	findBySubFunc func(string) (*db.EndUser, error)
}

func (s *stubUsersDAO) Insert(u *db.EndUser) error {
	if s.insertErr != nil {
		return s.insertErr
	}

	if s.insertFunc != nil {
		return s.insertFunc(u)
	}

	return nil
}

func (s *stubUsersDAO) FindBySub(sub string) (*db.EndUser, error) {
	return s.findBySubFunc(sub)
}

type stubOidcRequestsDAO struct {
	insertErr                error
	insertFunc               func(*db.OIDCRequest) error
	findBySubAndClientIDFunc func(string, string, []string) (*db.OIDCRequest, error)
	updateFunc               func(request *db.OIDCRequest) error
}

func (s *stubOidcRequestsDAO) Insert(r *db.OIDCRequest) error {
	if s.insertErr != nil {
		return s.insertErr
	}

	if s.insertFunc != nil {
		return s.insertFunc(r)
	}

	return nil
}

func (s *stubOidcRequestsDAO) FindBySubRPClientIDAndScopes(
	sub, clientID string, scopes []string) (*db.OIDCRequest, error) {
	return s.findBySubAndClientIDFunc(sub, clientID, scopes)
}

func (s *stubOidcRequestsDAO) Update(req *db.OIDCRequest) error {
	return s.updateFunc(req)
}

type stubRelyingPartiesDAO struct {
	findByClientIDFunc func(string) (*db.RelyingParty, error)
}

func (s *stubRelyingPartiesDAO) FindByClientID(clientID string) (*db.RelyingParty, error) {
	return s.findByClientIDFunc(clientID)
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
