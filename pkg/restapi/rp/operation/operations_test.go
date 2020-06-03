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

	"github.com/coreos/go-oidc"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-adapter/pkg/db"
	"github.com/trustbloc/edge-adapter/pkg/presentationex"
)

func TestGetRESTHandlers(t *testing.T) {
	c, err := New(&Config{})
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
		})
		require.NoError(t, err)
		w := &httptest.ResponseRecorder{}
		o.hydraLoginHandler(w, newHydraLoginRequest(t))
		require.Equal(t, http.StatusFound, w.Code)
		require.Equal(t, w.Header().Get("Location"), redirectURL)
	})
	t.Run("fails on missing login_challenge", func(t *testing.T) {
		o, err := New(&Config{})
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
		})
		require.NoError(t, err)

		c.setLoginRequestForState(state, &models.LoginRequest{Client: &models.OAuth2Client{ClientID: clientID}})

		r := &httptest.ResponseRecorder{}
		c.oidcCallbackHandler(r, newOidcCallbackRequest(t, state, code))

		require.Equal(t, http.StatusFound, r.Code)
		require.Equal(t, redirectURL, r.Header().Get("Location"))
	})

	t.Run("bad request on invalid state", func(t *testing.T) {
		c, err := New(&Config{})
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

			c, err := New(&Config{
				UIEndpoint: uiEndpoint,
				Hydra: &stubHydra{
					getConsentRequestFunc: func(r *admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
						require.Equal(t, challenge, r.ConsentChallenge)
						return &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
							Skip: false,
						}}, nil
					},
				},
				PresentationExProvider: mockPresentationDefinitionsProvider(),
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
			c, err := New(&Config{})
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
		})
		require.NoError(t, err)

		c.setConsentRequest(handle, &consentRequest{
			pd: presDefs,
			cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Subject:        userSubject,
				Client:         &models.OAuth2Client{ClientID: rpClientID},
				RequestedScope: scopes,
			}},
		})

		r := httptest.NewRecorder()
		c.createPresentationDefinition(r, newCreatePresentationDefinitionRequest(t, handle))

		require.Equal(t, http.StatusOK, r.Code)

		var resp presentationex.PresentationDefinitions
		require.NoError(t, json.Unmarshal(r.Body.Bytes(), &resp))

		require.Equal(t, presDefs, &resp)
	})

	t.Run("bad request if handle is invalid", func(t *testing.T) {
		c, err := New(&Config{})
		require.NoError(t, err)

		c.setConsentRequest(uuid.New().String(), &consentRequest{
			pd: &presentationex.PresentationDefinitions{},
			cr: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Subject: uuid.New().String(),
				Client:  &models.OAuth2Client{ClientID: uuid.New().String()},
			}},
		})

		r := httptest.NewRecorder()
		c.createPresentationDefinition(r, newCreatePresentationDefinitionRequest(t, "invalid"))

		require.Equal(t, http.StatusBadRequest, r.Code)
		require.Contains(t, r.Body.String(), "invalid request")
	})

	t.Run("bad request if handle is missing", func(t *testing.T) {
		c, err := New(&Config{})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		c.createPresentationDefinition(
			w, httptest.NewRequest(http.MethodGet, "http://adapter.example.com/createPresentation", nil))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestPresentationResponseHandler(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)

	r := &httptest.ResponseRecorder{}
	c.presentationResponseHandler(r, nil)

	require.Equal(t, http.StatusOK, r.Code)
}

func TestUserInfoHandler(t *testing.T) {
	c, err := New(&Config{})
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
