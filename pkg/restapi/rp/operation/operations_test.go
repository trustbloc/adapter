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

	"github.com/google/uuid"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/stretchr/testify/require"

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
		o.hydraLoginHandler(r, newHydraRequest(t))

		require.Equal(t, http.StatusOK, r.Code)
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
		o.hydraLoginHandler(w, newHydraRequest(t))
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
		o.hydraLoginHandler(w, newHydraRequest(t))
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
		o.hydraLoginHandler(w, newHydraRequest(t))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestOidcCallbackHandler(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)

	r := &httptest.ResponseRecorder{}
	c.oidcCallbackHandler(r, nil)

	require.Equal(t, http.StatusOK, r.Code)
}

func TestHydraConsentHandler(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)

	r := &httptest.ResponseRecorder{}
	c.hydraConsentHandler(r, nil)

	require.Equal(t, http.StatusOK, r.Code)
}

func TestCreatePresentationDefinition(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		c, err := New(&Config{PresentationExProvider: &mockPresentationExProvider{
			createValue: &presentationex.PresentationDefinitions{
				InputDescriptors: []presentationex.InputDescriptors{{ID: "1"}}}}})
		require.NoError(t, err)

		reqBytes, err := json.Marshal(CreatePresentationDefinitionReq{Scopes: []string{"scope1", "scope2"}})
		require.NoError(t, err)

		r := httptest.NewRecorder()
		c.createPresentationDefinition(r, &http.Request{Body: ioutil.NopCloser(bytes.NewReader(reqBytes))})

		require.Equal(t, http.StatusOK, r.Code)

		var resp presentationex.PresentationDefinitions
		require.NoError(t, json.Unmarshal(r.Body.Bytes(), &resp))

		require.Equal(t, "1", resp.InputDescriptors[0].ID)
	})

	t.Run("test failure from create presentation definition request", func(t *testing.T) {
		c, err := New(&Config{PresentationExProvider: &mockPresentationExProvider{
			createErr: fmt.Errorf("failed to create presentation definition request")}})
		require.NoError(t, err)

		reqBytes, err := json.Marshal(CreatePresentationDefinitionReq{Scopes: []string{"scope1", "scope2"}})
		require.NoError(t, err)

		r := httptest.NewRecorder()
		c.createPresentationDefinition(r, &http.Request{Body: ioutil.NopCloser(bytes.NewReader(reqBytes))})

		require.Equal(t, http.StatusBadRequest, r.Code)
		require.Contains(t, r.Body.String(), "failed to create presentation definition request")
	})

	t.Run("test failure from decode request", func(t *testing.T) {
		c, err := New(&Config{})
		require.NoError(t, err)

		r := httptest.NewRecorder()
		c.createPresentationDefinition(r, &http.Request{Body: ioutil.NopCloser(bytes.NewReader([]byte("w")))})

		require.Equal(t, http.StatusBadRequest, r.Code)
		require.Contains(t, r.Body.String(), "invalid request")
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

func newHydraRequest(t *testing.T) *http.Request {
	u, err := url.Parse("http://example.com?login_challenge=" + uuid.New().String())
	require.NoError(t, err)

	return &http.Request{
		URL: u,
	}
}

func newHydraRequestNoChallenge(t *testing.T) *http.Request {
	u, err := url.Parse("http://example.com")
	require.NoError(t, err)

	return &http.Request{
		URL: u,
	}
}

type stubHydra struct {
	loginRequestFunc func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error)
	acceptLoginFunc  func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error)
}

func (s *stubHydra) GetLoginRequest(params *admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
	return s.loginRequestFunc(params)
}

func (s *stubHydra) AcceptLoginRequest(params *admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
	return s.acceptLoginFunc(params)
}
