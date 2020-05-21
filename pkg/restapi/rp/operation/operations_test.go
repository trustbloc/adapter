/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetRESTHandlers(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)

	require.Equal(t, 7, len(c.GetRESTHandlers()))
}

func TestHydraLoginHandler(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)

	r := &httptest.ResponseRecorder{}
	c.hydraLoginHandler(r, nil)

	require.Equal(t, http.StatusOK, r.Code)
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

func TestGetPresentationRequestHandler(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)

	r := &httptest.ResponseRecorder{}
	c.getPresentationRequestHandler(r, nil)

	require.Equal(t, http.StatusOK, r.Code)
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

func TestHealthCheck(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)

	b := &httptest.ResponseRecorder{}
	c.healthCheckHandler(b, nil)

	require.Equal(t, http.StatusOK, b.Code)
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
