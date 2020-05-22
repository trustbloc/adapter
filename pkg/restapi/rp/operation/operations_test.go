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
	"testing"

	"github.com/trustbloc/edge-adapter/pkg/presentationex"

	"github.com/stretchr/testify/require"
)

func TestGetRESTHandlers(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)

	require.Equal(t, 6, len(c.GetRESTHandlers()))
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
