/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/trustbloc/edge-core/pkg/log"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
)

var logger = log.New("edge-adapter/issuer-login-consent")

const (
	addressPattern = ":%s"

	loginEndpoint   = "/login"
	consentEndpoint = "/consent"
)

var hydra_admin_url string

var httpClient *http.Client

/*
Issuer-Login-Consent is an ory/hydra login & consent backend that automatically accepts all login and consent requests.
*/

func main() {
	port := os.Getenv("ISSUER_LOGIN_CONSENT_PORT")
	if port == "" {
		logger.Fatalf("ISSUER_LOGIN_CONSENT_PORT env variable missing")
	}

	hydra_admin_url = os.Getenv("ISSUER_HYDRA_ADMIN_URL")
	if hydra_admin_url == "" {
		logger.Fatalf("ISSUER_HYDRA_ADMIN_URL env variable missing")
	}

	certPath := os.Getenv("MOCK_ISSUER_LOGIN_TLS_SERVE_CERT")
	if certPath == "" {
		logger.Fatalf("MOCK_ISSUER_LOGIN_TLS_SERVE_CERT env variable missing")
	}

	keyPath := os.Getenv("MOCK_ISSUER_LOGIN_TLS_SERVE_KEY")
	if keyPath == "" {
		logger.Fatalf("MOCK_ISSUER_LOGIN_TLS_SERVE_KEY env variable missing")
	}

	caCertPathString := os.Getenv("MOCK_ISSUER_LOGIN_TLS_CACERTS")
	if caCertPathString == "" {
		logger.Fatalf("MOCK_ISSUER_LOGIN_TLS_CACERTS env variable missing")
	}

	caCertPaths := strings.Split(caCertPathString, ",")

	rootCAs, err := tlsutils.GetCertPool(true, caCertPaths)
	if err != nil {
		logger.Fatalf("failed to initialize tls cert pool")
	}

	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS12,
			}}}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc(loginEndpoint, loginHandler).Methods(http.MethodGet)
	router.HandleFunc(consentEndpoint, consentHandler).Methods(http.MethodGet)

	logger.Fatalf("issuer server start error %s",
		http.ListenAndServeTLS(fmt.Sprintf(addressPattern, port), certPath, keyPath, router))

	// logger.Fatalf("issuer server start error %s", http.ListenAndServe(fmt.Sprintf(addressPattern, port), router))
}

type hydraRedirectResponse struct {
	Redirect string `json:"redirect_to"`
}

// TODO: should we have a static subject ID for testing? Or let a random one be generated each time.
var subjectID = uuid.New()

func loginHandler(rw http.ResponseWriter, req *http.Request) {
	challenge := req.FormValue("login_challenge")

	logger.Warnf("TODO NOTE starting login handling")

	loginInfoRequest, err := http.NewRequest(http.MethodGet,
		hydra_admin_url+"/oauth2/auth/requests/login?login_challenge="+challenge, nil)
	if err != nil {
		WriteErrorResponseWithLog(rw, 500, "failed creating login info request: "+err.Error(), loginEndpoint)
		return
	}

	_, err = sendHTTPRequest(loginInfoRequest, http.StatusOK, "")
	if err != nil {
		WriteErrorResponseWithLog(rw, 500, "failed fetching login metadata: "+err.Error(), loginEndpoint)
		return
	}

	// auto login

	acceptMessage := []byte(fmt.Sprintf(`{
	"subject":"%s",
	"remember":true,
	"remember_for":3600
}`, subjectID))

	completeFlow(rw, req, loginEndpoint,
		"/oauth2/auth/requests/login/accept?login_challenge="+challenge, acceptMessage)
}

// consentMetadata the response from the hydra consent info endpoint
type consentMetadata struct {
	RequestedScopes   []string `json:"requested_scope"`
	RequestedAudience []string `json:"requested_access_token_audience"`
}

// consentMessage the consent acceptance message sent to hydra
type consentMessage struct {
	Scopes   []string `json:"grant_scope"`
	Audience []string `json:"grant_access_token_audience,omitempty"`
	Remember bool     `json:"remember,omitempty"`
	Lifetime int      `json:"remember_for,omitempty"`
}

func consentHandler(rw http.ResponseWriter, req *http.Request) {
	challenge := req.FormValue("consent_challenge")

	logger.Warnf("TODO NOTE starting consent handling")

	consentInfoRequest, err := http.NewRequest(http.MethodGet,
		hydra_admin_url+"/oauth2/auth/requests/consent?consent_challenge="+challenge, nil)
	if err != nil {
		WriteErrorResponseWithLog(rw, 500, "failed creating consent info request: "+err.Error(), consentEndpoint)
		return
	}

	consentDataBytes, err := sendHTTPRequest(consentInfoRequest, http.StatusOK, "")
	if err != nil {
		WriteErrorResponseWithLog(rw, 500, "failed fetching consent metadata: "+err.Error(), consentEndpoint)
		return
	}

	metadata := consentMetadata{}
	err = json.Unmarshal(consentDataBytes, &metadata)
	if err != nil {
		WriteErrorResponseWithLog(rw, 500, "failed parsing consent metadata: "+err.Error(), consentEndpoint)
		return
	}

	// auto consent to requested scopes and audience
	response := consentMessage{
		Scopes:   metadata.RequestedScopes,
		Audience: metadata.RequestedAudience,
		Remember: true,
		Lifetime: 3600,
	}

	consentBytes, err := json.Marshal(&response)
	if err != nil {
		WriteErrorResponseWithLog(rw, 500, "failed marshaling consent message: "+err.Error(), consentEndpoint)
		return
	}

	completeFlow(rw, req, consentEndpoint,
		"/oauth2/auth/requests/consent/accept?consent_challenge="+challenge, consentBytes)
}

func completeFlow(myRW http.ResponseWriter, myReq *http.Request, myEndpoint, hydraEndpoint string, dataBytes []byte) {
	hydraResponseRequest, err := http.NewRequest(
		http.MethodPut,
		hydra_admin_url+hydraEndpoint,
		bytes.NewReader(dataBytes),
	)
	if err != nil {
		WriteErrorResponseWithLog(myRW, 500, "failed creating login/consent response message: "+err.Error(), myEndpoint)
		return
	}

	redirectResponseBytes, err := sendHTTPRequest(hydraResponseRequest, http.StatusOK, "")
	if err != nil {
		WriteErrorResponseWithLog(myRW, 500, "failed sending login/consent response to hydra: "+err.Error(), myEndpoint)
		return
	}

	resp := hydraRedirectResponse{}

	err = json.Unmarshal(redirectResponseBytes, &resp)
	if err != nil {
		WriteErrorResponseWithLog(myRW, 500, "failed parsing hydra redirect value: "+err.Error(), myEndpoint)
		return
	}

	http.Redirect(myRW, myReq, resp.Redirect, http.StatusFound)
}

func sendHTTPRequest(req *http.Request, status int, bearerToken string) ([]byte, error) {
	if bearerToken != "" {
		req.Header.Add("Authorization", "Bearer "+bearerToken)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request : %w", err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Warnf("failed to close response body")
		}
	}()

	if resp.StatusCode != status {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Warnf("failed to read response body for status: %d", resp.StatusCode)
		}

		return nil, fmt.Errorf("http request: %d %s", resp.StatusCode, string(body))
	}

	return ioutil.ReadAll(resp.Body)
}

// WriteErrorResponseWithLog write error response along with adding a error log.
func WriteErrorResponseWithLog(rw http.ResponseWriter, status int, msg, endpoint string) {
	rw.WriteHeader(status)

	_, err := rw.Write([]byte(fmt.Sprintf(`{"error":"%s"}`, msg)))
	if err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}

	logger.Errorf("endpoint=[%s] status=[%d] errMsg=[%s]", endpoint, status, msg)
}
