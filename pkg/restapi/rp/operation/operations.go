/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
)

// API endpoints.
const (
	hydraLoginEndpoint                 = "/login"
	hydraConsentEndpoint               = "/consent"
	oidcCallbackEndpoint               = "/callback"
	createPresentationRequestEndpoint  = "/presentations/create"
	handlePresentationResponseEndpoint = "/presentations/handleResponse"
	userInfoEndpoint                   = "/userinfo"
	healthCheckEndpoint                = "/healthcheck"
)

type healthCheckResp struct {
	Status      string    `json:"status"`
	CurrentTime time.Time `json:"currentTime"`
}

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// New returns CreateCredential instance.
func New(config *Config) (*Operation, error) {
	return &Operation{}, nil
}

// Config defines configuration for rp operations.
type Config struct {
}

// Operation defines handlers for rp operations.
type Operation struct {
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(hydraLoginEndpoint, http.MethodGet, o.hydraLoginHandler),
		support.NewHTTPHandler(hydraConsentEndpoint, http.MethodGet, o.hydraConsentHandler),
		support.NewHTTPHandler(oidcCallbackEndpoint, http.MethodGet, o.oidcCallbackHandler),
		support.NewHTTPHandler(createPresentationRequestEndpoint, http.MethodPost, o.getPresentationRequestHandler),
		support.NewHTTPHandler(handlePresentationResponseEndpoint, http.MethodPost, o.presentationResponseHandler),
		support.NewHTTPHandler(userInfoEndpoint, http.MethodGet, o.userInfoHandler),
		support.NewHTTPHandler(healthCheckEndpoint, http.MethodGet, o.healthCheckHandler),
	}
}

// Hydra redirects the user here in the authentication phase.
func (o *Operation) hydraLoginHandler(w http.ResponseWriter, _ *http.Request) {
	// TODO verify with hydra if we need to show the login screen. If so, save
	//  hydra's login_challenge, redirect to OIDC provider (map login_challenge to state param).
	//  Otherwise accept this login at hydra's /login/accept endpoint and redirect back to hydra.
	testResponse(w)
}

// OIDC provider redirects the user here after they've been authenticated.
func (o *Operation) oidcCallbackHandler(w http.ResponseWriter, _ *http.Request) {
	// TODO exchange auth code for access_token, then fetch id_token using access_token.
	//  Accept this login at hydra's /login/accept and redirect back to hydra.
	testResponse(w)
}

// Hydra redirects the user here in the consent phase.
func (o *Operation) hydraConsentHandler(w http.ResponseWriter, _ *http.Request) {
	// TODO verify with hydra if we need to show the consent screen. If so, save hydra's
	//  consent_challenge, create a request for presentation, save it, and redirect to the
	//  ui endpoint (append a handle to the request for presentation).
	//  Otherwise accept this consent at hydra's /consent/accept endpoint and redirect
	//  back to hydra.
	testResponse(w)
}

// Frontend requests a request for a presentation and provides a handle.
func (o *Operation) getPresentationRequestHandler(w http.ResponseWriter, _ *http.Request) {
	// TODO extract handle and return the request for presentation.
	testResponse(w)
}

// Frontend submits the user's presentation for evaluation.
//
// The user may have provided either:
// - all required credentials in a single response, or
// - consent credential + didcomm endpoint where the requested presentations can be obtained, or
// - nothing (an error response?), indicating they cannot satisfy the request.
func (o *Operation) presentationResponseHandler(w http.ResponseWriter, _ *http.Request) {
	// TODO validate response, do DIDComm with the issuer if required, gather all credentials,
	//  make sure they're all valid and all present, load the consent_challenge and accept the user's
	//  consent at hydra's /consent/accept endpoint and respond with hydra's redirect URL.
	testResponse(w)
}

// RP requests user data.
func (o *Operation) userInfoHandler(w http.ResponseWriter, _ *http.Request) {
	// TODO introspect RP's access_token (Authorization request header) with hydra and validate.
	//  Load VPs related to the user and map them to a normal id_token and reply with that.
	testResponse(w)
}

func (o *Operation) healthCheckHandler(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusOK)

	err := json.NewEncoder(rw).Encode(&healthCheckResp{
		Status:      "success",
		CurrentTime: time.Now(),
	})
	if err != nil {
		log.Errorf("healthcheck response failure, %s", err)
	}
}

func testResponse(w io.Writer) {
	_, err := w.Write([]byte("OK"))
	if err != nil {
		fmt.Printf("error writing test response: %s", err.Error())
	}
}
