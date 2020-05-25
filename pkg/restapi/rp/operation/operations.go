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

	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"

	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
	"github.com/trustbloc/edge-adapter/pkg/presentationex"
	commhttp "github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/http"
)

// API endpoints.
const (
	hydraLoginEndpoint                 = "/login"
	hydraConsentEndpoint               = "/consent"
	oidcCallbackEndpoint               = "/callback"
	createPresentationRequestEndpoint  = "/presentations/create"
	handlePresentationResponseEndpoint = "/presentations/handleResponse"
	userInfoEndpoint                   = "/userinfo"
)

// errors.
const (
	invalidRequestErrMsg = "invalid request"
)

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type presentationExProvider interface {
	Create(scopes []string) (*presentationex.PresentationDefinitions, error)
}

// Hydra is the client used to interface with the Hydra service.
type Hydra interface {
	GetLoginRequest(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error)
	AcceptLoginRequest(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error)
}

// New returns CreateCredential instance.
func New(config *Config) (*Operation, error) {
	return &Operation{
		presentationExProvider: config.PresentationExProvider,
		hydra:                  config.Hydra,
	}, nil
}

// Config defines configuration for rp operations.
type Config struct {
	PresentationExProvider presentationExProvider
	Hydra                  Hydra
}

// Operation defines handlers for rp operations.
type Operation struct {
	presentationExProvider presentationExProvider
	hydra                  Hydra
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(hydraLoginEndpoint, http.MethodGet, o.hydraLoginHandler),
		support.NewHTTPHandler(hydraConsentEndpoint, http.MethodGet, o.hydraConsentHandler),
		support.NewHTTPHandler(oidcCallbackEndpoint, http.MethodGet, o.oidcCallbackHandler),
		support.NewHTTPHandler(createPresentationRequestEndpoint, http.MethodPost, o.createPresentationDefinition),
		support.NewHTTPHandler(handlePresentationResponseEndpoint, http.MethodPost, o.presentationResponseHandler),
		support.NewHTTPHandler(userInfoEndpoint, http.MethodGet, o.userInfoHandler),
	}
}

// Hydra redirects the user here in the authentication phase.
// TODO redirect to UI when not skipping
// TODO ensure request's origin is the same as the hydraUrl
//  https://stackoverflow.com/q/27234861/1623885
func (o *Operation) hydraLoginHandler(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("login_challenge")
	if challenge == "" {
		commhttp.WriteErrorResponse(w, http.StatusBadRequest, "missing challenge")
		return
	}

	req := admin.NewGetLoginRequestParams()

	req.SetLoginChallenge(challenge)

	login, err := o.hydra.GetLoginRequest(req)
	if err != nil {
		commhttp.WriteErrorResponse(
			w, http.StatusInternalServerError, fmt.Sprintf("failed to contact hydra : %s", err.Error()))
		return
	}

	if login.GetPayload().Skip {
		err := acceptLoginAndRedirectToHydra(w, r, o.hydra, login.GetPayload().Subject)
		if err != nil {
			commhttp.WriteErrorResponse(
				w, http.StatusInternalServerError, fmt.Sprintf("failed to accept login request : %s", err.Error()))
		}

		return
	}

	// TODO redirect to OIDC provider
	testResponse(w)
}

func acceptLoginAndRedirectToHydra(w http.ResponseWriter, r *http.Request, hydra Hydra, subject string) error {
	accept := admin.NewAcceptLoginRequestParams()

	accept.SetBody(&models.AcceptLoginRequest{
		Subject: &subject,
	})

	loginResponse, err := hydra.AcceptLoginRequest(accept)
	if err != nil {
		return fmt.Errorf("failed to accept login request : %w", err)
	}

	http.Redirect(w, r, loginResponse.GetPayload().RedirectTo, http.StatusFound)

	return nil
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

// Frontend requests to create presentation definition.
func (o *Operation) createPresentationDefinition(rw http.ResponseWriter, req *http.Request) {
	// get the request
	verificationReq := CreatePresentationDefinitionReq{}

	err := json.NewDecoder(req.Body).Decode(&verificationReq)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	// TODO remove scopes and use handle after this task https://github.com/trustbloc/edge-adapter/issues/14
	presentationDefinition, err := o.presentationExProvider.Create(verificationReq.Scopes)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponse(rw, presentationDefinition)
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

func testResponse(w io.Writer) {
	_, err := w.Write([]byte("OK"))
	if err != nil {
		fmt.Printf("error writing test response: %s", err.Error())
	}
}
