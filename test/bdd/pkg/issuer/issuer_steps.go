/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	issuerprofile "github.com/trustbloc/edge-adapter/pkg/profile/issuer"
	"github.com/trustbloc/edge-adapter/pkg/restapi/issuer/operation"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/context"
)

const (
	// AdapterURL is issuer adapter endpoint.
	AdapterURL = "https://issuer-adapter-rest.trustbloc.local:9070"
)

// Steps is steps for VC BDD tests.
type Steps struct {
	bddContext *context.BDDContext
	txnIDs     map[string]string
	states     map[string]string
	userIDs    map[string]string
}

// NewSteps returns new agent from client SDK.
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{
		bddContext: ctx,
		txnIDs:     make(map[string]string),
		states:     make(map[string]string),
		userIDs:    make(map[string]string),
	}
}

// RegisterSteps registers agent steps.
// nolint: lll
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Issuer Profile with id "([^"]*)", name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", requiresBlindedRoute "([^"]*)" and supportsAssuranceCred "([^"]*)"$`, // nolint: lll
		e.createBasicProfile)
	s.Step(`^Issuer Profile with id "([^"]*)", name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", requiresBlindedRoute "([^"]*)", supportsAssuranceCred "([^"]*)" and oidc provider "([^"]*)"$`, // nolint: lll
		e.createProfileWithOIDC)
	s.Step(`^Retrieved profile with id "([^"]*)" contains name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", requiresBlindedRoute "([^"]*)" and supportsAssuranceCred "([^"]*)"$`, // nolint: lll
		e.retrieveBasicProfile)
	s.Step(`^Retrieved profile with id "([^"]*)" contains name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", requiresBlindedRoute "([^"]*)", supportsAssuranceCred "([^"]*)" and oidc provider "([^"]*)"$`, // nolint: lll
		e.retrieveProfileWithOIDC)
	s.Step(`^Issuer adapter shows the wallet connect UI when the issuer "([^"]*)" wants to connect to the wallet$`,
		e.walletConnect)
	s.Step(`^Issuer adapter shows the wallet connect UI when the issuer "([^"]*)" with scopes "([^"]*)" wants to connect to the wallet$`,
		e.walletConnectOIDC)
	s.Step(`^Issuer adapter gets oidc authorization for the issuer "([^"]*)"$`,
		e.oidcLogin)
	s.Step(`^Issuer adapter \("([^"]*)"\) creates DIDComm connection invitation for "([^"]*)"$`,
		e.didcommConnectionInvitation)
	s.Step(`^Issuer adapter \("([^"]*)"\) validates response from "([^"]*)" and redirects to "([^"]*)"$`,
		e.validateConnectResp)
	s.Step(`^Issuer has a profile with name "([^"]*)", issuerURL "([^"]*)" and supportedVCContexts "([^"]*)"$`, e.createAndValidateProfile)
	s.Step(`^Issuer has a profile with name "([^"]*)", issuerURL "([^"]*)", oidc provider "([^"]*)" and supportedVCContexts "([^"]*)"$`, e.createAndValidateProfileWithOIDC)

	// waci steps
	s.Step(`^Issuer Profile with id "([^"]*)", name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", scopes "([^"]*)", issuer id "([^"]*)", linked wallet "([^"]*)" and oidc provider "([^"]*)" with WACI support$`, e.createProfileWithWACI)
	s.Step(`^Issuer Profile with id "([^"]*)", name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", scopes "([^"]*)", issuer id "([^"]*)", linked wallet "([^"]*)" and oidc provider "([^"]*)" with DIDComm V2 and WACI support$`, e.createProfileWithWACIDIDCommV2)
	s.Step(`^Retrieved profile with id "([^"]*)" contains name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", scopes "([^"]*)", issuer id "([^"]*)", linked wallet "([^"]*)" and oidc provider "([^"]*)" with WACI support$`, e.retrieveProfileWithWACI)
	s.Step(`^Retrieved profile with id "([^"]*)" contains name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", scopes "([^"]*)", issuer id "([^"]*)", linked wallet "([^"]*)" and oidc provider "([^"]*)" with DIDComm V2 and WACI support$`, e.retrieveProfileWithWACIDIDCommV2)
}

func (e *Steps) createBasicProfile(id, name, issuerURL, supportedVCContexts,
	requiresBlindedRouteStr, supportsAssuranceCredStr string) error {
	return e.createProfile(id, name, issuerURL, supportedVCContexts,
		requiresBlindedRouteStr, supportsAssuranceCredStr, "", "", "", "",
		false, true)
}

func (e *Steps) createProfileWithOIDC(id, name, issuerURL, supportedVCContexts,
	requiresBlindedRouteStr, supportsAssuranceCredStr, oidcProvider string) error {
	return e.createProfile(id, name, issuerURL, supportedVCContexts,
		requiresBlindedRouteStr, supportsAssuranceCredStr, oidcProvider, "", "", "",
		false, true)
}

func (e *Steps) createProfile(id, name, issuerURL, supportedVCContexts,
	requiresBlindedRouteStr, supportsAssuranceCredStr, oidcProvider, credScope, issuerID,
	linkedWallet string, supportsWACI, isDIDCommV1 bool) error {
	supportsAssuranceCred, err := strconv.ParseBool(supportsAssuranceCredStr)
	if err != nil {
		return fmt.Errorf("parse failure: %w", err)
	}

	requiresBlindedRoute, err := strconv.ParseBool(requiresBlindedRouteStr)
	if err != nil {
		return fmt.Errorf("parse failure: %w", err)
	}

	profileReq := operation.ProfileDataRequest{
		ID:                          id,
		Name:                        name,
		URL:                         issuerURL,
		SupportedVCContexts:         strings.Split(supportedVCContexts, ","),
		SupportsAssuranceCredential: supportsAssuranceCred,
		RequiresBlindedRoute:        requiresBlindedRoute,
		SupportsWACI:                supportsWACI,
		OIDCProviderURL:             oidcProvider,
		IssuerID:                    issuerID,
		CredentialScopes:            strings.Split(credScope, ","),
		LinkedWalletURL:             linkedWallet,
		IsDIDCommV1:                 isDIDCommV1,
	}

	requestBytes, err := json.Marshal(profileReq)
	if err != nil {
		return fmt.Errorf("failed to marshal profile request: %w", err)
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, AdapterURL+"/profile", "", "", // nolint: bodyclose
		bytes.NewBuffer(requestBytes), e.bddContext.TLSConfig())

	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		// nolint:wrapcheck // ignore
		return bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	return nil
}

func (e *Steps) retrieveBasicProfile(id, name, issuerURL, supportedVCContexts,
	requiresBlindedRouteStr, supportsAssuranceCredStr string) error {
	return e.retrieveProfile(id, name, issuerURL, supportedVCContexts,
		requiresBlindedRouteStr, supportsAssuranceCredStr, "", "", "", "",
		false, true)
}

func (e *Steps) retrieveProfileWithOIDC(id, name, issuerURL, supportedVCContexts,
	requiresBlindedRouteStr, supportsAssuranceCredStr, oidcProvider string) error {
	return e.retrieveProfile(id, name, issuerURL, supportedVCContexts,
		requiresBlindedRouteStr, supportsAssuranceCredStr, oidcProvider, "", "", "",
		false, true)
}

// nolint:funlen,gomnd,gocyclo,cyclop
func (e *Steps) retrieveProfile(id, name, issuerURL, supportedVCContexts,
	requiresBlindedRouteStr, supportsAssuranceCredStr, oidcProvider, credScope, issuerID,
	linkedWallet string, supportsWACI, isDIDCommV1 bool) error {
	resp, err := bddutil.HTTPDo(http.MethodGet, // nolint: bodyclose
		fmt.Sprintf(AdapterURL+"/profile/%s", id), "", "", nil, e.bddContext.TLSConfig())
	if err != nil {
		return fmt.Errorf("failed to execute profile request: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// nolint:wrapcheck // ignore
		return bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	profileResponse := &issuerprofile.ProfileData{}

	err = json.Unmarshal(respBytes, profileResponse)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if profileResponse.Name != name {
		return fmt.Errorf("profile name doesn't match : expected=%s actual=%s", name, profileResponse.Name)
	}

	if profileResponse.URL != issuerURL {
		return fmt.Errorf("profile callback url doesn't match : expected=%s actual=%s",
			issuerURL, profileResponse.URL)
	}

	if profileResponse.OIDCProviderURL != oidcProvider {
		return fmt.Errorf("profile oidc provider url doesn't match : expected=%s actual=%s",
			oidcProvider, profileResponse.OIDCProviderURL)
	}

	if profileResponse.IssuerID != issuerID {
		return fmt.Errorf("profile issuer id doesn't match : expected=%s actual=%s",
			issuerID, profileResponse.IssuerID)
	}

	if len(profileResponse.CredentialScopes) != len(strings.Split(credScope, ",")) {
		return fmt.Errorf("supported cred scope count doesnt match : expected=%d actual=%d",
			len(strings.Split(credScope, ",")), len(profileResponse.CredentialScopes))
	}

	if len(profileResponse.SupportedVCContexts) != len(strings.Split(supportedVCContexts, ",")) {
		return fmt.Errorf("supported vc count doesnt match : expected=%d actual=%d",
			len(strings.Split(supportedVCContexts, ",")), len(profileResponse.SupportedVCContexts))
	}

	supportsAssuranceCred, err := strconv.ParseBool(supportsAssuranceCredStr)
	if err != nil {
		return fmt.Errorf("parse failure: %w", err)
	}

	if profileResponse.SupportsAssuranceCredential != supportsAssuranceCred {
		return fmt.Errorf("profile supports assurance cred doesn't match : expected=%t actual=%t",
			supportsAssuranceCred, profileResponse.SupportsAssuranceCredential)
	}

	requiresBlindedRoute, err := strconv.ParseBool(requiresBlindedRouteStr)
	if err != nil {
		return fmt.Errorf("parse failure: %w", err)
	}

	if profileResponse.RequiresBlindedRoute != requiresBlindedRoute {
		return fmt.Errorf("profile requiresBlindedRoute doesn't match : expected=%t actual=%t",
			supportsAssuranceCred, profileResponse.SupportsAssuranceCredential)
	}

	if profileResponse.SupportsWACI != supportsWACI {
		return fmt.Errorf("profile supportsWACI doesn't match : expected=%t actual=%t",
			supportsWACI, profileResponse.SupportsWACI)
	}

	if profileResponse.IsDIDCommV1 != isDIDCommV1 {
		return fmt.Errorf("profile isDIDCommV1 doesn't match : expected=%t actual=%t",
			isDIDCommV1, profileResponse.IsDIDCommV1)
	}

	if profileResponse.LinkedWalletURL != linkedWallet {
		return fmt.Errorf("profile linked wallet url doesn't match : expected=%s actual=%s",
			linkedWallet, profileResponse.LinkedWalletURL)
	}

	if profileResponse.CredentialSigningKey == "" {
		return errors.New("credential signing key can't be empty")
	}

	if profileResponse.PresentationSigningKey == "" {
		return errors.New("presentation signing key can't be empty")
	}

	didKeyIDSplit := strings.Split(profileResponse.CredentialSigningKey, "#")

	if len(didKeyIDSplit) != 2 {
		return fmt.Errorf("invalid did key id : expected=%d actual=%d", 2, len(didKeyIDSplit))
	}

	_, err = bddutil.ResolveDID(e.bddContext.VDRI, didKeyIDSplit[0], 10)
	if err != nil {
		return fmt.Errorf("did resolution failied for id=%s err : %w", didKeyIDSplit[0], err)
	}

	return nil
}

func (e *Steps) walletConnect(profileID string) error {
	state := uuid.New().String()
	e.states[profileID] = state

	resp, err := bddutil.HTTPDo(http.MethodGet, // nolint: bodyclose // False positive
		fmt.Sprintf(AdapterURL+"/%s/connect/wallet?state=%s", profileID, state), "", "", nil,
		e.bddContext.TLSConfig())
	if err != nil {
		return fmt.Errorf("failed to execute wallet request: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	// validating only status code as the vue page needs javascript support
	if resp.StatusCode != http.StatusOK {
		// nolint:wrapcheck // error returned from external package is unwrapped
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, nil)
	}

	e.txnIDs[profileID] = resp.Request.URL.Query().Get("txnID")
	e.userIDs[profileID] = resp.Request.URL.Query().Get("uID")

	return nil
}

func (e *Steps) walletConnectOIDC(profileID, credScope string) error {
	resp, err := bddutil.HTTPDo(http.MethodGet, // nolint: bodyclose // False positive
		fmt.Sprintf(AdapterURL+"/%s/connect/wallet?cred=%s", profileID, credScope), "", "", nil,
		e.bddContext.TLSConfig())
	if err != nil {
		return fmt.Errorf("failed to execute wallet request: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	// validating only status code as the vue page needs javascript support
	if resp.StatusCode != http.StatusOK {
		// nolint:wrapcheck // error returned from external package is unwrapped
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, nil)
	}

	e.txnIDs[profileID] = resp.Request.URL.Query().Get("txnID")
	e.userIDs[profileID] = resp.Request.URL.Query().Get("uID")

	return nil
}

func (e *Steps) oidcLogin(issuerID string) error {
	txnID := e.txnIDs[issuerID]
	uID := e.userIDs[issuerID]

	reqData := fmt.Sprintf(`?txnID=%s&uID=%s`, txnID, uID)

	resp, err := bddutil.HTTPDo(http.MethodGet, // nolint: bodyclose
		AdapterURL+"/oidc/request"+reqData, "", "", nil, e.bddContext.TLSConfig())
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	// validating only status code as the vue page needs javascript support
	if resp.StatusCode != http.StatusOK {
		// nolint:wrapcheck // ignore
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, body)
	}

	println("body:", string(body))

	return nil
}

func (e *Steps) didcommConnectionInvitation(issuerID, agentID string) error {
	resp, err := bddutil.HTTPDo(http.MethodGet, // nolint: bodyclose
		AdapterURL+"/issuer/didcomm/interaction/request?txnID="+e.txnIDs[issuerID], "", "", nil,
		e.bddContext.TLSConfig())
	if err != nil {
		return fmt.Errorf("failed to execute chapi request: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// nolint:wrapcheck // ignore
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	// Mocking CHAPI request call
	e.bddContext.Store[bddutil.GetDIDConnectRequestKey(issuerID, agentID)] = string(respBytes)

	return nil
}

func (e *Steps) validateConnectResp(issuerID, agentID, issuerURL string) error {
	validateURL := AdapterURL + "/connect/validate?txnID=" + e.txnIDs[issuerID]

	vp, found := e.bddContext.GetString(bddutil.GetDIDConnectResponseKey(issuerID, agentID))
	if !found {
		return fmt.Errorf("VP not found")
	}

	profileReq := operation.WalletConnect{
		Resp: []byte(vp),
	}

	requestBytes, err := json.Marshal(profileReq)
	if err != nil {
		return fmt.Errorf("failed to marshal profileReq: %w", err)
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, // nolint: bodyclose
		validateURL, "", "", bytes.NewBuffer(requestBytes), e.bddContext.TLSConfig())
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// nolint:wrapcheck // ignore
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	validateResp := &operation.ValidateConnectResp{}

	err = json.Unmarshal(respBytes, validateResp)
	if err != nil {
		return fmt.Errorf("failed to unmarhal response: %w", err)
	}

	if !strings.Contains(validateResp.RedirectURL, getCallBackURL(issuerURL)) {
		return fmt.Errorf("expected redirectURL contains [%s] for issuer[%s], but got[%s]",
			getCallBackURL(issuerURL), issuerID, validateResp.RedirectURL)
	}

	u, err := url.Parse(validateResp.RedirectURL)
	if err != nil {
		return fmt.Errorf("failed to parse redirect url: %w", err)
	}

	if u.Query().Get("state") != e.states[issuerID] {
		return fmt.Errorf("expected state [%s] for issuer[%s], but got[%s]", e.states[issuerID], issuerID,
			u.Query().Get("state"))
	}

	return nil
}

func getCallBackURL(issuerURL string) string {
	return fmt.Sprintf("%s/cb", issuerURL)
}

func (e *Steps) createAndValidateProfile(name, issuerURL, supportedVCContexts string) error {
	id := uuid.New().String()

	err := e.createBasicProfile(id, name, issuerURL, supportedVCContexts, "false",
		"false")
	if err != nil {
		return fmt.Errorf("failed to create profile for id='%s', err:%w", id, err)
	}

	err = e.retrieveBasicProfile(id, name, issuerURL, supportedVCContexts, "false",
		"false")
	if err != nil {
		return fmt.Errorf("failed to retrieve profile for id='%s', err:%w", id, err)
	}

	return nil
}

func (e *Steps) createAndValidateProfileWithOIDC(name, issuerURL, oidcProvider, supportedVCContexts string) error {
	id := uuid.New().String()

	err := e.createProfile(id, name, issuerURL, supportedVCContexts, "false",
		"false", oidcProvider, "", "", "",
		false, true)
	if err != nil {
		return fmt.Errorf("failed to create profile for id='%s', err:%w", id, err)
	}

	err = e.retrieveProfile(id, name, issuerURL, supportedVCContexts, "false",
		"false", oidcProvider, "", "", "",
		false, true)
	if err != nil {
		return fmt.Errorf("failed to retrieve profile for id='%s', err:%w", id, err)
	}

	return nil
}
func (e *Steps) createProfileWithWACI(id, name, issuerURL, supportedVCContexts, credScopes,
	issuerID, linkedWallet, oidcProvider string) error {
	err := e.createProfile(id, name, issuerURL, supportedVCContexts, "false",
		"false", oidcProvider, credScopes, issuerID, linkedWallet,
		true, true)
	if err != nil {
		return fmt.Errorf("failed to create profile for id='%s', err:%w", id, err)
	}

	return nil
}
func (e *Steps) createProfileWithWACIDIDCommV2(id, name, issuerURL, supportedVCContexts, credScopes,
	issuerID, linkedWallet, oidcProvider string) error {
	err := e.createProfile(id, name, issuerURL, supportedVCContexts, "false",
		"false", oidcProvider, credScopes, issuerID, linkedWallet,
		true, false)
	if err != nil {
		return fmt.Errorf("failed to create profile for id='%s', err:%w", id, err)
	}

	return nil
}

func (e *Steps) retrieveProfileWithWACI(id, name, issuerURL, supportedVCContexts, credScopes, issuerID,
	linkedWallet, oidcProvider string) error {
	err := e.retrieveProfile(id, name, issuerURL, supportedVCContexts, "false",
		"false", oidcProvider, credScopes, issuerID, linkedWallet,
		true, true)
	if err != nil {
		return fmt.Errorf("failed to retrieve profile for id='%s', err:%w", id, err)
	}

	return nil
}

func (e *Steps) retrieveProfileWithWACIDIDCommV2(id, name, issuerURL, supportedVCContexts, credScopes, issuerID,
	linkedWallet, oidcProvider string) error {
	err := e.retrieveProfile(id, name, issuerURL, supportedVCContexts, "false",
		"false", oidcProvider, credScopes, issuerID, linkedWallet,
		true, false)
	if err != nil {
		return fmt.Errorf("failed to retrieve profile for id='%s', err:%w", id, err)
	}

	return nil
}
