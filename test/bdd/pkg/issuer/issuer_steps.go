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
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Issuer Profile with id "([^"]*)", name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", requiresBlindedRoute "([^"]*)" and supportsAssuranceCred "([^"]*)"$`, // nolint: lll
		e.createProfile)
	s.Step(`^Issuer Profile with id "([^"]*)", name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", requiresBlindedRoute "([^"]*)", supportsAssuranceCred "([^"]*)" and oidc provider "([^"]*)"$`, // nolint: lll
		e.createProfileWithOIDC)
	s.Step(`^Retrieved profile with id "([^"]*)" contains name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", requiresBlindedRoute "([^"]*)" and supportsAssuranceCred "([^"]*)"$`, // nolint: lll
		e.retrieveProfile)
	s.Step(`^Retrieved profile with id "([^"]*)" contains name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", requiresBlindedRoute "([^"]*)", supportsAssuranceCred "([^"]*)" and oidc provider "([^"]*)"$`, // nolint: lll
		e.retrieveProfileWithOIDC)
	s.Step(`^Issuer adapter shows the wallet connect UI when the issuer "([^"]*)" wants to connect to the wallet$`,
		e.walletConnect)
	s.Step(`^Issuer adapter gets oidc authorization for the issuer "([^"]*)"$`,
		e.oidcLogin)
	s.Step(`^Issuer adapter \("([^"]*)"\) creates DIDComm connection invitation for "([^"]*)"$`,
		e.didcommConnectionInvitation)
	s.Step(`^Issuer adapter \("([^"]*)"\) validates response from "([^"]*)" and redirects to "([^"]*)"$`,
		e.validateConnectResp)
	s.Step(`^Issuer has a profile with name "([^"]*)", issuerURL "([^"]*)" and supportedVCContexts "([^"]*)"$`, e.createAndValidateProfile)                                  // nolint: lll
	s.Step(`^Issuer has a profile with name "([^"]*)", issuerURL "([^"]*)", oidc provider "([^"]*)" and supportedVCContexts "([^"]*)"$`, e.createAndValidateProfileWithOIDC) // nolint: lll
}

func (e *Steps) createProfile(id, name, issuerURL, supportedVCContexts,
	requiresBlindedRouteStr, supportsAssuranceCredStr string) error {
	return e.createProfileWithOIDC(id, name, issuerURL, supportedVCContexts,
		requiresBlindedRouteStr, supportsAssuranceCredStr, "")
}

func (e *Steps) createProfileWithOIDC(id, name, issuerURL, supportedVCContexts,
	requiresBlindedRouteStr, supportsAssuranceCredStr, oidcProvider string) error {
	supportsAssuranceCred, err := strconv.ParseBool(supportsAssuranceCredStr)
	if err != nil {
		return err
	}

	requiresBlindedRoute, err := strconv.ParseBool(requiresBlindedRouteStr)
	if err != nil {
		return err
	}

	profileReq := operation.ProfileDataRequest{
		ID:                          id,
		Name:                        name,
		URL:                         issuerURL,
		SupportedVCContexts:         strings.Split(supportedVCContexts, ","),
		SupportsAssuranceCredential: supportsAssuranceCred,
		RequiresBlindedRoute:        requiresBlindedRoute,
		OIDCProviderURL:             oidcProvider,
	}

	requestBytes, err := json.Marshal(profileReq)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, AdapterURL+"/profile", "", "", //nolint: bodyclose
		bytes.NewBuffer(requestBytes), e.bddContext.TLSConfig())

	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusCreated {
		return bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	return nil
}

func (e *Steps) retrieveProfile(id, name, issuerURL, supportedVCContexts,
	requiresBlindedRouteStr, supportsAssuranceCredStr string) error {
	return e.retrieveProfileWithOIDC(id, name, issuerURL, supportedVCContexts,
		requiresBlindedRouteStr, supportsAssuranceCredStr, "")
}

// nolint:funlen,gomnd,gocyclo
func (e *Steps) retrieveProfileWithOIDC(id, name, issuerURL, supportedVCContexts,
	requiresBlindedRouteStr, supportsAssuranceCredStr, oidcProvider string) error {
	resp, err := bddutil.HTTPDo(http.MethodGet, //nolint: bodyclose
		fmt.Sprintf(AdapterURL+"/profile/%s", id), "", "", nil, e.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	profileResponse := &issuerprofile.ProfileData{}

	err = json.Unmarshal(respBytes, profileResponse)
	if err != nil {
		return err
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

	if len(profileResponse.SupportedVCContexts) != len(strings.Split(supportedVCContexts, ",")) {
		return fmt.Errorf("supported vc count doesnt match : expected=%d actual=%d",
			len(strings.Split(supportedVCContexts, ",")), len(profileResponse.SupportedVCContexts))
	}

	supportsAssuranceCred, err := strconv.ParseBool(supportsAssuranceCredStr)
	if err != nil {
		return err
	}

	if profileResponse.SupportsAssuranceCredential != supportsAssuranceCred {
		return fmt.Errorf("profile supports assurance cred doesn't match : expected=%t actual=%t",
			supportsAssuranceCred, profileResponse.SupportsAssuranceCredential)
	}

	requiresBlindedRoute, err := strconv.ParseBool(requiresBlindedRouteStr)
	if err != nil {
		return err
	}

	if profileResponse.RequiresBlindedRoute != requiresBlindedRoute {
		return fmt.Errorf("profile requiresBlindedRoute doesn't match : expected=%t actual=%t",
			supportsAssuranceCred, profileResponse.SupportsAssuranceCredential)
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

func (e *Steps) walletConnect(issuerID string) error {
	state := uuid.New().String()
	e.states[issuerID] = state

	resp, err := bddutil.HTTPDo(http.MethodGet, //nolint: bodyclose
		fmt.Sprintf(AdapterURL+"/%s/connect/wallet?state=%s", issuerID, state), "", "", nil,
		e.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	// validating only status code as the vue page needs javascript support
	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, nil)
	}

	e.txnIDs[issuerID] = resp.Request.URL.Query().Get("txnID")
	e.userIDs[issuerID] = resp.Request.URL.Query().Get("uID")

	return nil
}

func (e *Steps) oidcLogin(issuerID string) error {
	txnID := e.txnIDs[issuerID]
	uID := e.userIDs[issuerID]

	reqData := fmt.Sprintf(`?txnID=%s&uID=%s`, txnID, uID)

	resp, err := bddutil.HTTPDo(http.MethodGet, //nolint: bodyclose
		AdapterURL+"/oidc/request"+reqData, "", "", nil, e.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	// validating only status code as the vue page needs javascript support
	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, body)
	}

	println("body:", string(body))

	return nil
}

func (e *Steps) didcommConnectionInvitation(issuerID, agentID string) error {
	resp, err := bddutil.HTTPDo(http.MethodGet, //nolint: bodyclose
		AdapterURL+"/issuer/didcomm/chapi/request?txnID="+e.txnIDs[issuerID], "", "", nil,
		e.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
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
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, //nolint: bodyclose
		validateURL, "", "", bytes.NewBuffer(requestBytes), e.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	validateResp := &operation.ValidateConnectResp{}

	err = json.Unmarshal(respBytes, validateResp)
	if err != nil {
		return err
	}

	if !strings.Contains(validateResp.RedirectURL, getCallBackURL(issuerURL)) {
		return fmt.Errorf("expected redirectURL contains [%s] for issuer[%s], but got[%s]",
			getCallBackURL(issuerURL), issuerID, validateResp.RedirectURL)
	}

	u, err := url.Parse(validateResp.RedirectURL)
	if err != nil {
		return err
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

	err := e.createProfile(id, name, issuerURL, supportedVCContexts, "false", "false")
	if err != nil {
		return fmt.Errorf("failed to create profile for id='%s', err:%w", id, err)
	}

	err = e.retrieveProfile(id, name, issuerURL, supportedVCContexts, "false", "false")
	if err != nil {
		return fmt.Errorf("failed to retrieve profile for id='%s', err:%w", id, err)
	}

	return nil
}

func (e *Steps) createAndValidateProfileWithOIDC(name, issuerURL, oidcProvider, supportedVCContexts string) error {
	id := uuid.New().String()

	err := e.createProfileWithOIDC(id, name, issuerURL, supportedVCContexts, "false", "false", oidcProvider)
	if err != nil {
		return fmt.Errorf("failed to create profile for id='%s', err:%w", id, err)
	}

	err = e.retrieveProfileWithOIDC(id, name, issuerURL, supportedVCContexts, "false", "false", oidcProvider)
	if err != nil {
		return fmt.Errorf("failed to retrieve profile for id='%s', err:%w", id, err)
	}

	return nil
}
