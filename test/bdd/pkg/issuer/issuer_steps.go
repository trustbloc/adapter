/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cucumber/godog"

	issuerprofile "github.com/trustbloc/edge-adapter/pkg/profile/issuer"
	"github.com/trustbloc/edge-adapter/pkg/restapi/issuer/operation"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/context"
)

const (
	issuerAdapterURL = "http://localhost:9070"
)

// Steps is steps for VC BDD tests.
type Steps struct {
	bddContext *context.BDDContext
	txnIDs     map[string]string
}

// NewSteps returns new agent from client SDK.
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{
		bddContext: ctx,
		txnIDs:     make(map[string]string),
	}
}

// RegisterSteps registers agent steps.
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Issuer Profile with id "([^"]*)", name "([^"]*)" and callbackURL "([^"]*)"$`, e.createProfile)
	s.Step(`^Retrieved profile with id "([^"]*)" contains name "([^"]*)" and callbackURL "([^"]*)"$`, e.retrieveProfile)
	s.Step(`^Issuer adapter shows the wallet connect UI when the issuer "([^"]*)" wants to connect to the wallet$`,
		e.walletConnect)
	s.Step(`^Issuer adapter \("([^"]*)"\) creates DIDExchange request for "([^"]*)"$`, e.didExchangeRequest)
	s.Step(`^Issuer adapter \("([^"]*)"\) validates response from "([^"]*)" and redirects to "([^"]*)"$`,
		e.validateConnectResp)
}

func (e *Steps) createProfile(id, name, callbackURL string) error {
	profileReq := issuerprofile.ProfileData{
		ID:          id,
		Name:        name,
		CallbackURL: callbackURL,
	}

	requestBytes, err := json.Marshal(profileReq)
	if err != nil {
		return nil
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, issuerAdapterURL+"/profile", "", "", //nolint: bodyclose
		bytes.NewBuffer(requestBytes))

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

func (e *Steps) retrieveProfile(id, name, callbackURL string) error {
	resp, err := bddutil.HTTPDo(http.MethodGet, //nolint: bodyclose
		fmt.Sprintf(issuerAdapterURL+"/profile/%s", id), "", "", nil)
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

	if profileResponse.CallbackURL != callbackURL {
		return fmt.Errorf("profile callback url doesn't match : expected=%s actual=%s",
			callbackURL, profileResponse.CallbackURL)
	}

	return nil
}

func (e *Steps) walletConnect(issuerID string) error {
	resp, err := bddutil.HTTPDo(http.MethodGet, //nolint: bodyclose
		fmt.Sprintf(issuerAdapterURL+"/%s/connect/wallet", issuerID), "", "", nil)
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	// validating only status code as the vue page needs javascript support
	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, nil)
	}

	e.txnIDs[issuerID] = resp.Request.URL.Query().Get("txnID")

	return nil
}

func (e *Steps) didExchangeRequest(issuerID, agentID string) error {
	resp, err := bddutil.HTTPDo(http.MethodGet, //nolint: bodyclose
		issuerAdapterURL+"/issuer/didcomm/invitation?txnID="+e.txnIDs[issuerID], "", "", nil)
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, nil)
	}

	// Mocking CHAPI request call
	e.bddContext.Store[bddutil.GetDIDConnectRequestKey(issuerID, agentID)] = string(respBytes)

	return nil
}

func (e *Steps) validateConnectResp(issuerID, agentID, callbackURL string) error {
	url := issuerAdapterURL + "/connect/validate?txnID=" + e.txnIDs[issuerID]
	vp := e.bddContext.Store[bddutil.GetDIDConnectResponseKey(issuerID, agentID)]

	profileReq := operation.WalletConnect{
		Resp: []byte(vp),
	}

	requestBytes, err := json.Marshal(profileReq)
	if err != nil {
		return nil
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, //nolint: bodyclose
		url, "", "", bytes.NewBuffer(requestBytes))
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

	if validateResp.RedirectURL != callbackURL {
		return fmt.Errorf("expected redirectURL[%s] for issuer[%s], but got[%s]", callbackURL, issuerID,
			validateResp.RedirectURL)
	}

	return nil
}
