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
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"

	issuerprofile "github.com/trustbloc/edge-adapter/pkg/profile/issuer"
	"github.com/trustbloc/edge-adapter/pkg/restapi/issuer/operation"
	walletops "github.com/trustbloc/edge-adapter/pkg/restapi/wallet/operation"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/agent"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/context"
)

const (
	issuerAdapterURL = "https://localhost:9070"
	msgReplyEndpoint = "/message/reply"

	chapiResponseMsgType = "https://trustbloc.dev/chapi/1.0/response"

	//nolint: lll
	sampleVP = `{
	    "@context": [
	        "https://www.w3.org/2018/credentials/v1"
    	],
    	"type": "VerifiablePresentation",
    	"verifiableCredential": [{
        	"@context": [
        	    "https://www.w3.org/2018/credentials/v1",
    	        "https://www.w3.org/2018/credentials/examples/v1",
	            "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld"
        	],
        	"id": "http://example.gov/credentials/3732",
        	"type": ["VerifiableCredential", "UniversityDegreeCredential"],
        	"name": "Bachelor Degree",
        	"description": "Bachelor of Science and Arts of Mr.John Smith",
        	"issuer": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
        	"issuanceDate": "2020-03-16T22:37:26.544Z",
        	"credentialSubject": {
            	"id": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
            	"degree": {"type": "BachelorDegree", "name": "Bachelor of Science and Arts"}
        	},
        	"proof": {
            	"type": "Ed25519Signature2018",
            	"created": "2020-03-16T22:37:26Z",
            	"verificationMethod": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
            	"proofPurpose": "assertionMethod",
            	"jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..7gJwYBvJuXYrFa_hpuWxknm3R5Czas_NDL-Bh7LnURA1PwjH0uBqMy4W4pgYeat3xYa12gZBkmIR0VmgY3qQCw"
        	}
    	}]
	}`

	sampleCHAPIStoreResponse = `{
                dataType: "response",
                data: "success"
            }`
)

// Steps is steps for VC BDD tests.
type Steps struct {
	bddContext *context.BDDContext
	txnIDs     map[string]string
	states     map[string]string
}

// NewSteps returns new agent from client SDK.
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{
		bddContext: ctx,
		txnIDs:     make(map[string]string),
		states:     make(map[string]string),
	}
}

// RegisterSteps registers agent steps.
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Issuer Profile with id "([^"]*)", name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", requiresBlindedRoute "([^"]*)" and supportsAssuranceCred "([^"]*)"$`, // nolint: lll
		e.createProfile)
	s.Step(`^Retrieved profile with id "([^"]*)" contains name "([^"]*)", issuerURL "([^"]*)", supportedVCContexts "([^"]*)", requiresBlindedRoute "([^"]*)" and supportsAssuranceCred "([^"]*)"$`, // nolint: lll
		e.retrieveProfile)
	s.Step(`^Issuer adapter shows the wallet connect UI when the issuer "([^"]*)" wants to connect to the wallet$`,
		e.walletConnect)
	s.Step(`^Issuer adapter \("([^"]*)"\) creates DIDComm connection invitation for "([^"]*)"$`,
		e.didcommConnectionInvitation)
	s.Step(`^Issuer adapter \("([^"]*)"\) validates response from "([^"]*)" and redirects to "([^"]*)"$`,
		e.validateConnectResp)
	s.Step(`^Issuer has a profile with name "([^"]*)", issuerURL "([^"]*)" and supportedVCContexts "([^"]*)"$`, e.createAndValidateProfile)                                  // nolint: lll
	s.Step(`^issuer creates a deep link to invite remote wallet user "([^"]*)" to connect$`, e.createWalletBridgeInvitation)                                                 // nolint: lll
	s.Step(`^Issuer checks wallet application profile for "([^"]*)" it finds profile status as "([^"]*)"$`, e.checkWalletProfileStatus)                                      // nolint: lll
	s.Step(`^issuer sends store credential request to remote wallet of "([^"]*)" and gets response back remote wallet app "([^"]*)"$`, e.sendCHAPIRequestToRemoteWalletUser) // nolint: lll
}

func (e *Steps) createProfile(id, name, issuerURL, supportedVCContexts,
	requiresBlindedRouteStr, supportsAssuranceCredStr string) error {
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
	}

	requestBytes, err := json.Marshal(profileReq)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, issuerAdapterURL+"/profile", "", "", //nolint: bodyclose
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

// nolint:funlen,gomnd,gocyclo
func (e *Steps) retrieveProfile(id, name, issuerURL, supportedVCContexts,
	requiresBlindedRouteStr, supportsAssuranceCredStr string) error {
	resp, err := bddutil.HTTPDo(http.MethodGet, //nolint: bodyclose
		fmt.Sprintf(issuerAdapterURL+"/profile/%s", id), "", "", nil, e.bddContext.TLSConfig())
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
		fmt.Sprintf(issuerAdapterURL+"/%s/connect/wallet?state=%s", issuerID, state), "", "", nil,
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

	return nil
}

func (e *Steps) didcommConnectionInvitation(issuerID, agentID string) error {
	resp, err := bddutil.HTTPDo(http.MethodGet, //nolint: bodyclose
		issuerAdapterURL+"/issuer/didcomm/chapi/request?txnID="+e.txnIDs[issuerID], "", "", nil,
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
	validateURL := issuerAdapterURL + "/connect/validate?txnID=" + e.txnIDs[issuerID]

	vp, found := e.bddContext.GetString(bddutil.GetDIDConnectResponseKey(issuerID, agentID))
	if !found {
		return fmt.Errorf("VP not found")
	}

	profileReq := operation.WalletConnect{
		Resp: []byte(vp),
	}

	requestBytes, err := json.Marshal(profileReq)
	if err != nil {
		return nil
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

func (e *Steps) createWalletBridgeInvitation(userID string) error {
	rqBytes, err := json.Marshal(&walletops.CreateInvitationRequest{
		UserID: userID,
	})
	if err != nil {
		return fmt.Errorf("failed to prepare request for creating wallet-bridge invitation: %w", err)
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, issuerAdapterURL+"/wallet-bridge/create-invitation", //nolint: bodyclose
		"", "", bytes.NewBuffer(rqBytes), e.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	// validating only status code as the vue page needs javascript support
	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, nil)
	}

	response := &walletops.CreateInvitationResponse{}

	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return fmt.Errorf("failed to read response from wallet-bridge create-invitation: %w", err)
	}

	if response.URL == "" {
		return fmt.Errorf("failed to get valid invitation URL from wallet-bridge")
	}

	e.bddContext.Store[bddutil.GetDeepLinkWalletInvitationKey(userID)] = response.URL

	return nil
}

func (e *Steps) checkWalletProfileStatus(userID, status string) error {
	rqBytes, err := json.Marshal(&walletops.ApplicationProfileRequest{
		UserID: userID,
	})
	if err != nil {
		return fmt.Errorf("failed to prepare request for creating wallet-bridge invitation: %w", err)
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, issuerAdapterURL+"/wallet-bridge/request-app-profile", //nolint: bodyclose
		"", "", bytes.NewBuffer(rqBytes), e.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, nil)
	}

	response := &walletops.ApplicationProfileResponse{}

	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return fmt.Errorf("failed to read response from wallet-bridge create-invitation: %w", err)
	}

	if response.ConnectionStatus != status {
		return fmt.Errorf("wallet application profile is not '%s'", status)
	}

	return nil
}

func (e *Steps) sendCHAPIRequestToRemoteWalletUser(userID, walletID string) error {
	walletInfoVal, found := e.bddContext.Get(bddutil.GetRemoteWalletAppInfo(walletID))
	if !found {
		return fmt.Errorf("failed to get test wallet info by id='%s'", walletID)
	}

	walletInfo, ok := walletInfoVal.(struct {
		WebhookURL    string
		ControllerURL string
		MessageHandle string
	})
	if !ok {
		return fmt.Errorf("invalid test wallet info")
	}

	go func() {
		failure := e.handleCHAPIStoreRequest(walletInfo.ControllerURL, walletInfo.WebhookURL, walletInfo.MessageHandle)
		if failure != nil {
			panic(fmt.Sprintf("failed to reply with chapi response: %s", failure.Error()))
		}
	}()

	rqBytes, err := json.Marshal(&walletops.CHAPIRequest{
		UserID:  userID,
		Request: []byte(sampleVP),
	})
	if err != nil {
		return fmt.Errorf("failed to prepare request for creating wallet-bridge invitation: %w", err)
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, issuerAdapterURL+"/wallet-bridge/send-chapi-request", //nolint: bodyclose
		"", "", bytes.NewBuffer(rqBytes), e.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, nil)
	}

	response := &walletops.CHAPIResponse{}

	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return fmt.Errorf("failed to read response from wallet-bridge create-invitation: %w", err)
	}

	return nil
}

func (e *Steps) handleCHAPIStoreRequest(controllerURL, webhookURL, msgHandle string) error {
	msg, err := agent.PullMsgFromWebhookURL(webhookURL, msgHandle)
	if err != nil {
		return err
	}

	incoming := struct {
		Message service.DIDCommMsgMap `json:"message"`
	}{}

	err = msg.Decode(&incoming)
	if err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	}

	msgDataBytes, err := json.Marshal(map[string]interface{}{
		"@id":   uuid.New().String(),
		"@type": chapiResponseMsgType,
		"data":  []byte(sampleCHAPIStoreResponse),
	})
	if err != nil {
		return err
	}

	request := &messaging.SendReplyMessageArgs{
		MessageID:   incoming.Message.ID(),
		MessageBody: msgDataBytes,
	}

	msgBytes, err := json.Marshal(request)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, controllerURL+msgReplyEndpoint, //nolint: bodyclose
		"", "", bytes.NewBuffer(msgBytes), e.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, nil)
	}

	return nil
}
