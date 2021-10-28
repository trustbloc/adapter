/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"

	walletops "github.com/trustbloc/edge-adapter/pkg/restapi/wallet/operation"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/agent"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/context"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/issuer"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/rp"
)

const (
	msgReplyEndpoint             = "/message/reply"
	createWalletBridgeInvitation = "/wallet-bridge/create-invitation"
	requestAppProfileStatus      = "/wallet-bridge/request-app-profile"
	sendCHAPIRequest             = "/wallet-bridge/send-chapi-request"

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
	sampleCHAPIGetRequest = `{
   	 "web": {
        	"VerifiablePresentation": {
            	"query": {
                	"type": "DIDAuth"
            	},
            	"challenge": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc",
            	"domain": "example.com"
        	}
    	}
	}`

	sampleCHAPIStoreResponse = `{
                "dataType": "response",
                "data": "success"
            }`
	//nolint: lll
	sampleCHAPIGetResponse = `{
  			"@context": [
  		    	"https://www.w3.org/2018/credentials/v1"
			],
    		"holder": "did:trustbloc:4vSjd:EiCpyXBU6bBluyIBkDGLFEIJ5wqqfcSIXgqSLSV19f-e2g",
    		"proof": {
      			"challenge": "c62f893b-f40b-44ee-bfd4-b19810d46ea3",
      			"created": "2021-01-27T17:47:53.586-05:00",
      			"domain": "example.com",
      			"jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..m-PFo2gPpZBxLon9h5MZ6dnBksAZxuY4S0DrA8_NmL8BjfN0plln7lk14PubTbIOB3l0BQ-xi1BETK5l-jSBBg",
      			"proofPurpose": "authentication",
      			"type": "Ed25519Signature2018",
      			"verificationMethod": "did:trustbloc:4vSjd:EiCpyXBU6bBluyIBkDGLFEIJ5wqqfcSIXgqSLSV19f-e2g#zwjIRMCMFQKNqYW96V_WxptPMmuMQoizTdxKuBvc1HM"
    		},
    		"type": "VerifiablePresentation"
  		}`
)

// WalletSteps is steps for wallet bridge BDD tests.
type WalletSteps struct {
	bddContext *context.BDDContext
}

// NewWalletSteps returns new common wallet bridge steps from client SDK.
func NewWalletSteps(ctx *context.BDDContext) *WalletSteps {
	return &WalletSteps{bddContext: ctx}
}

// RegisterSteps registers agent steps.
func (e *WalletSteps) RegisterSteps(s *godog.Suite) {
	// issuer steps
	s.Step(`^issuer creates a deep link to invite remote wallet user "([^"]*)" to connect$`, e.createWalletBridgeInvitationForIssuer)                                             // nolint: lll
	s.Step(`^Issuer checks wallet application profile for "([^"]*)" it finds profile status as "([^"]*)"$`, e.checkWalletProfileStatusForIssuer)                                  // nolint: lll
	s.Step(`^issuer sends store credential request to remote wallet of "([^"]*)" and gets response back remote wallet app "([^"]*)"$`, e.sendCHAPIStoreRequestToRemoteWalletUser) // nolint: lll

	// rp steps
	s.Step(`^rp tenant creates a deep link to invite remote wallet user "([^"]*)" to connect$`, e.createWalletBridgeInvitationForRP)                                               // nolint: lll
	s.Step(`^rp tenant checks wallet application profile for "([^"]*)" it finds profile status as "([^"]*)"$`, e.checkWalletProfileStatusForRP)                                    // nolint: lll
	s.Step(`^rp tenant sends store credential request to remote wallet of "([^"]*)" and gets response back remote wallet app "([^"]*)"$`, e.sendCHAPIGetRequestToRemoteWalletUser) // nolint: lll
}

func (e *WalletSteps) createWalletBridgeInvitationForIssuer(userID string) error {
	return e.createWalletBridgeInvitation(issuer.AdapterURL, userID)
}

func (e *WalletSteps) createWalletBridgeInvitationForRP(userID string) error {
	return e.createWalletBridgeInvitation(rp.AdapterURL, userID)
}

func (e *WalletSteps) checkWalletProfileStatusForIssuer(userID, status string) error {
	return e.checkWalletProfileStatus(issuer.AdapterURL, userID, status)
}

func (e *WalletSteps) checkWalletProfileStatusForRP(userID, status string) error {
	return e.checkWalletProfileStatus(rp.AdapterURL, userID, status)
}

func (e *WalletSteps) sendCHAPIStoreRequestToRemoteWalletUser(userID, walletID string) error {
	return e.sendCHAPIRequestToRemoteWalletUser(issuer.AdapterURL, userID, walletID,
		[]byte(sampleVP), sampleCHAPIStoreResponse)
}

func (e *WalletSteps) sendCHAPIGetRequestToRemoteWalletUser(userID, walletID string) error {
	return e.sendCHAPIRequestToRemoteWalletUser(rp.AdapterURL, userID, walletID,
		[]byte(sampleCHAPIGetRequest), sampleCHAPIGetResponse)
}

func (e *WalletSteps) createWalletBridgeInvitation(adapterURL, userID string) error {
	rqBytes, err := json.Marshal(&walletops.CreateInvitationRequest{
		UserID: userID,
	})
	if err != nil {
		return fmt.Errorf("failed to prepare request for creating wallet-bridge invitation: %w", err)
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, adapterURL+createWalletBridgeInvitation, //nolint: bodyclose
		"", "", bytes.NewBuffer(rqBytes), e.bddContext.TLSConfig())
	if err != nil {
		return fmt.Errorf("failed to execeute request: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	// validating only status code as the vue page needs javascript support
	if resp.StatusCode != http.StatusOK {
		// nolint:wrapcheck // ignore
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

func (e *WalletSteps) checkWalletProfileStatus(adapterURL, userID, status string) error {
	rqBytes, err := json.Marshal(&walletops.ApplicationProfileRequest{
		UserID: userID,
	})
	if err != nil {
		return fmt.Errorf("failed to prepare request for creating wallet-bridge invitation: %w", err)
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, adapterURL+requestAppProfileStatus, //nolint: bodyclose
		"", "", bytes.NewBuffer(rqBytes), e.bddContext.TLSConfig())
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// nolint:wrapcheck // ignore
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

// nolint:funlen
func (e *WalletSteps) sendCHAPIRequestToRemoteWalletUser(adapterURL, userID, walletID string,
	chapiRqst json.RawMessage, expectedResponse string) error {
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
		if failure := e.handleCHAPIStoreRequest(walletInfo.ControllerURL, walletInfo.WebhookURL,
			walletInfo.MessageHandle, expectedResponse); failure != nil {
			panic(fmt.Sprintf("failed to reply with chapi response: %s", failure.Error()))
		}
	}()

	rqBytes, err := json.Marshal(&walletops.CHAPIRequest{
		UserID:  userID,
		Payload: chapiRqst,
	})
	if err != nil {
		return fmt.Errorf("failed to prepare request for creating wallet-bridge invitation: %w", err)
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, adapterURL+sendCHAPIRequest, //nolint: bodyclose
		"", "", bytes.NewBuffer(rqBytes), e.bddContext.TLSConfig())
	if err != nil {
		return fmt.Errorf("failed to failed to execute request: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// nolint:wrapcheck // ignore
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, nil)
	}

	response := &walletops.CHAPIResponse{}

	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return fmt.Errorf("failed to read response from wallet-bridge send CHAPI request: %w", err)
	}

	result, err := bddutil.JSONBytesEqual(response.Data, []byte(expectedResponse))
	if err != nil {
		return fmt.Errorf("failed to assert CHAPI response: %w", err)
	}

	if !result {
		return fmt.Errorf("unexpected CHAPI response, \n expected `%s` \nbut got :`%s`",
			expectedResponse, string(response.Data))
	}

	return nil
}

func (e *WalletSteps) handleCHAPIStoreRequest(controllerURL, webhookURL, msgHandle,
	expectedResponse string) error {
	incoming, err := agent.PullMsgFromWebhookURL(webhookURL, msgHandle, nil)
	if err != nil {
		return fmt.Errorf("failed to pull msg from webhook: %w", err)
	}

	msgDataBytes, err := json.Marshal(map[string]interface{}{
		"@id":   uuid.New().String(),
		"@type": chapiResponseMsgType,
		"data":  json.RawMessage(expectedResponse),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal msg: %w", err)
	}

	request := &messaging.SendReplyMessageArgs{
		MessageID:   incoming.ID(),
		MessageBody: msgDataBytes,
	}

	msgBytes, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, controllerURL+msgReplyEndpoint, //nolint: bodyclose
		"", "", bytes.NewBuffer(msgBytes), e.bddContext.TLSConfig())
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// nolint:wrapcheck // ignore
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, nil)
	}

	return nil
}
