/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package agent

import (
	"bytes"
	goctx "context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	issuecredclient "github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	issuecredcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
	presentproofcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
	verifiablecmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	issuecredsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/edge-core/pkg/log"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/trustbloc/edge-adapter/pkg/vc/issuer"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/context"
)

const (
	completedState = "completed"
	timeoutWS      = 3 * time.Second

	connOperationID       = "/connections"
	receiveInvitationPath = connOperationID + "/receive-invitation"
	acceptInvitationPath  = connOperationID + "/%s/accept-invitation"
	connectionsByID       = connOperationID + "/{id}"

	issueCredOperationID = "/issuecredential"
	sendCredRequest      = issueCredOperationID + "/send-request"
	issueCredActions     = issueCredOperationID + "/actions"
	acceptCredentialPath = issueCredOperationID + "/%s/accept-credential"

	presentProofOperationID = "/presentproof"
	sendRequestPresentation = presentProofOperationID + "/send-request-presentation"
	acceptPresentationPath  = presentProofOperationID + "/%s/accept-presentation"
	presentProofActions     = presentProofOperationID + "/actions"
)

var logger = log.New("edge-adapter/tests")

// Steps contains steps for aries agent.
type Steps struct {
	bddContext         *context.BDDContext
	ControllerURLs     map[string]string
	WebhookURLs        map[string]string
	webSocketConns     map[string]*websocket.Conn
	adapterConnections map[string]*didexchange.Connection
}

// NewSteps returns new agent steps.
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{
		bddContext:         ctx,
		ControllerURLs:     make(map[string]string),
		WebhookURLs:        make(map[string]string),
		webSocketConns:     make(map[string]*websocket.Conn),
		adapterConnections: make(map[string]*didexchange.Connection),
	}
}

// RegisterSteps registers agent steps.
func (a *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with controller "([^"]*)"$`,
		a.ValidateAgentConnection)
	s.Step(`^"([^"]*)" responds to connect request from Issuer adapter \("([^"]*)"\) within "([^"]*)" seconds$`,
		a.handleDIDConnectRequest)
	s.Step(`^"([^"]*)" sends request credential message and receives credential from the issuer \("([^"]*)"\)$`,
		a.fetchCredential)
	s.Step(`^"([^"]*)" sends present proof request message and receives presentation from the issuer \("([^"]*)"\)$`,
		a.fetchPresentation)
}

// ValidateAgentConnection checks if the controller agent is running.
func (a *Steps) ValidateAgentConnection(agentID, inboundHost,
	inboundPort, controllerURL string) error {
	if err := a.checkAgentIsRunning(agentID, controllerURL); err != nil {
		return err
	}

	// verify inbound
	if err := a.healthCheck(fmt.Sprintf("http://%s:%s", inboundHost, inboundPort)); err != nil {
		logger.Debugf("Unable to reach inbound '%s' for agent '%s', cause : %s", controllerURL, agentID, err)
		return err
	}

	logger.Debugf("Agent '%s' running inbound on '%s' and port '%s'", agentID, inboundHost, inboundPort)

	return nil
}

func (a *Steps) checkAgentIsRunning(agentID, controllerURL string) error {
	// verify controller
	err := a.healthCheck(controllerURL)
	if err != nil {
		logger.Debugf("Unable to reach controller '%s' for agent '%s', cause : %s", controllerURL, agentID, err)
		return err
	}

	logger.Debugf("Agent '%s' running controller '%s'", agentID, controllerURL)

	a.ControllerURLs[agentID] = controllerURL

	// create and register websocket connection for notifications
	u, err := url.Parse(controllerURL)
	if err != nil {
		return fmt.Errorf("invalid controller URL [%s]", controllerURL)
	}

	wsURL := fmt.Sprintf("ws://%s%s/ws", u.Host, u.Path)

	ctx, cancel := goctx.WithTimeout(goctx.Background(), timeoutWS)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, nil) //nolint:bodyclose
	if err != nil {
		return fmt.Errorf("failed to dial connection from '%s' : %w", wsURL, err)
	}

	a.webSocketConns[agentID] = conn

	return nil
}

func (a *Steps) healthCheck(endpoint string) error {
	if strings.HasPrefix(endpoint, "http") {
		resp, err := http.Get(endpoint) //nolint: gosec
		if err != nil {
			return err
		}

		err = resp.Body.Close()
		if err != nil {
			logger.Errorf("Failed to close response body : %s", err)
		}

		return nil
	}

	return errors.New("url scheme is not supported for url = " + endpoint)
}

func (a *Steps) handleDIDConnectRequest(agentID, issuerID string, timeout int) error {
	// Mock CHAPI request from Issuer
	invitationJSON := a.bddContext.Store[bddutil.GetDIDConnectRequestKey(issuerID, agentID)]

	connectionID, err := a.ReceiveInvitation(agentID, invitationJSON)
	if err != nil {
		return err
	}

	err = a.ApproveInvitation(agentID)
	if err != nil {
		return err
	}

	// Added to mock CHAPI timeout (ie, DIDExchange should happen with this duration)
	time.Sleep(time.Duration(timeout) * time.Second)

	conn, err := a.ValidateConnection(agentID, connectionID)
	if err != nil {
		return err
	}

	subject := issuer.DIDConnectCredentialSubject{
		ID:              connectionID,
		InviteeDID:      conn.MyDID,
		InviterDID:      conn.TheirDID,
		InviterLabel:    "my-label",
		ThreadID:        conn.ThreadID,
		ConnectionState: "completed",
	}

	vc := verifiable.Credential{
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		Types:   []string{"VerifiableCredential", issuer.DIDConnectCredentialType},
		Issuer:  verifiable.Issuer{ID: "did:example:123"},
		Issued:  util.NewTime(time.Now().UTC()),
		Subject: subject,
	}

	vp, err := vc.Presentation()
	if err != nil {
		return err
	}

	vpJSON, err := vp.MarshalJSON()
	if err != nil {
		return err
	}

	a.bddContext.Store[bddutil.GetDIDConnectResponseKey(issuerID, agentID)] = string(vpJSON)

	return nil
}

// ValidateConnection retrieves the agent's connection record and tests whether its state is completed.
func (a *Steps) ValidateConnection(agentID, connID string) (*didexchange.Connection, error) {
	conn, err := a.getConnection(agentID, connID)
	if err != nil {
		return nil, err
	}

	// Verify state
	if conn.State != completedState {
		return nil, fmt.Errorf("expected state[%s] for agent[%s], but got[%s]", completedState, agentID, conn.State)
	}

	a.adapterConnections[agentID] = conn

	return conn, nil
}

// ReceiveInvitation will make the agent accept the given invitation.
func (a *Steps) ReceiveInvitation(agentID, invitation string) (string, error) {
	destination, ok := a.ControllerURLs[agentID]
	if !ok {
		return "", fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	// call controller
	var result didexcmd.ReceiveInvitationResponse

	err := sendHTTP(http.MethodPost, destination+receiveInvitationPath, []byte(invitation), &result)
	if err != nil {
		logger.Errorf("Failed to perform receive invitation, cause : %s", err)
		return "", err
	}

	// validate payload
	if result.ConnectionID == "" {
		return "", fmt.Errorf("failed to get valid payload from receive invitation call for agent [%s]", agentID)
	}

	return result.ConnectionID, nil
}

// ApproveInvitation will make the agent approve any outstanding invitations.
func (a *Steps) ApproveInvitation(agentID string) error {
	connectionID, err := a.pullEventsFromWebSocket(agentID, "invited")
	if err != nil {
		return fmt.Errorf("approve exchange invitation : %w", err)
	}

	var response didexcmd.AcceptInvitationResponse

	err = a.performApprove(agentID, connectionID, acceptInvitationPath, &response)
	if err != nil {
		return err
	}

	if response.ConnectionID == "" {
		return fmt.Errorf("failed to perform approve invitation, invalid response")
	}

	return nil
}

func (a *Steps) performApprove(agentID, connectionID, operationPath string, response interface{}) error {
	controllerURL, ok := a.ControllerURLs[agentID]
	if !ok {
		return fmt.Errorf("unable to find contoller URL for agent [%s]", controllerURL)
	}

	path := controllerURL + fmt.Sprintf(operationPath, connectionID)

	err := sendHTTP(http.MethodPost, path, nil, &response)
	if err != nil {
		return fmt.Errorf("failed to perform approve request : %w", err)
	}

	return nil
}

func (a *Steps) getConnection(agentID, connectionID string) (*didexchange.Connection, error) {
	destination, ok := a.ControllerURLs[agentID]
	if !ok {
		return nil, fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	// call controller
	var response didexcmd.QueryConnectionResponse

	err := sendHTTP(http.MethodGet, destination+strings.Replace(connectionsByID, "{id}", connectionID, 1), nil, &response)
	if err != nil {
		logger.Errorf("Failed to perform receive invitation, cause : %s", err)
		return nil, err
	}

	return response.Result, nil
}

func (a *Steps) pullEventsFromWebSocket(agentID, state string) (string, error) {
	conn, ok := a.webSocketConns[agentID]
	if !ok {
		return "", fmt.Errorf("unable to get websocket conn for agent [%s]", agentID)
	}

	ctx, cancel := goctx.WithTimeout(goctx.Background(), timeoutWS)
	defer cancel()

	var incoming struct {
		ID      string `json:"id"`
		Topic   string `json:"topic"`
		Message struct {
			StateID    string
			Properties map[string]string
			Type       string
		} `json:"message"`
	}

	for {
		err := wsjson.Read(ctx, conn, &incoming)
		if err != nil {
			return "", fmt.Errorf("failed to get topics for agent '%s' : %w", agentID, err)
		}

		if incoming.Topic == "didexchange_states" && incoming.Message.Type == "post_state" {
			if strings.EqualFold(state, incoming.Message.StateID) {
				logger.Debugf("Able to find webhook topic with expected state[%s] for agent[%s] and connection[%s]",
					incoming.Message.StateID, agentID, incoming.Message.Properties["connectionID"])

				return incoming.Message.Properties["connectionID"], nil
			}
		}
	}
}

func (a *Steps) fetchCredential(agentID, issuerID string) error {
	conn, ok := a.adapterConnections[agentID]
	if !ok {
		return fmt.Errorf("unable to find the issuer adapter connection data [%s]", agentID)
	}

	controllerURL, ok := a.ControllerURLs[agentID]
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	req := &issuecredcmd.SendRequestArgs{
		MyDID:             conn.MyDID,
		TheirDID:          conn.TheirDID,
		RequestCredential: &issuecredclient.RequestCredential{},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed marshal issue-credential send request : %w", err)
	}

	err = sendHTTP(http.MethodPost, controllerURL+sendCredRequest, reqBytes, nil)
	if err != nil {
		return fmt.Errorf("[issue-credential] failed to send request : %w", err)
	}

	piid, err := actionPIID(controllerURL, issueCredActions)
	if err != nil {
		return err
	}

	credentialName := uuid.New().String()

	err = acceptCredential(piid, credentialName, controllerURL)
	if err != nil {
		return fmt.Errorf("[issue-credential] failed to accept credential : %w", err)
	}

	err = validateCredential(credentialName, controllerURL)
	if err != nil {
		return fmt.Errorf("[issue-credential] failed to validate credential : %w", err)
	}

	return nil
}

func (a *Steps) fetchPresentation(agentID, issuerID string) error {
	conn, ok := a.adapterConnections[agentID]
	if !ok {
		return fmt.Errorf("unable to find the issuer connection data [%s]", agentID)
	}

	controllerURL, ok := a.ControllerURLs[agentID]
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	// send presentation request
	err := sendPresentationRequest(conn, controllerURL)
	if err != nil {
		return err
	}

	// receive presentation
	piid, err := actionPIID(controllerURL, presentProofActions)
	if err != nil {
		return err
	}

	// accept presentation
	presentationName := uuid.New().String()

	err = acceptPresentation(piid, presentationName, controllerURL)
	if err != nil {
		return err
	}

	// validate presentation
	err = validatePresentation(presentationName, controllerURL)
	if err != nil {
		return err
	}

	return nil
}

func sendPresentationRequest(conn *didexchange.Connection, controllerURL string) error {
	req := &presentproofcmd.SendRequestPresentationArgs{
		MyDID:               conn.MyDID,
		TheirDID:            conn.TheirDID,
		RequestPresentation: &presentproof.RequestPresentation{},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	err = sendHTTP(http.MethodPost, controllerURL+sendRequestPresentation, reqBytes, nil)
	if err != nil {
		return err
	}

	return nil
}

func acceptCredential(piid, credentialName, controllerURL string) error {
	req := issuecredcmd.AcceptCredentialArgs{
		Names: []string{credentialName},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to perform approve request : %w", err)
	}

	err = sendHTTP(http.MethodPost, controllerURL+fmt.Sprintf(acceptCredentialPath, piid), reqBytes, nil)
	if err != nil {
		return fmt.Errorf("failed to perform approve request : %w", err)
	}

	return nil
}

func validateCredential(credentialName, controllerURL string) error { // nolint: funlen
	// TODO use listener rather than polling (update once aries bdd-tests are refactored)
	const (
		timeoutWait = 10 * time.Second
		retryDelay  = 500 * time.Millisecond
	)

	start := time.Now()

	for {
		if time.Since(start) > timeoutWait {
			break
		}

		var result struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}

		err := sendHTTP(http.MethodGet,
			fmt.Sprintf("%s/verifiable/credential/name/%s", controllerURL, credentialName), nil, &result)
		if err != nil {
			time.Sleep(retryDelay)
			continue
		}

		var getVCResp struct {
			VC string `json:"verifiableCredential"`
		}

		err = sendHTTP(http.MethodGet,
			fmt.Sprintf("%s/verifiable/credential/%s", controllerURL,
				base64.StdEncoding.EncodeToString([]byte(result.ID))), nil, &getVCResp)
		if err != nil {
			return err
		}

		vc, err := verifiable.ParseCredential([]byte(getVCResp.VC))
		if err != nil {
			return err
		}

		if !bddutil.StringsContains(issuer.DIDCommInitCredentialType, vc.Types) {
			return fmt.Errorf("missing vc type : %s", issuer.DIDCommInitCredentialType)
		}

		didCommInit := &struct {
			Subject *issuer.DIDCommInitCredentialSubject `json:"credentialSubject"`
		}{}

		err = bddutil.DecodeJSONMarshaller(vc, &didCommInit)
		if err != nil {
			return fmt.Errorf("failed to parse credential : %s", err.Error())
		}

		didDoc, err := did.ParseDocument(didCommInit.Subject.DIDDoc)
		if err != nil {
			return err
		}

		if strings.Split(didDoc.ID, ":")[1] != "peer" {
			return fmt.Errorf("unexpected did method : expected=%s actual=%s", "peer",
				strings.Split(didDoc.ID, ":")[1])
		}

		return nil
	}

	return fmt.Errorf("failed to validate credential: not found")
}

func acceptPresentation(piid, presentationName, controllerURL string) error {
	acceptReq := &presentproofcmd.AcceptPresentationArgs{
		Names: []string{presentationName},
	}

	acceptReqBytes, err := json.Marshal(acceptReq)
	if err != nil {
		return err
	}

	err = sendHTTP(http.MethodPost, controllerURL+fmt.Sprintf(acceptPresentationPath, piid), acceptReqBytes, nil)
	if err != nil {
		return err
	}

	return nil
}

func validatePresentation(presentationName, controllerURL string) error {
	var result verifiablecmd.RecordResult
	if err := sendHTTP(http.MethodGet, controllerURL+"/verifiable/presentations", nil, &result); err != nil {
		return err
	}

	for _, val := range result.Result {
		if val.Name == presentationName {
			return nil
		}
	}

	return nil
}

func actionPIID(endpoint, urlPath string) (string, error) {
	// TODO use listener rather than polling (update once aries bdd-tests are refactored)
	const (
		timeoutWait = 10 * time.Second
		retryDelay  = 500 * time.Millisecond
	)

	start := time.Now()

	for {
		if time.Since(start) > timeoutWait {
			break
		}

		var result struct {
			Actions []issuecredsvc.Action `json:"actions"`
		}

		err := sendHTTP(http.MethodGet, endpoint+urlPath, nil, &result)
		if err != nil {
			return "", fmt.Errorf("failed to get action PIID: %w", err)
		}

		if len(result.Actions) == 0 {
			time.Sleep(retryDelay)
			continue
		}

		return result.Actions[0].PIID, nil
	}

	return "", fmt.Errorf("unable to get action PIID: timeout")
}

func sendHTTP(method, destination string, message []byte, result interface{}) error {
	// create request
	req, err := http.NewRequest(method, destination, bytes.NewBuffer(message))
	if err != nil {
		return fmt.Errorf("failed to create new http '%s' request for '%s', cause: %s", method, destination, err)
	}

	// set headers
	req.Header.Set("Content-Type", "application/json")

	// send http request
	resp, err := http.DefaultClient.Do(req) //nolint: bodyclose
	if err != nil {
		return fmt.Errorf("failed to get response from '%s', cause :%s", destination, err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response from '%s', cause :%s", destination, err)
	}

	logger.Debugf("Got response from '%s' [method: %s], response payload: %s", destination, method, string(data))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get successful response from '%s', unexpected status code [%d], "+
			"and message [%s]", destination, resp.StatusCode, string(data))
	}

	if result == nil {
		return nil
	}

	return json.Unmarshal(data, result)
}
