/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package agent

import (
	"bytes"
	goctx "context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cucumber/godog"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	"github.com/trustbloc/edge-core/pkg/log"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

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
)

var logger = log.New("aries-framework/tests")

// Steps contains steps for aries agent.
type Steps struct {
	bddContext     *context.BDDContext
	Args           map[string]string
	ControllerURLs map[string]string
	WebhookURLs    map[string]string
	webSocketConns map[string]*websocket.Conn
}

// NewSteps returns new agent steps.
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{
		bddContext:     ctx,
		Args:           make(map[string]string),
		ControllerURLs: make(map[string]string),
		WebhookURLs:    make(map[string]string),
		webSocketConns: make(map[string]*websocket.Conn),
	}
}

// RegisterSteps registers agent steps.
func (a *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with controller "([^"]*)"$`,
		a.validateAgentConnection)
	s.Step(`^"([^"]*)" responds to connect request from Issuer adapter \("([^"]*)"\) within "([^"]*)" seconds$`,
		a.handleDIDConnectRequest)
}

func (a *Steps) validateAgentConnection(agentID, inboundHost,
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
	invitationJSON := a.bddContext.Store[bddutil.GetDIDConectRequestKey(issuerID, agentID)]

	connectionID, err := a.receiveInvitation(agentID, invitationJSON)
	if err != nil {
		return err
	}

	err = a.approveInvitation(agentID)
	if err != nil {
		return err
	}

	// Added to mock CHAPI timeout (ie, DIDExchange should happen with this duration)
	time.Sleep(time.Duration(timeout) * time.Second)

	err = a.validateConnection(agentID, connectionID, completedState)
	if err != nil {
		return err
	}

	return nil
}

func (a *Steps) receiveInvitation(agentID, invitation string) (string, error) {
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

func (a *Steps) approveInvitation(agentID string) error {
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

func (a *Steps) validateConnection(agentID, connectionID, stateValue string) error {
	destination, ok := a.ControllerURLs[agentID]
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	// call controller
	var response didexcmd.QueryConnectionResponse

	err := sendHTTP(http.MethodGet, destination+strings.Replace(connectionsByID, "{id}", connectionID, 1), nil, &response)
	if err != nil {
		logger.Errorf("Failed to perform receive invitation, cause : %s", err)
		return err
	}

	// Verify state
	if response.Result.State != stateValue {
		return fmt.Errorf("expected state[%s] for agent[%s], but got[%s]", stateValue, agentID, response.Result.State)
	}

	return nil
}

func (a *Steps) pullEventsFromWebSocket(agentID, state string) (string, error) {
	conn, ok := a.webSocketConns[agentID]
	if !ok {
		return "", fmt.Errorf("unable to get websocket conn for agent [%s]", agentID)
	}

	ctx, cancel := goctx.WithTimeout(goctx.Background(), timeoutWS)
	defer cancel()

	var incoming struct {
		ID      string                 `json:"id"`
		Topic   string                 `json:"topic"`
		Message didexcmd.ConnectionMsg `json:"message"`
	}

	for {
		err := wsjson.Read(ctx, conn, &incoming)
		if err != nil {
			return "", fmt.Errorf("failed to get topics for agent '%s' : %w", agentID, err)
		}

		if incoming.Topic == "connections" {
			if strings.EqualFold(state, incoming.Message.State) {
				logger.Debugf("Able to find webhook topic with expected state[%s] for agent[%s] and connection[%s]",
					incoming.Message.State, agentID, incoming.Message.ConnectionID)

				return incoming.Message.ConnectionID, nil
			}
		}
	}
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
