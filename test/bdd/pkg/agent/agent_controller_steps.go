/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package agent

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	issuecredclient "github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	issuecredcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
	kmscmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
	oobcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	presentproofcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
	vdricmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdr"
	verifiablecmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	kms2 "github.com/hyperledger/aries-framework-go/pkg/controller/rest/kms"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	issuecredsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/trustbloc/edge-core/pkg/log"

	issuerops "github.com/trustbloc/edge-adapter/pkg/restapi/issuer/operation"
	adaptervc "github.com/trustbloc/edge-adapter/pkg/vc"
	"github.com/trustbloc/edge-adapter/pkg/vc/issuer"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/context"
)

const (
	completedState = "completed"

	oobOperationID   = "/outofband"
	acceptOOBInvPath = oobOperationID + "/accept-invitation"
	createOOBInvPath = oobOperationID + "/create-invitation"

	connOperationID      = "/connections"
	connectionsByIDPath  = connOperationID + "/%s"
	createConnectionPath = connOperationID + "/create"

	issueCredOperationID = "/issuecredential"
	sendCredRequest      = issueCredOperationID + "/send-request"
	issueCredActions     = issueCredOperationID + "/actions"
	acceptCredentialPath = issueCredOperationID + "/%s/accept-credential"

	presentProofOperationID   = "/presentproof"
	sendRequestPresentation   = presentProofOperationID + "/send-request-presentation"
	acceptRequestPresentation = presentProofOperationID + "/%s/accept-request-presentation"
	acceptPresentationPath    = presentProofOperationID + "/%s/accept-presentation"
	presentProofActions       = presentProofOperationID + "/actions"

	vdrOperationID = "/vdr"
	vdrDIDPath     = vdrOperationID + "/did"
	resolveDIDPath = vdrDIDPath + "/resolve/%s"

	verifiableOperationID    = "/verifiable"
	signCredentialPath       = verifiableOperationID + "/signcredential"
	generatePresentationPath = verifiableOperationID + "/presentation/generate"

	// webhook.
	checkForTopics               = "/checktopics"
	pullTopicsWaitInMilliSec     = 200
	pullTopicsAttemptsBeforeFail = 500 / pullTopicsWaitInMilliSec

	governanceCtx       = "https://trustbloc.github.io/context/governance/context.jsonld"
	governanceVCCTXSize = 3
)

var logger = log.New("edge-adapter/agent")

// Steps contains steps for aries agent.
type Steps struct {
	bddContext         *context.BDDContext
	ControllerURLs     map[string]string
	WebhookURLs        map[string]string
	adapterConnections map[string]*didexchange.Connection
	credentials        map[string]*verifiable.Credential
	refCredentials     map[string]*verifiable.Credential
}

// NewSteps returns new agent steps.
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{
		bddContext:         ctx,
		ControllerURLs:     make(map[string]string),
		WebhookURLs:        make(map[string]string),
		adapterConnections: make(map[string]*didexchange.Connection),
		credentials:        make(map[string]*verifiable.Credential),
		refCredentials:     make(map[string]*verifiable.Credential),
	}
}

// RegisterSteps registers agent steps.
func (a *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with controller "([^"]*)"$`,
		a.ValidateAgentConnection)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with webhook "([^"]*)" and controller "([^"]*)"$`,
		a.validateAgentConnectionWithWebhook)
	s.Step(`^"([^"]*)" validates the supportedVCContexts "([^"]*)" in connect request from Issuer adapter \("([^"]*)"\) along with primary credential type "([^"]*)" in case of supportsAssuranceCred "([^"]*)" and responds within "([^"]*)" seconds$`, // nolint: lll
		a.handleDIDCommConnectRequest)
	s.Step(`^"([^"]*)" sends request credential message and receives credential from the issuer \("([^"]*)"\)$`,
		a.fetchCredential)
	s.Step(`^"([^"]*)" sends present proof request message to the the issuer \("([^"]*)"\) and validates that the vc inside vp contains type "([^"]*)" along with supportsAssuranceCred "([^"]*)" validation$`, // nolint: lll
		a.fetchPresentation)
	s.Step(`^"([^"]*)" with blinded routing support\("([^"]*)"\) receives the DIDConnect request from Issuer adapter \("([^"]*)"\)$`, a.didConnectReqWithRouting) // nolint: lll
}

// ValidateAgentConnection checks if the controller agent is running.
func (a *Steps) ValidateAgentConnection(agentID, inboundHost, inboundPort, controllerURL string) error {
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

func (a *Steps) validateAgentConnectionWithWebhook(agentID, inboundHost,
	inboundPort, webhookURL, controllerURL string) error {
	if err := a.checkAgentIsRunning(agentID, controllerURL); err != nil {
		return err
	}

	// verify inbound
	if err := a.healthCheck(fmt.Sprintf("http://%s:%s", inboundHost, inboundPort)); err != nil {
		logger.Debugf("Unable to reach inbound '%s' for agent '%s', cause : %s", controllerURL, agentID, err)
		return err
	}

	if err := a.checkWebhookIsRunning(agentID, webhookURL); err != nil {
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

	return nil
}

func (a *Steps) checkWebhookIsRunning(agentID, webhookURL string) error {
	// verify controller
	err := a.healthCheck(webhookURL)
	if err != nil {
		logger.Debugf("Unable to reach webhook '%s' for agent '%s', cause : %s", webhookURL, agentID, err)
		return err
	}

	logger.Debugf("Agent '%s' running webhook '%s'", agentID, webhookURL)

	a.WebhookURLs[agentID] = webhookURL

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

//nolint:funlen,gocyclo
func (a *Steps) handleDIDCommConnectRequest(agentID, supportedVCContexts, issuerID,
	primaryVCType, supportsAssuranceCredStr string, timeout int) error {
	// Mock CHAPI request from Issuer
	didConnReq := a.bddContext.Store[bddutil.GetDIDConnectRequestKey(issuerID, agentID)]

	request := &issuerops.CHAPIRequest{}

	err := json.Unmarshal([]byte(didConnReq), request)
	if err != nil {
		return err
	}

	supportsAssuranceCred, err := strconv.ParseBool(supportsAssuranceCredStr)
	if err != nil {
		return err
	}

	if supportsAssuranceCred && len(request.Credentials) != 3 {
		return fmt.Errorf("invalid number of credential in chapi request: "+
			"expected=%d actual=%d", 3, len(request.Credentials))
	} else if !supportsAssuranceCred && len(request.Credentials) != 2 {
		return fmt.Errorf("invalid number of credential in chapi request: "+
			"expected=%d actual=%d", 2, len(request.Credentials))
	}

	err = validateManifestCred(request.Credentials[0], supportedVCContexts)
	if err != nil {
		return fmt.Errorf("failed to parse credential : %s", err.Error())
	}

	if supportsAssuranceCred {
		vc, vcErr := validateAndGetReferenceCred(request.Credentials[1], primaryVCType, a.bddContext.VDRI)
		if vcErr != nil {
			return fmt.Errorf("failed to parse credential : %s", vcErr.Error())
		}

		a.refCredentials[agentID] = vc
	}

	if supportsAssuranceCred {
		err = validateGovernance(request.Credentials[2])
	} else {
		err = validateGovernance(request.Credentials[1])
	}

	if err != nil {
		return fmt.Errorf("failed to parse governance credential : %s", err.Error())
	}

	connectionID, err := a.AcceptOOBInvitation(agentID, request.DIDCommInvitation, issuerID)
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

func (a *Steps) didConnectReqWithRouting(agentID, routerURL, issuerID string) error {
	didConnReq := a.bddContext.Store[bddutil.GetDIDConnectRequestKey(issuerID, agentID)]

	request := &issuerops.CHAPIRequest{}

	err := json.Unmarshal([]byte(didConnReq), request)
	if err != nil {
		return err
	}

	connectionID, err := a.AcceptOOBInvitation(agentID, request.DIDCommInvitation, issuerID)
	if err != nil {
		return err
	}

	err = validateConnection(a.ControllerURLs[agentID], connectionID, completedState)
	if err != nil {
		return err
	}

	// unregister all the msg services (to clear older data)
	err = unregisterAllMsgServices(a.ControllerURLs[agentID])
	if err != nil {
		return err
	}

	// send request to adapter for fetching the peerDIDDoc
	// issuer adapter - wallet
	msgID, adapterDIDDoc, err := adapterDIDDocReq(a.ControllerURLs[agentID], a.WebhookURLs[agentID], connectionID)
	if err != nil {
		return fmt.Errorf("adapter did doc : %w", err)
	}

	// create a connection with router
	routerConnID, err := a.connectWithRouter(agentID, routerURL)
	if err != nil {
		return fmt.Errorf("connect to router: %w", err)
	}

	// wallet to router
	routerDIDDoc, err := routerConnReq(a.ControllerURLs[agentID], a.WebhookURLs[agentID], routerConnID, adapterDIDDoc)
	if err != nil {
		return fmt.Errorf("router connection req : %w", err)
	}

	// wallet to issuer
	err = adapterCreateConnReq(a.ControllerURLs[agentID], a.WebhookURLs[agentID], msgID, routerDIDDoc)
	if err != nil {
		return fmt.Errorf("adapter connection req : %w", err)
	}

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

// Connect establishes a didcomm connection between the two agents.
func (a *Steps) Connect(inviter, invitee string) error {
	inv, err := a.createInvitation(inviter)
	if err != nil {
		return fmt.Errorf("%s failed to create invitation for %s : %w", inviter, invitee, err)
	}

	inviteeConnID, err := a.AcceptOOBInvitation(invitee, inv, invitee)
	if err != nil {
		return fmt.Errorf("%s failed to accept outofband invitation from %s: %w", invitee, inviter, err)
	}

	return backoff.RetryNotify(
		func() error {
			_, err = a.ValidateConnection(invitee, inviteeConnID)
			return err
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 3),
		func(e error, d time.Duration) {
			logger.Debugf(
				"caught an error [%s] while validating connection status for %s - will sleep for %s before trying again", //nolint:lll
				e.Error(), invitee, d)
		},
	)
}

func (a *Steps) createInvitation(agent string) (*outofband.Invitation, error) {
	destination, ok := a.ControllerURLs[agent]
	if !ok {
		return nil, fmt.Errorf("unable to find controller URL registered for agent [%s]", agent)
	}

	request, err := json.Marshal(&oobcmd.CreateInvitationArgs{Label: agent})
	if err != nil {
		return nil, fmt.Errorf("'%s'failed to create an outofband invitation : %w", agent, err)
	}

	var resp oobcmd.CreateInvitationResponse

	err = bddutil.SendHTTP(http.MethodPost, destination+createOOBInvPath, request, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to create invitation, cause : %s", err)
	}

	return resp.Invitation, nil
}

// AcceptOOBInvitation makes agentID accept the invitation, returning the connection ID.
func (a *Steps) AcceptOOBInvitation(agentID string, invitation *outofband.Invitation, label string) (string, error) {
	destination, ok := a.ControllerURLs[agentID]
	if !ok {
		return "", fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	request, err := json.Marshal(&oobcmd.AcceptInvitationArgs{
		Invitation: invitation,
		MyLabel:    label,
	})
	if err != nil {
		return "", fmt.Errorf("'%s' failed to marshal oob accept invitation args : %w", agentID, err)
	}

	var result oobcmd.AcceptInvitationResponse

	err = bddutil.SendHTTP(http.MethodPost, destination+acceptOOBInvPath, request, &result)
	if err != nil {
		return "", fmt.Errorf("'%s' failed to accept oob invitation : %w", agentID, err)
	}

	if result.ConnectionID == "" {
		return "", fmt.Errorf("'%s' failed to get valid payload from accept oob invitation", agentID)
	}

	return result.ConnectionID, nil
}

func (a *Steps) getConnection(agentID, connectionID string) (*didexchange.Connection, error) {
	destination, ok := a.ControllerURLs[agentID]
	if !ok {
		return nil, fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentID)
	}

	// call controller
	var response didexcmd.QueryConnectionResponse

	err := bddutil.SendHTTP(http.MethodGet,
		destination+fmt.Sprintf(connectionsByIDPath, connectionID), nil, &response)
	if err != nil {
		logger.Errorf("Failed to perform receive invitation, cause : %s", err)
		return nil, err
	}

	return response.Result, nil
}

// GetConnectionBetweenAgents returns a didcomm connection record between the two agents, if one exists.
func (a *Steps) GetConnectionBetweenAgents(agentA, agentB string) (*didexchange.Connection, error) {
	destination, ok := a.ControllerURLs[agentA]
	if !ok {
		return nil, fmt.Errorf(" unable to find controller URL registered for agent [%s]", agentA)
	}

	var resp didexcmd.QueryConnectionsResponse

	err := bddutil.SendHTTP(http.MethodGet, destination+connOperationID, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("%s failed to query connection records : %w", agentA, err)
	}

	for i := range resp.Results {
		if agentB == resp.Results[i].TheirLabel {
			return resp.Results[i], nil
		}
	}

	return nil, fmt.Errorf("no connection found between %s and %s", agentA, agentB)
}

// CreateConnection creates a didcomm connection for the agent between myDID and theirDID.
func (a *Steps) CreateConnection(agent, myDID, label string, theirDID *did.Doc) (string, error) {
	destination, ok := a.ControllerURLs[agent]
	if !ok {
		return "", fmt.Errorf(" unable to find controller URL registered for agent [%s]", agent)
	}

	theirDIDBytes, err := theirDID.JSONBytes()
	if err != nil {
		return "", fmt.Errorf("theirDID failed to marshal to bytes : %w", err)
	}

	request, err := json.Marshal(&didexcmd.CreateConnectionRequest{
		MyDID: myDID,
		TheirDID: didexcmd.DIDDocument{
			ID:       theirDID.ID,
			Contents: theirDIDBytes,
		},
		TheirLabel: label,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal save connection request : %w", err)
	}

	var resp didexcmd.ConnectionIDArg

	err = bddutil.SendHTTP(http.MethodPost, destination+createConnectionPath, request, &resp)
	if err != nil {
		return "", fmt.Errorf("%s failed to create connection : %w", agent, err)
	}

	return resp.ID, nil
}

func (a *Steps) fetchCredential(agentID, issuerID string) error { // nolint: funlen, gocyclo
	conn, ok := a.adapterConnections[agentID]
	if !ok {
		return fmt.Errorf("unable to find the issuer adapter connection data [%s]", agentID)
	}

	controllerURL, ok := a.ControllerURLs[agentID]
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	didDocument, err := a.ResolveDID(agentID, conn.MyDID)
	if err != nil {
		return err
	}

	didDocJSON, err := didDocument.JSONBytes()
	if err != nil {
		return err
	}

	ccReq := &issuerops.AuthorizationCredentialReq{
		SubjectDID: conn.MyDID,
		RPDIDDoc: &adaptervc.DIDDoc{
			ID:  didDocument.ID,
			Doc: didDocJSON,
		},
	}

	req := &issuecredcmd.SendRequestArgs{
		MyDID:    conn.MyDID,
		TheirDID: conn.TheirDID,
		RequestCredential: &issuecredclient.RequestCredential{
			Type: issuecredsvc.RequestCredentialMsgType,
			RequestsAttach: []decorator.Attachment{
				{
					Data: decorator.AttachmentData{
						JSON: ccReq,
					},
				},
			},
		},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed marshal issue-credential send request : %w", err)
	}

	err = bddutil.SendHTTP(http.MethodPost, controllerURL+sendCredRequest, reqBytes, nil)
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

	vc, err := getCredential(credentialName, controllerURL, a.bddContext.VDRI)
	if err != nil {
		return err
	}

	authorizationData, err := validateAndGetAuthorizationCredential(vc, ccReq)
	if err != nil {
		return fmt.Errorf("[issue-credential] failed to validate authorization credential : %w", err)
	}

	issuerDIDDoc, err := did.ParseDocument(authorizationData.IssuerDIDDoc.Doc)
	if err != nil {
		return err
	}

	issuerDIDDoc.ID = authorizationData.IssuerDIDDoc.ID

	err = a.bddContext.VDRI.Store(issuerDIDDoc)
	if err != nil {
		return err
	}

	connID, err := a.CreateConnection(agentID, authorizationData.RPDIDDoc.ID, uuid.New().String(), issuerDIDDoc)
	if err != nil {
		return err
	}

	extConn, err := a.getConnection(agentID, connID)
	if err != nil {
		return err
	}

	a.adapterConnections[getExtCreateConnKey(agentID)] = extConn
	a.credentials[agentID] = vc

	return nil
}

// nolint:gocyclo
func (a *Steps) fetchPresentation(agentID, issuerID, expectedScope, supportsAssuranceCredStr string) error {
	conn, ok := a.adapterConnections[getExtCreateConnKey(agentID)]
	if !ok {
		return fmt.Errorf("unable to find the issuer connection data [%s]", agentID)
	}

	controllerURL, ok := a.ControllerURLs[agentID]
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	vc, ok := a.credentials[agentID]
	if !ok {
		return fmt.Errorf("unable to find the the authorization credential for agent [%s]", agentID)
	}

	vp, err := vc.Presentation()
	if err != nil {
		return err
	}

	// send presentation request
	err = sendPresentationRequest(conn, vp, controllerURL)
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
	vpID, err := validatePresentation(presentationName, controllerURL)
	if err != nil {
		return err
	}

	supportsAssuranceCred, err := strconv.ParseBool(supportsAssuranceCredStr)
	if err != nil {
		return err
	}

	err = a.validateIssuerVC(vpID, agentID, controllerURL, expectedScope, supportsAssuranceCred, a.bddContext.VDRI)
	if err != nil {
		return err
	}

	return nil
}

// ResolveDID resolves the did on behalf of the agent.
func (a *Steps) ResolveDID(agent, didID string) (*did.Doc, error) {
	destination, ok := a.ControllerURLs[agent]
	if !ok {
		return nil, fmt.Errorf("unable to find controller URL registered for agent [%s]", agent)
	}

	destination = fmt.Sprintf(destination+resolveDIDPath, base64.StdEncoding.EncodeToString([]byte(didID)))

	var resp vdricmd.Document

	err := bddutil.SendHTTP(http.MethodGet, destination, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("%s failed to fetch did=%s : %w", agent, didID, err)
	}

	doc, err := did.ParseDocument(resp.DID)
	if err != nil {
		return nil, fmt.Errorf("%s failed to parse did document : %w", agent, err)
	}

	return doc, nil
}

// SaveDID saves the did document.
func (a *Steps) SaveDID(agent, friendlyName string, d *did.Doc) error {
	bits, err := d.JSONBytes()
	if err != nil {
		return fmt.Errorf("failed to marshal did doc: %w", err)
	}

	request, err := json.Marshal(&vdricmd.DIDArgs{
		Name:     friendlyName,
		Document: vdricmd.Document{DID: bits},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request to save did doc: %w", err)
	}

	requestURL := a.ControllerURLs[agent] + vdr.SaveDIDPath

	err = bddutil.SendHTTP(http.MethodPost, requestURL, request, nil)
	if err != nil {
		return fmt.Errorf("failed to save did at url %s: %w", requestURL, err)
	}

	return nil
}

// AcceptRequestPresentation accepts the request for presentation.
func (a *Steps) AcceptRequestPresentation(agent string, presentation *verifiable.Presentation) error {
	destination := a.ControllerURLs[agent]

	piid, err := actionPIID(destination, presentProofActions)
	if err != nil {
		return err
	}

	vpBytes, err := presentation.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal verifiable presentation : %w", err)
	}

	request, err := json.Marshal(presentproofcmd.AcceptRequestPresentationArgs{
		PIID: piid,
		Presentation: &presentproof.Presentation{
			Type: presentproofsvc.PresentationMsgType,
			PresentationsAttach: []decorator.Attachment{{
				ID:       uuid.New().String(),
				MimeType: "application/ld+json",
				Data: decorator.AttachmentData{
					Base64: base64.StdEncoding.EncodeToString(vpBytes),
				},
			}},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal accept request presentation request : %w", err)
	}

	acceptRequestURL := fmt.Sprintf(destination+acceptRequestPresentation, piid)

	return bddutil.SendHTTP(http.MethodPost, acceptRequestURL, request,
		&presentproofcmd.AcceptRequestPresentationResponse{})
}

// SignCredential signs the credential.
func (a *Steps) SignCredential(agent, signingDID string, cred *verifiable.Credential) (*verifiable.Credential, error) {
	destination := a.ControllerURLs[agent]

	inputBits, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("'%s' failed to marshal credential: %w", agent, err)
	}

	request, err := json.Marshal(&verifiablecmd.SignCredentialRequest{
		Credential: inputBits,
		DID:        signingDID,
		ProofOptions: &verifiablecmd.ProofOptions{
			SignatureType: verifiablecmd.Ed25519Signature2018,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("'%s' failed to marshal SignCredential request: %w", agent, err)
	}

	response := &verifiablecmd.SignCredentialResponse{}

	err = bddutil.SendHTTP(http.MethodPost, destination+signCredentialPath, request, response)
	if err != nil {
		return nil, fmt.Errorf("'%s' failed to sign credential: %w", agent, err)
	}

	output, err := verifiable.ParseUnverifiedCredential(response.VerifiableCredential)
	if err != nil {
		return nil, fmt.Errorf("'%s' failed to parse their own signed credential: %w", agent, err)
	}

	return output, nil
}

// GeneratePresentation generates a new, signed presentation.
func (a *Steps) GeneratePresentation(agent, signingDID, verificationMethod string,
	vp *verifiable.Presentation, vcs ...*verifiable.Credential) (*verifiable.Presentation, error) {
	destinationURL := a.ControllerURLs[agent]

	rawCreds := make([]json.RawMessage, len(vcs))

	for i := range vcs {
		rawCred, err := json.Marshal(vcs[i])
		if err != nil {
			return nil, fmt.Errorf("'%s' failed to marshal a credential while generating a presentation: %w", agent, err)
		}

		rawCreds[i] = rawCred
	}

	var (
		err      error
		vpToSign []byte
	)

	if vp != nil {
		vpToSign, err = json.Marshal(vp)
		if err != nil {
			return nil, fmt.Errorf("failed to sign vp with verMethod %s: %w", verificationMethod, err)
		}
	}

	request, err := json.Marshal(&verifiablecmd.PresentationRequest{
		Presentation:          vpToSign,
		VerifiableCredentials: rawCreds,
		DID:                   signingDID,
		ProofOptions: &verifiablecmd.ProofOptions{
			SignatureType:      ed25519signature2018.SignatureType,
			VerificationMethod: verificationMethod,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("'%s' failed to marshal generate presentation request: %w", agent, err)
	}

	response := &verifiablecmd.Presentation{}

	err = bddutil.SendHTTP(http.MethodPost, destinationURL+generatePresentationPath, request, response)
	if err != nil {
		return nil, fmt.Errorf("'%s' failed to generate their own presentation: %w", agent, err)
	}

	signedVP, err := verifiable.ParseUnverifiedPresentation(response.VerifiablePresentation)
	if err != nil {
		return nil, fmt.Errorf("'%s' failed to parse their own presentation: %w", agent, err)
	}

	return signedVP, nil
}

// CreateKey creates a key of the given type.
// Returns the key's ID and the public key material.
func (a *Steps) CreateKey(agent string, t kms.KeyType) (id string, key []byte, err error) {
	request, err := json.Marshal(&kmscmd.CreateKeySetRequest{KeyType: string(t)})
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal createKeySet request: %w", err)
	}

	requestURL := a.ControllerURLs[agent] + kms2.CreateKeySetPath

	response := &kmscmd.CreateKeySetResponse{}

	err = bddutil.SendHTTP(http.MethodPost, requestURL, request, response)
	if err != nil {
		return "", nil, fmt.Errorf("failed to execute createKeySet request to %s: %w", requestURL, err)
	}

	bits, err := base64.RawURLEncoding.DecodeString(response.PublicKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to base64URL-decode key: %w", err)
	}

	return response.KeyID, bits, nil
}

func sendPresentationRequest(conn *didexchange.Connection, vp *verifiable.Presentation, controllerURL string) error {
	req := &presentproofcmd.SendRequestPresentationArgs{
		MyDID:    conn.MyDID,
		TheirDID: conn.TheirDID,
		RequestPresentation: &presentproof.RequestPresentation{
			Type: presentproofsvc.RequestPresentationMsgType,
			RequestPresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{
					JSON: vp,
				}},
			},
		},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	err = bddutil.SendHTTP(http.MethodPost, controllerURL+sendRequestPresentation, reqBytes, nil)
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

	err = bddutil.SendHTTP(http.MethodPost, controllerURL+fmt.Sprintf(acceptCredentialPath, piid), reqBytes, nil)
	if err != nil {
		return fmt.Errorf("failed to perform approve request : %w", err)
	}

	return nil
}

func getCredential(credentialName, controllerURL string, vdriReg vdriapi.Registry) (*verifiable.Credential, error) {
	// TODO use listener rather than polling (update once aries bdd-tests are refactored)
	const (
		timeoutWait = 10 * time.Second
		retryDelay  = 500 * time.Millisecond
	)

	var err error

	start := time.Now()

	for {
		if time.Since(start) > timeoutWait {
			break
		}

		var result struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}

		err = bddutil.SendHTTP(http.MethodGet,
			fmt.Sprintf("%s/verifiable/credential/name/%s", controllerURL, credentialName), nil, &result)
		if err != nil {
			time.Sleep(retryDelay)
			continue
		}

		var getVCResp struct {
			VC string `json:"verifiableCredential"`
		}

		err = bddutil.SendHTTP(http.MethodGet,
			fmt.Sprintf("%s/verifiable/credential/%s", controllerURL,
				base64.StdEncoding.EncodeToString([]byte(result.ID))), nil, &getVCResp)
		if err != nil {
			return nil, err
		}

		var vc *verifiable.Credential

		vc, err = verifiable.ParseCredential(
			[]byte(getVCResp.VC),
			verifiable.WithPublicKeyFetcher(verifiable.NewDIDKeyResolver(vdriReg).PublicKeyFetcher()),
		)
		if err != nil {
			return nil, err
		}

		return vc, nil
	}

	return nil, fmt.Errorf("failed to validate credential: not found: %w", err)
}

func validateAndGetAuthorizationCredential(vc *verifiable.Credential,
	ccReq *issuerops.AuthorizationCredentialReq) (*adaptervc.AuthorizationCredentialSubject, error) {
	if !bddutil.StringsContains(adaptervc.AuthorizationCredentialType, vc.Types) {
		return nil, fmt.Errorf("missing vc type : %s", adaptervc.AuthorizationCredentialType)
	}

	authorizationVC := &struct {
		Subject *adaptervc.AuthorizationCredentialSubject `json:"credentialSubject"`
	}{}

	err := bddutil.DecodeJSONMarshaller(vc, &authorizationVC)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential : %s", err.Error())
	}

	if authorizationVC.Subject.SubjectDID != ccReq.SubjectDID {
		return nil, fmt.Errorf("unexpected user did authorization credential : expected=%s actual=%s", ccReq.SubjectDID,
			authorizationVC.Subject.SubjectDID)
	}

	_, err = did.ParseDocument(authorizationVC.Subject.IssuerDIDDoc.Doc)
	if err != nil {
		return nil, fmt.Errorf("invalid did document : %w", err)
	}

	if strings.Split(authorizationVC.Subject.IssuerDIDDoc.ID, ":")[1] != "peer" {
		return nil, fmt.Errorf("unexpected did method : expected=%s actual=%s", "peer",
			strings.Split(authorizationVC.Subject.IssuerDIDDoc.ID, ":")[1])
	}

	return authorizationVC.Subject, nil
}

func acceptPresentation(piid, presentationName, controllerURL string) error {
	acceptReq := &presentproofcmd.AcceptPresentationArgs{
		Names: []string{presentationName},
	}

	acceptReqBytes, err := json.Marshal(acceptReq)
	if err != nil {
		return err
	}

	err = bddutil.SendHTTP(http.MethodPost, controllerURL+fmt.Sprintf(acceptPresentationPath, piid), acceptReqBytes, nil)
	if err != nil {
		return err
	}

	return nil
}

func validatePresentation(presentationName, controllerURL string) (string, error) {
	const (
		timeoutWait = 10 * time.Second
		retryDelay  = 500 * time.Millisecond
	)

	start := time.Now()

	for {
		if time.Since(start) > timeoutWait {
			break
		}

		var result verifiablecmd.RecordResult
		if err := bddutil.SendHTTP(http.MethodGet, controllerURL+"/verifiable/presentations", nil, &result); err != nil {
			return "", err
		}

		for _, val := range result.Result {
			if val.Name == presentationName {
				return val.ID, nil
			}
		}

		time.Sleep(retryDelay)

		continue
	}

	return "", errors.New("presentation not found")
}

// nolint: gocyclo
func (a *Steps) validateIssuerVC(id, agentID, controllerURL, expectedScope string, supportsAssuranceCred bool,
	vdriReg vdriapi.Registry) error {
	var vpResult verifiablecmd.Presentation

	if err := bddutil.SendHTTP(http.MethodGet,
		controllerURL+"/verifiable/presentation/"+base64.StdEncoding.EncodeToString([]byte(id)),
		nil, &vpResult); err != nil {
		return err
	}

	vp, err := verifiable.ParsePresentation(
		vpResult.VerifiablePresentation,
		verifiable.WithPresPublicKeyFetcher(verifiable.NewDIDKeyResolver(vdriReg).PublicKeyFetcher()),
	)
	if err != nil {
		return err
	}

	creds, err := vp.MarshalledCredentials()
	if err != nil {
		return err
	}

	if len(creds) != 1 {
		return fmt.Errorf("invalid number of credentials: expected=%d actual=%d", 1, len(creds))
	}

	vc, err := verifiable.ParseCredential(
		creds[0],
		verifiable.WithPublicKeyFetcher(verifiable.NewDIDKeyResolver(vdriReg).PublicKeyFetcher()),
	)
	if err != nil {
		return err
	}

	if supportsAssuranceCred {
		err = validateAssuranceVC(vc)
		if err != nil {
			return err
		}

		if a.refCredentials[agentID].ID != fmt.Sprintf("%v", vc.CustomFields["referenceVCID"]) {
			return fmt.Errorf("reference credential id doesn't match: expected=%s actual=%s",
				a.refCredentials[agentID].ID, fmt.Sprintf("%v", vc.CustomFields["referenceVCID"]))
		}
	}

	for _, t := range vc.Types {
		if t == expectedScope {
			return nil
		}
	}

	return fmt.Errorf("vc type validation failed : expected=%s actual=%s", expectedScope, vc.Types)
}

func validateAssuranceVC(vc *verifiable.Credential) error {
	for _, t := range vc.Types {
		if t == adaptervc.AssuranceCredentialType {
			return nil
		}
	}

	return fmt.Errorf("assurance vc type validation failed : expected=%s actual=%s",
		adaptervc.AssuranceCredentialType, vc.Types)
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

		err := bddutil.SendHTTP(http.MethodGet, endpoint+urlPath, nil, &result)
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

func validateManifestCred(manifestVCBytes []byte, supportedVCContexts string) error {
	manifestCred, err := verifiable.ParseCredential(manifestVCBytes)
	if err != nil {
		return err
	}

	manifestCredSub := &issuer.ManifestCredential{}

	err = bddutil.DecodeJSONMarshaller(manifestCred, manifestCredSub)
	if err != nil {
		return fmt.Errorf("failed to parse credential : %s", err.Error())
	}

	if len(manifestCredSub.Subject.Contexts) != len(strings.Split(supportedVCContexts, ",")) {
		return fmt.Errorf("supported vc count doesnt match : expected=%d actual=%d",
			len(strings.Split(supportedVCContexts, ",")), len(manifestCredSub.Subject.Contexts))
	}

	return nil
}

func validateGovernance(governanceVCBytes json.RawMessage) error {
	governanceVC, err := verifiable.ParseUnverifiedCredential(governanceVCBytes)
	if err != nil {
		return err
	}

	if len(governanceVC.Context) != governanceVCCTXSize {
		return fmt.Errorf("governance vc context not equal 3")
	}

	exist := false

	for _, v := range governanceVC.Context {
		if v == governanceCtx {
			exist = true
		}
	}

	if !exist {
		return fmt.Errorf("governance vc context %s not exist", governanceCtx)
	}

	return nil
}

func validateAndGetReferenceCred(vcBytes []byte, vcType string,
	vdriReg vdriapi.Registry) (*verifiable.Credential, error) {
	cred, err := verifiable.ParseCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(verifiable.NewDIDKeyResolver(vdriReg).PublicKeyFetcher()),
	)
	if err != nil {
		return nil, err
	}

	for _, t := range cred.Types {
		if t == vcType {
			return cred, nil
		}
	}

	return nil, fmt.Errorf("primary vc type validation failed; expected=%s actual=%s", vcType, cred.Types)
}

func getExtCreateConnKey(agentID string) string {
	return agentID + "-ext"
}

func validateConnection(controllerURL, connID, state string) error {
	const (
		sleep      = 1 * time.Second
		numRetries = 30
	)

	return backoff.RetryNotify(
		func() error {
			var openErr error

			var result didexcmd.QueryConnectionResponse
			if err := bddutil.SendHTTP(http.MethodGet, controllerURL+fmt.Sprintf(connectionsByIDPath, connID),
				nil, &result); err != nil {
				return err
			}

			if result.Result.State != state {
				return fmt.Errorf("expected=%s actual=%s", state, result.Result.State)
			}

			return openErr
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(sleep), uint64(numRetries)),
		func(retryErr error, t time.Duration) {
			logger.Warnf(
				"validate connection : sleeping for %s before trying again : %s\n",
				t, retryErr)
		},
	)
}

func pullMsgFromWebhookURL(webhookURL, topic string) (*service.DIDCommMsgMap, error) {
	var incoming struct {
		ID      string                `json:"id"`
		Topic   string                `json:"topic"`
		Message service.DIDCommMsgMap `json:"message"`
	}

	// try to pull recently pushed topics from webhook
	for i := 0; i < pullTopicsAttemptsBeforeFail; {
		err := bddutil.SendHTTP(http.MethodGet, webhookURL+checkForTopics,
			nil, &incoming)
		if err != nil {
			return nil, fmt.Errorf("failed pull topics from webhook, cause : %w", err)
		}

		if incoming.Topic != topic {
			continue
		}

		if len(incoming.Message) > 0 {
			return &incoming.Message, nil
		}

		i++

		time.Sleep(pullTopicsWaitInMilliSec * time.Millisecond)
	}

	return nil, fmt.Errorf("exhausted all [%d] attempts to pull topic from webhook", pullTopicsAttemptsBeforeFail)
}

func (a *Steps) connectWithRouter(agentID, routerURL string) (string, error) {
	var routerInvitation struct {
		Invitation *outofband.Invitation `json:"invitation"`
	}

	err := bddutil.SendHTTP(http.MethodGet, routerURL+"/didcomm/invitation",
		nil, &routerInvitation)
	if err != nil {
		return "", err
	}

	connectionID, err := a.AcceptOOBInvitation(agentID, routerInvitation.Invitation, "router")
	if err != nil {
		return "", err
	}

	err = validateConnection(a.ControllerURLs[agentID], connectionID, completedState)
	if err != nil {
		return "", err
	}

	return connectionID, nil
}
