/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
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
	oobcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	presentproofcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
	vdricmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdri"
	verifiablecmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	issuecredsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	presentproofsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
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
	connectionsByIDPath  = connOperationID + "/{id}"
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

	vdriOperationID = "/vdri"
	vdriDIDPath     = vdriOperationID + "/did"
	resolveDIDPath  = vdriDIDPath + "/resolve/%s"
)

var logger = log.New("edge-adapter/tests")

// Steps contains steps for aries agent.
type Steps struct {
	bddContext         *context.BDDContext
	ControllerURLs     map[string]string
	WebhookURLs        map[string]string
	adapterConnections map[string]*didexchange.Connection
	credentials        map[string]*verifiable.Credential
}

// NewSteps returns new agent steps.
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{
		bddContext:         ctx,
		ControllerURLs:     make(map[string]string),
		WebhookURLs:        make(map[string]string),
		adapterConnections: make(map[string]*didexchange.Connection),
		credentials:        make(map[string]*verifiable.Credential),
	}
}

// RegisterSteps registers agent steps.
func (a *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with controller "([^"]*)"$`,
		a.ValidateAgentConnection)
	s.Step(`^"([^"]*)" validates the supportedVCContexts "([^"]*)" in connect request from Issuer adapter \("([^"]*)"\) and responds within "([^"]*)" seconds$`, // nolint: lll
		a.handleDIDCommConnectRequest)
	s.Step(`^"([^"]*)" sends request credential message and receives credential from the issuer \("([^"]*)"\)$`,
		a.fetchCredential)
	s.Step(`^"([^"]*)" sends present proof request message to the the issuer \("([^"]*)"\) and validates that the vc inside vp contains type "([^"]*)"$`, // nolint: lll
		a.fetchPresentation)
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

func (a *Steps) handleDIDCommConnectRequest(agentID, supportedVCContexts, issuerID string, timeout int) error {
	// Mock CHAPI request from Issuer
	didConnReq := a.bddContext.Store[bddutil.GetDIDConnectRequestKey(issuerID, agentID)]

	request := &issuerops.CHAPIRequest{}

	err := json.Unmarshal([]byte(didConnReq), request)
	if err != nil {
		return err
	}

	err = validateManifestCred(request.Manifest, supportedVCContexts)
	if err != nil {
		return fmt.Errorf("failed to parse credential : %s", err.Error())
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

	err = sendHTTP(http.MethodPost, destination+createOOBInvPath, request, &resp)
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

	err = sendHTTP(http.MethodPost, destination+acceptOOBInvPath, request, &result)
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

	err := sendHTTP(http.MethodGet,
		destination+strings.Replace(connectionsByIDPath, "{id}", connectionID, 1), nil, &response)
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

	err := sendHTTP(http.MethodGet, destination+connOperationID, nil, &resp)
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

	err = sendHTTP(http.MethodPost, destination+createConnectionPath, request, &resp)
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

func (a *Steps) fetchPresentation(agentID, issuerID, expectedScope string) error {
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

	err = validateIssuerVC(vpID, controllerURL, expectedScope, a.bddContext.VDRI)
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

	err := sendHTTP(http.MethodGet, destination, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("%s failed to fetch did=%s : %w", agent, didID, err)
	}

	doc, err := did.ParseDocument(resp.DID)
	if err != nil {
		return nil, fmt.Errorf("%s failed to parse did document : %w", agent, err)
	}

	return doc, nil
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

	return sendHTTP(http.MethodPost, acceptRequestURL, request, &presentproofcmd.AcceptRequestPresentationResponse{})
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

func getCredential(credentialName, controllerURL string, vdri vdriapi.Registry) (*verifiable.Credential, error) {
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
			return nil, err
		}

		vc, err := verifiable.ParseCredential(
			[]byte(getVCResp.VC),
			verifiable.WithPublicKeyFetcher(verifiable.NewDIDKeyResolver(vdri).PublicKeyFetcher()),
		)
		if err != nil {
			return nil, err
		}

		return vc, nil
	}

	return nil, fmt.Errorf("failed to validate credential: not found")
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

	err = sendHTTP(http.MethodPost, controllerURL+fmt.Sprintf(acceptPresentationPath, piid), acceptReqBytes, nil)
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
		if err := sendHTTP(http.MethodGet, controllerURL+"/verifiable/presentations", nil, &result); err != nil {
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

func validateIssuerVC(id, controllerURL, expectedScope string, vdri vdriapi.Registry) error {
	var vpResult verifiablecmd.Presentation

	if err := sendHTTP(http.MethodGet,
		controllerURL+"/verifiable/presentation/"+base64.StdEncoding.EncodeToString([]byte(id)),
		nil, &vpResult); err != nil {
		return err
	}

	vp, err := verifiable.ParsePresentation(
		vpResult.VerifiablePresentation,
		verifiable.WithPresPublicKeyFetcher(verifiable.NewDIDKeyResolver(vdri).PublicKeyFetcher()),
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
		verifiable.WithPublicKeyFetcher(verifiable.NewDIDKeyResolver(vdri).PublicKeyFetcher()),
	)
	if err != nil {
		return err
	}

	for _, t := range vc.Types {
		if t == expectedScope {
			return nil
		}
	}

	return fmt.Errorf("vc type validation failed : expected=%s actual=%s", expectedScope, vc.Types)
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

func getExtCreateConnKey(agentID string) string {
	return agentID + "-ext"
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
