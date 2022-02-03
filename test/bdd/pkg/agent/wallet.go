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
	"net/url"
	"time"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	issuecredsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"

	issuerop "github.com/trustbloc/edge-adapter/pkg/restapi/issuer/operation"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/context"
)

const (
	// wallet controller URLs
	walletOperationID     = "/vcwallet"
	createProfilePath     = walletOperationID + "/create-profile"
	unlockWalletPath      = walletOperationID + "/open"
	proposeCredentialPath = walletOperationID + "/propose-credential"
	requestCredentialPath = walletOperationID + "/request-credential"

	// time constants
	waitForResponseTimeout = 20 * time.Second
	tokenExpiry            = 20 * time.Minute
)

// Steps contains steps for aries agent.
type walletSteps struct {
	bddContext     *context.BDDContext
	ControllerURLs map[string]string
	WebhookURLs    map[string]string
}

// newWalletSteps returns new wallet steps.
func newWalletSteps(ctx *context.BDDContext, controllers, webhooks map[string]string) *walletSteps {
	return &walletSteps{
		bddContext:     ctx,
		ControllerURLs: controllers,
		WebhookURLs:    webhooks,
	}
}

// RegisterSteps registers agent steps.
//nolint:lll
func (a *walletSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Wallet "([^"]*)" has profile created and unlocked$`, a.createProfileAndUnlock)
	s.Step(`^"([^"]*)" accepts invitation from issuer adapter "([^"]*)" and performs WACI credential issuance interaction$`, a.performWACIIssuanceInteraction)
	s.Step(`^"([^"]*)" received web redirect info from "([^"]*)" after successful completion of WACI credential issuance interaction$`, a.validateWebRedirect)
}

func (a *walletSteps) createProfileAndUnlock(walletID string) error {
	destination, ok := a.ControllerURLs[walletID]
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for wallet agent [%s]", walletID)
	}

	// create wallet profile
	createRequest, err := json.Marshal(&vcwallet.CreateOrUpdateProfileRequest{
		UserID:             walletID,
		LocalKMSPassphrase: walletID,
	})
	if err != nil {
		return fmt.Errorf("failed to prepare wallet create profile request : %w", err)
	}

	err = bddutil.SendHTTP(http.MethodPost, destination+createProfilePath, createRequest, nil)
	if err != nil {
		return fmt.Errorf("'%s', failed to create wallet profile : %w", walletID, err)
	}

	// unlock wallet
	unlockRequest, err := json.Marshal(&vcwallet.UnlockWalletRequest{
		UserID:             walletID,
		LocalKMSPassphrase: walletID,
		Expiry:             tokenExpiry,
	})
	if err != nil {
		return fmt.Errorf("failed to prepare wallet unlock request : %w", err)
	}

	var response vcwallet.UnlockWalletResponse

	err = bddutil.SendHTTP(http.MethodPost, destination+unlockWalletPath, unlockRequest, &response)
	if err != nil {
		return fmt.Errorf("'%s', failed to unlock wallet profile : %w", walletID, err)
	}

	a.bddContext.Store[walletAuthKey(walletID)] = response.Token

	return nil
}

func (a *walletSteps) performWACIIssuanceInteraction(walletID, issuerID string) error {
	controller, ok := a.ControllerURLs[walletID]
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for wallet agent [%s]", walletID)
	}

	auth, ok := a.bddContext.GetString(walletAuthKey(walletID))
	if !ok {
		return fmt.Errorf("failed to find wallet auth for wallet['%s']", walletID)
	}

	thID, err := a.initiateWACIIssuance(walletID, issuerID, auth, controller)
	if err != nil {
		return fmt.Errorf("failed to initiate WACI issuance interaction for wallet[%s] : %w", walletID, err)
	}

	err = a.concludeWACIIssuance(walletID, issuerID, auth, thID, controller)
	if err != nil {
		return fmt.Errorf("failed to conclude WACI issuance interaction for wallet[%s] : %w", walletID, err)
	}

	return nil
}

func (a *walletSteps) validateWebRedirect(walletID, agentID string) error {
	redirectURL, ok := a.bddContext.GetString(walletRedirectKey(walletID, agentID))
	if !ok || redirectURL == "" {
		return fmt.Errorf("redirect URL not found for wallet[%s] and agent[%s]", walletID, agentID)
	}

	return nil
}

func (a *walletSteps) initiateWACIIssuance(walletID, issuerID, auth, controller string) (string, error) {
	oob, err := a.decodeOOBInvitation(walletID, issuerID)
	if err != nil {
		return "", fmt.Errorf("'%s' fails to read oob invitation from '%s': %w", walletID, issuerID, err)
	}

	// initiate WACI issuance interaction from wallet by proposing credential
	proposeRequest, err := json.Marshal(&vcwallet.ProposeCredentialRequest{
		WalletAuth: vcwallet.WalletAuth{
			UserID: walletID,
			Auth:   auth,
		},
		Invitation: oob,
	})
	if err != nil {
		return "", fmt.Errorf("failed to prepare wallet create profile request : %w", err)
	}

	var response vcwallet.ProposeCredentialResponse

	err = bddutil.SendHTTP(http.MethodPost, controller+proposeCredentialPath, proposeRequest, &response)
	if err != nil {
		return "", fmt.Errorf("failed to propose credential from wallet : %w", err)
	}

	logger.Debugf("wallet[%s] received propose credential response: %+v", walletID, response.OfferCredential)

	err = validateOfferCredential(response.OfferCredential)
	if err != nil {
		return "", fmt.Errorf("offer credential response validation failed : %w", err)
	}

	var thID string

	if oob.Version() == service.V2 {
		thID = response.OfferCredential.ParentThreadID()
	} else {
		thID, err = response.OfferCredential.ThreadID()
		if err != nil {
			return "", fmt.Errorf("failed to get thread ID from offer credential : %w", err)
		}
	}

	if thID == "" {
		return "", errors.New("no threadID found in offer credential message")
	}

	return thID, nil
}

func (a *walletSteps) concludeWACIIssuance(walletID, issuerID, auth, thID, controller string) error {
	// conclude WACI interaction by sending credential request
	requestCredential, err := json.Marshal(vcwallet.RequestCredentialRequest{
		WalletAuth: vcwallet.WalletAuth{
			UserID: walletID,
			Auth:   auth,
		},
		ThreadID:    thID,
		WaitForDone: true,
	})
	if err != nil {
		return fmt.Errorf("failed to prepare request credential: %w", err)
	}

	status := make(chan error)

	go func() {
		status <- a.waitAndAcceptIncomingCredential(walletID)
	}()

	var interactionResponse vcwallet.RequestCredentialResponse

	err = bddutil.SendHTTP(http.MethodPost, controller+requestCredentialPath, requestCredential, &interactionResponse)
	if err != nil {
		return fmt.Errorf("'%s', failed to request credential from wallet : %w", walletID, err)
	}

	logger.Debugf("wallet[%s] received credential fulfillment response: %+v", interactionResponse)

	select {
	case e := <-status:
		if e != nil {
			return fmt.Errorf("incoming credential validation failed for wallet[%s]: cause: %w", walletID, e)
		}
	case <-time.After(waitForResponseTimeout):
		return fmt.Errorf("timeout waiting for incoming credential wallet[%s]", walletID)
	}

	if interactionResponse.Status != "OK" {
		return fmt.Errorf("invalid credential interaction status received wallet[%s], expected[OK], got[%s]",
			walletID, interactionResponse.Status)
	}

	a.bddContext.Store[walletRedirectKey(walletID, issuerID)] = interactionResponse.RedirectURL

	return nil
}

func (a *walletSteps) waitAndAcceptIncomingCredential(walletID string) error { // nolint: gocyclo,cyclop
	webhookURL, ok := a.WebhookURLs[walletID]
	if !ok {
		return fmt.Errorf("unable to find webhook URL registered for wallet agent [%s]", walletID)
	}

	msg, properties, err := PullMsgFromWebhookURL(webhookURL,
		"issue-credential_actions",
		func(message WebhookMessage) bool {
			return message.Message.Type() == issuecredsvc.IssueCredentialMsgTypeV2 ||
				message.Message.Type() == issuecredsvc.IssueCredentialMsgTypeV3
		})
	if err != nil {
		return fmt.Errorf("failed while waiting issue credential action topic: %w", err)
	}

	piid, ok := properties["piid"]
	if !ok {
		return errors.New("missing piid, cannot accept credential")
	}

	controllerURL, ok := a.ControllerURLs[walletID]
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for wallet agent [%s]", walletID)
	}

	err = acceptCredential(piid.(string), "", controllerURL, true)
	if err != nil {
		return fmt.Errorf("failed to accept credential from wallet '%s' : %w", walletID, err)
	}

	var response issuecredential.IssueCredential

	err = msg.Decode(&response)
	if err != nil {
		return fmt.Errorf("failed to decode incoming issue credential message '%s' : %w", walletID, err)
	}

	if len(response.Formats) == 0 && response.Type == issuecredsvc.IssueCredentialMsgTypeV2 {
		return fmt.Errorf("wallet[%s] received invalid issue credential message: empty attachment formats", walletID)
	}

	if len(response.Attachments) == 0 {
		return fmt.Errorf("wallet[%s] received invalid issue credential message: empty attachments", walletID)
	}

	return nil
}

func (a *walletSteps) decodeOOBInvitation(walletID, issuerID string) (*wallet.GenericInvitation, error) {
	invResBytes, ok := a.bddContext.Store[bddutil.GetDIDConnectRequestKey(issuerID, walletID)]
	if !ok {
		return nil, fmt.Errorf("failed to find valid invitation from issuer[%s], wallet[%s]", issuerID, walletID)
	}

	// Get wallet redirect URL
	request := &issuerop.CredentialHandlerRequest{}

	err := json.Unmarshal([]byte(invResBytes.(string)), &request)
	if err != nil {
		return nil, fmt.Errorf("failed to decode invitation from issuer[%s], wallet[%s] : %w", issuerID, walletID, err)
	}

	if request.WalletRedirect == "" {
		return nil, fmt.Errorf("no WACI invitation URL found")
	}

	ooburl, err := url.Parse(request.WalletRedirect)
	if err != nil {
		return nil, fmt.Errorf("failed to decode WACI invitation URL: %w", err)
	}

	oobEncoded, ok := ooburl.Query()["oob"]
	if !ok || len(oobEncoded) == 0 {
		return nil, fmt.Errorf("oob invitationn not found")
	}

	oobBytes, err := base64.URLEncoding.DecodeString(oobEncoded[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode oob invitation: %w", err)
	}

	inv := &wallet.GenericInvitation{}

	if err = json.Unmarshal(oobBytes, &inv); err != nil {
		return nil, fmt.Errorf("'%s' failed to decode oob bytes : %w", walletID, err)
	}

	return inv, nil
}

func validateOfferCredential(msg *service.DIDCommMsgMap) error {
	var offer issuecredential.OfferCredential

	if err := msg.Decode(&offer); err != nil {
		return fmt.Errorf("failed to decode offer credential from incoming msg: %w", err)
	}

	if offer.Type == "" {
		return fmt.Errorf("invalid offer credential message, empty type:\nmsg = %#v\noffer = %#v", msg, offer)
	}

	if len(offer.Attachments) == 0 {
		return errors.New("invalid offer credential message, expected attachments")
	}

	if offer.Type == issuecredsvc.OfferCredentialMsgTypeV2 && len(offer.Formats) == 0 {
		return errors.New("invalid offer credential message, expected valid attachment formats")
	}

	return nil
}

func walletAuthKey(walletID string) string {
	return fmt.Sprintf("walletauth_%s", walletID)
}

func walletRedirectKey(walletID, issuerID string) string {
	return fmt.Sprintf("wallet_redirect_%s_%s", walletID, issuerID)
}
