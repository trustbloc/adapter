/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package agent

import (
	_ "embed" //nolint // This is needed to use go:embed
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	issuecredsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"

	issuerop "github.com/trustbloc/edge-adapter/pkg/restapi/issuer/operation"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/context"
)

var (
	//go:embed testdata/vc_prc.json
	vcPRC []byte //nolint:gochecknoglobals
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

// nolint:gochecknoglobals
var expectedManifestIDs = []string{"mDL_mID", "prc_mID"}

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
	s.Step(`^"([^"]*)" accepts invitation from issuer adapter "([^"]*)" and performs WACI credential issuance interaction$`, a.performWACIIssuanceInteractionV1)
	s.Step(`^"([^"]*)" accepts invitation from issuer adapter "([^"]*)" and performs WACI credential issuance interaction with manifest with PEx requirement "([^"]*)"$`, a.performWACIIssuanceInteractionV2)
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

func (a *walletSteps) performWACIIssuanceInteractionV1(walletID, issuerID string) error {
	controller, ok := a.ControllerURLs[walletID]
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for wallet agent [%s]", walletID)
	}

	auth, ok := a.bddContext.GetString(walletAuthKey(walletID))
	if !ok {
		return fmt.Errorf("failed to find wallet auth for wallet['%s']", walletID)
	}

	thID, err := a.initiateWACIIssuanceV1(walletID, issuerID, auth, controller)
	if err != nil {
		return fmt.Errorf("failed to initiate WACI issuance interaction for wallet[%s] : %w", walletID, err)
	}

	err = a.concludeWACIIssuanceV1(walletID, issuerID, auth, thID, controller)
	if err != nil {
		return fmt.Errorf("failed to conclude WACI issuance interaction for wallet[%s] : %w", walletID, err)
	}

	return nil
}

func (a *walletSteps) initiateWACIIssuanceV1(walletID, issuerID, auth, controller string) (string, error) {
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

	err = validateOfferCredentialV1(response.OfferCredential)
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

func validateOfferCredentialV1(msg *service.DIDCommMsgMap) error {
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

func (a *walletSteps) concludeWACIIssuanceV1(walletID, issuerID, auth, thID, controller string) error {
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

func (a *walletSteps) performWACIIssuanceInteractionV2(walletID, issuerID, hasPExRequirement string) error {
	controller, ok := a.ControllerURLs[walletID]
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for wallet agent [%s]", walletID)
	}

	auth, ok := a.bddContext.GetString(walletAuthKey(walletID))
	if !ok {
		return fmt.Errorf("failed to find wallet auth for wallet['%s']", walletID)
	}

	manifest, thID, err := a.initiateWACIIssuance(walletID, issuerID, auth, controller, hasPExRequirement)
	if err != nil {
		return fmt.Errorf("failed to initiate WACI issuance interaction for wallet[%s] : %w", walletID, err)
	}

	err = a.concludeWACIIssuance(walletID, issuerID, auth, thID, controller, manifest)
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

func (a *walletSteps) initiateWACIIssuance(walletID, issuerID, auth, controller,
	hasPExRequirement string) (*cm.CredentialManifest, string, error) {
	oob, err := a.decodeOOBInvitation(walletID, issuerID)
	if err != nil {
		return nil, "", fmt.Errorf("'%s' fails to read oob invitation from '%s': %w", walletID, issuerID, err)
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
		return nil, "", fmt.Errorf("failed to prepare wallet create profile request : %w", err)
	}

	var response vcwallet.ProposeCredentialResponse

	err = bddutil.SendHTTP(http.MethodPost, controller+proposeCredentialPath, proposeRequest, &response)
	if err != nil {
		return nil, "", fmt.Errorf("failed to propose credential from wallet : %w", err)
	}

	logger.Debugf("wallet[%s] received propose credential response: %+v", walletID, response.OfferCredential)

	manifest, err := validateOfferCredential(response.OfferCredential, hasPExRequirement)
	if err != nil {
		return nil, "", fmt.Errorf("offer credential response validation failed : %w", err)
	}

	var thID string

	if oob.Version() == service.V2 {
		thID = response.OfferCredential.ParentThreadID()
	} else {
		thID, err = response.OfferCredential.ThreadID()
		if err != nil {
			return nil, "", fmt.Errorf("failed to get thread ID from offer credential : %w", err)
		}
	}

	if thID == "" {
		return nil, "", errors.New("no threadID found in offer credential message")
	}

	return manifest, thID, nil
}

func generatePresentationWithCredentialApplication(credentialManifest *cm.CredentialManifest) (*verifiable.Presentation,
	error) {
	presentationWithCA, err := cm.PresentCredentialApplication(credentialManifest)
	if err != nil {
		return nil, fmt.Errorf("failed to generate presentation with credential application : %w", err)
	}

	cred := &verifiable.Credential{}

	err = json.Unmarshal(vcPRC, cred)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential : %w", err)
	}

	presentationWithCA.AddCredentials(cred)

	return presentationWithCA, nil
}

func (a *walletSteps) concludeWACIIssuance(walletID, issuerID, auth, thID, controller string,
	manifest *cm.CredentialManifest) error {
	presentation, err := generatePresentationWithCredentialApplication(manifest)
	if err != nil {
		return fmt.Errorf("failed to generate credential application attachment: %w", err)
	}

	rawPresentation, err := presentation.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal credential application presentation : %w", err)
	}

	// conclude WACI interaction by sending credential request with credential application
	requestCredential, err := json.Marshal(vcwallet.RequestCredentialRequest{
		WalletAuth: vcwallet.WalletAuth{
			UserID: walletID,
			Auth:   auth,
		},
		ThreadID:     thID,
		WaitForDone:  true,
		Presentation: rawPresentation,
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

	logger.Infof("wallet[%s] received credential fulfillment response: %+v", interactionResponse)

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

	credentialFulfillment, err := getCredentialFulfillmentFromAttachment(&response.Attachments[0])
	if err != nil {
		return fmt.Errorf("failed to credential fulfillment from attachment %w", err)
	}

	if !stringsContains(credentialFulfillment.ManifestID, expectedManifestIDs) {
		return fmt.Errorf("expected credential fulfillment's manifest ID to be %s, but got %s instead",
			expectedManifestIDs, credentialFulfillment.ManifestID)
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

func validateOfferCredential(msg *service.DIDCommMsgMap, hasPExRequirement string) (*cm.CredentialManifest, error) {
	var offer issuecredential.OfferCredential

	if err := msg.Decode(&offer); err != nil {
		return nil, fmt.Errorf("failed to decode offer credential from incoming msg: %w", err)
	}

	if offer.Type == "" {
		return nil, fmt.Errorf("invalid offer credential message, empty type:\nmsg = %#v\noffer = %#v", msg, offer)
	}

	if len(offer.Attachments) == 0 {
		return nil, errors.New("invalid offer credential message, expected attachments")
	}

	if offer.Type == issuecredsvc.OfferCredentialMsgTypeV2 && len(offer.Formats) == 0 {
		return nil, errors.New("invalid offer credential message, expected valid attachment formats")
	}

	credentialManifest, err := validateOfferCredAttachments(&offer, hasPExRequirement)
	if err != nil {
		return nil, fmt.Errorf("failed to validate attachments %w", err)
	}

	return credentialManifest, nil
}

func validateOfferCredAttachments(offer *issuecredential.OfferCredential,
	hasPExRequirement string) (*cm.CredentialManifest, error) {
	credentialManifest, err := getCredentialManifestFromAttachment(&offer.Attachments[0])
	if err != nil {
		return nil, fmt.Errorf("credential manifest not found: err=  %w", err)
	}

	if !stringsContains(credentialManifest.ID, expectedManifestIDs) {
		return nil, fmt.Errorf("expected credential manifest ID to be %v"+
			" but got %s instead", expectedManifestIDs, credentialManifest.ID)
	}

	hasPExSupport, err := strconv.ParseBool(hasPExRequirement)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bool  %v value for PEx support", hasPExSupport)
	}
	// if Presentation requirement is defined via input descriptors then
	// presentation definition must be part of credential manifest
	if hasPExSupport {
		if credentialManifest.PresentationDefinition == nil {
			return nil, fmt.Errorf("failed to find presentation definitation in the manifest with PEx "+
				"support %v", hasPExSupport)
		}
	}

	// The Credential Fulfillment we receive from the issuer acts as a preview for the credentials we eventually
	// wish to receive.
	credentialFulfillment, err := getCredentialFulfillmentFromAttachment(&offer.Attachments[1])
	if err != nil {
		return nil, fmt.Errorf("failed to credential fulfillment from attachment %w", err)
	}

	if !stringsContains(credentialManifest.ID, expectedManifestIDs) {
		return nil, fmt.Errorf("expected credential fulfillment's manifest ID to be %v"+
			"but got %s instead", expectedManifestIDs, credentialFulfillment.ManifestID)
	}

	err = resolveVCBasedOnCredentialFulfillment(credentialFulfillment, offer.Attachments[1].Data.JSON)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve vc based on credential fulfillment %w", err)
	}

	return credentialManifest, nil
}

func resolveVCBasedOnCredentialFulfillment(credentialFulfillment *cm.CredentialFulfillment,
	dataFromAttachment interface{}) error {
	documentLoader, err := bddutil.DocumentLoader()
	if err != nil {
		return fmt.Errorf("failed to load document loader: %w", err)
	}

	// These VCs are only previews - they lack proofs.
	vcs, err := credentialFulfillment.ResolveDescriptorMaps(dataFromAttachment,
		verifiable.WithJSONLDDocumentLoader(documentLoader))
	if err != nil {
		return fmt.Errorf("failed to resolve DescriptorMaps %w", err)
	}

	if len(vcs) != 1 {
		return fmt.Errorf("received %d VCs, but expected only one", len(vcs))
	}

	return nil
}

//nolint:dupl
func getCredentialManifestFromAttachment(attachment *decorator.GenericAttachment) (*cm.CredentialManifest, error) {
	attachmentAsMap, ok := attachment.Data.JSON.(map[string]interface{})
	if !ok {
		return nil, errors.New("couldn't assert attachment as a map")
	}

	credentialManifestRaw, ok := attachmentAsMap["credential_manifest"]
	if !ok {
		return nil, errors.New("credential_manifest object missing from attachment")
	}

	credentialManifestBytes, err := json.Marshal(credentialManifestRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential manifest error = %w", err)
	}

	var credentialManifest cm.CredentialManifest

	// This unmarshal call also triggers the credential manifest validation code, which ensures that the
	// credential manifest is valid under the spec.
	err = json.Unmarshal(credentialManifestBytes, &credentialManifest)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential manifest error = %w", err)
	}

	return &credentialManifest, nil
}

//nolint:dupl
func getCredentialFulfillmentFromAttachment(attachment *decorator.GenericAttachment) (*cm.CredentialFulfillment,
	error) {
	attachmentAsMap, ok := attachment.Data.JSON.(map[string]interface{})
	if !ok {
		return nil, errors.New("couldn't assert attachment as a map")
	}

	credentialFulfillmentRaw, ok := attachmentAsMap["credential_fulfillment"]
	if !ok {
		return nil, errors.New("credential_fulfillment object missing from attachment")
	}

	credentialFulfillmentBytes, err := json.Marshal(credentialFulfillmentRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential fulfillment error = %w", err)
	}

	var credentialFulfillment cm.CredentialFulfillment

	// This unmarshal call also triggers the credential fulfillment validation code, which ensures that the
	// credential fulfillment object is valid under the spec.
	err = json.Unmarshal(credentialFulfillmentBytes, &credentialFulfillment)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential fulfillment error = %w", err)
	}

	return &credentialFulfillment, nil
}

func stringsContains(val string, slice []string) bool {
	for _, s := range slice {
		if val == s {
			return true
		}
	}

	return false
}

func walletAuthKey(walletID string) string {
	return fmt.Sprintf("walletauth_%s", walletID)
}

func walletRedirectKey(walletID, issuerID string) string {
	return fmt.Sprintf("wallet_redirect_%s_%s", walletID, issuerID)
}
