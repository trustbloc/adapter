/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/coreos/go-oidc"
	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/trustbloc/edge-core/pkg/log"
	trustblocdid "github.com/trustbloc/trustbloc-did-method/pkg/did"
	trustblocvdri "github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-adapter/pkg/crypto"
	"github.com/trustbloc/edge-adapter/pkg/presentationex"
	"github.com/trustbloc/edge-adapter/pkg/presexch"
	"github.com/trustbloc/edge-adapter/pkg/restapi/rp/operation"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/agent"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
	bddctx "github.com/trustbloc/edge-adapter/test/bdd/pkg/context"
)

const (
	rpAdapterURL        = "https://localhost:8070"
	resolverURL         = "http://localhost:8072/1.0/identifiers"
	hydraAdminURL       = "https://localhost:4445/"
	hydraPublicURL      = "https://localhost:4444/"
	governanceCtx       = "https://trustbloc.github.io/context/governance/context.jsonld"
	governanceVCCTXSize = 3

	trustblocDIDMethodDomain = "testnet.trustbloc.local"
)

const relyingPartyResultsPageSimulation = "Your credentials have been received!"

var logger = log.New("edge-adapter/bddtests/rp")

type tenantContext struct {
	*operation.CreateRPTenantResponse
	label            string
	callbackURL      string
	pdHandle         string
	browser          *http.Client
	callbackServer   *httptest.Server
	walletConnID     string
	invitationID     string
	expectedUserData map[string]interface{}
	oidcProvider     *oidc.Provider
	oauth2Config     *oauth2.Config
	callbackReceived *url.URL
	scope            []string
	presDefs         *presexch.PresentationDefinitions
}

// nolint:gochecknoglobals
var localCredentials = map[string]func() *verifiable.Credential{
	"driver_license:local": newDriversLicenseVC,
}

// nolint:gochecknoglobals
var remoteCredentials = map[string]func() *verifiable.Credential{
	"credit_card_stmt:remote": newCreditCardStatementVC,
}

// Steps is the BDD steps for the RP Adapter BDD tests.
type Steps struct {
	context    *bddctx.BDDContext
	tenantCtx  map[string]*tenantContext
	controller *agent.Steps
}

// NewSteps returns new agent from client SDK.
func NewSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{
		context:    ctx,
		tenantCtx:  make(map[string]*tenantContext),
		controller: agent.NewSteps(ctx),
	}
}

// RegisterSteps registers agent steps.
func (s *Steps) RegisterSteps(g *godog.Suite) {
	g.Step(`^the "([^"]*)" is running on "([^"]*)" port "([^"]*)" with controller "([^"]*)"$`, s.registerAgentController)
	g.Step(`^the "([^"]*)" is running on "([^"]*)" port "([^"]*)" with webhook "([^"]*)" and controller "([^"]*)"$`, s.registerAgentControllerWithWebhook) //nolint:lll
	g.Step(`^a request is sent to create an RP tenant with label "([^"]*)"$`, s.createTenant)
	g.Step(`^the trustbloc DID of the tenant with label "([^"]*)" is resolvable$`, s.resolveDID)
	g.Step(`^the client ID of the tenant with label "([^"]*)" is registered at hydra$`, s.lookupClientID)
	g.Step(`^the client ID of the tenant with label "([^"]*)" and scopes "([^"]*)" is registered at hydra$`, s.lookupClientID) //nolint:lll
	g.Step(`^a request is sent to create an RP tenant with label "([^"]*)" and scopes "([^"]*)"$`, s.registerTenantFlow)
	g.Step(`^a registered rp tenant with label "([^"]*)" and scopes "([^"]*)"$`, s.registerTenantFlow)
	g.Step(`^the rp tenant "([^"]*)" redirects the user to the rp adapter with scope "([^"]*)"$`, s.redirectUserToAdapter)
	g.Step(`the rp adapter "([^"]*)" submits a CHAPI request to "([^"]*)" with presentation-definitions and a didcomm invitation to connect`, s.sendCHAPIRequestToWallet) //nolint:lll
	g.Step(`^"([^"]*)" accepts the didcomm invitation from "([^"]*)"$`, s.walletAcceptsDIDCommInvitation)
	g.Step(`^"([^"]*)" connects with the RP adapter "([^"]*)"$`, s.validateConnection)
	g.Step(`^"([^"]*)" and "([^"]*)" have a didcomm connection$`, s.connectAgents)
	g.Step(`^an rp tenant with label "([^"]*)" and scopes "([^"]*)" that requests the "([^"]*)" scope from the "([^"]*)"`, s.didexchangeFlow)                                                                                   //nolint:lll
	g.Step(`^the "([^"]*)" provides an authorization credential via CHAPI that contains the DIDs of rp "([^"]*)" and issuer "([^"]*)"$`, s.walletRespondsWithAuthorizationCredential)                                           //nolint:lll
	g.Step(`^the "([^"]*)" provides an authorization credential via CHAPI that contains the DIDs of blinded rp "([^"]*)" registered with router "([^"]*)" and issuer "([^"]*)"$`, s.walletRespondsWithBlindedRPAuthzCredential) //nolint:lll
	g.Step(`^"([^"]*)" responds to "([^"]*)" with the user's data$`, s.issuerRepliesWithUserData)
	g.Step(`^the user is redirected to the rp tenant "([^"]*)"$`, s.userRedirectBackToTenant)
	g.Step(`^the rp tenant "([^"]*)" retrieves the user data from the rp adapter$`, s.rpTenantRetrievesUserData)
}

func (s *Steps) registerAgentController(agentID, inboundHost, inboundPort, controllerURL string) error {
	return s.controller.ValidateAgentConnection(agentID, inboundHost, inboundPort, controllerURL)
}

func (s *Steps) registerAgentControllerWithWebhook(agentID, inboundHost, inboundPort,
	webhookURL, controllerURL string) error {
	return s.controller.ValidateAgentConnectionWithWebhook(agentID, inboundHost, inboundPort, webhookURL, controllerURL)
}

func (s *Steps) createTenant(label, scopesStr string) error {
	callbackServer := httptest.NewServer(s)
	callbackURL := callbackServer.URL + "/" + label
	scopes := strings.Split(scopesStr, ",")

	requestBytes, err := json.Marshal(&operation.CreateRPTenantRequest{
		Label:    label,
		Callback: callbackURL,
		Scopes:   scopes,
	})
	if err != nil {
		return err
	}

	resp, err := (&http.Client{
		Transport: &http.Transport{TLSClientConfig: s.context.TLSConfig()},
	}).Post(rpAdapterURL+"/relyingparties", "application/json", bytes.NewReader(requestBytes)) //nolint:bodyclose
	if err != nil {
		return fmt.Errorf("failed to send request to create rp tenant : %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read create rp tenant response : %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	response := &operation.CreateRPTenantResponse{}

	err = json.NewDecoder(bytes.NewBuffer(respBytes)).Decode(response)
	if err != nil {
		return fmt.Errorf("failed to decode create rp tenant response : %s", err)
	}

	s.tenantCtx[label] = &tenantContext{
		CreateRPTenantResponse: response,
		label:                  label,
		callbackURL:            callbackURL,
		callbackServer:         callbackServer,
		expectedUserData:       make(map[string]interface{}),
	}

	return nil
}

func (s *Steps) resolveDID(label string) error {
	vdri := trustblocvdri.New(
		trustblocvdri.WithTLSConfig(s.context.TLSConfig()),
		trustblocvdri.WithResolverURL(resolverURL),
		trustblocvdri.WithDomain("testnet.trustbloc.local"),
	)

	const (
		maxRetries = 3
		sleep      = 500 * time.Millisecond
	)

	publicDID := s.tenantCtx[label].PublicDID

	err := backoff.RetryNotify(
		func() error {
			_, err := vdri.Read(publicDID)
			return err
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(sleep), maxRetries),
		func(retryErr error, sleep time.Duration) {
			logger.Debugf("failed to resolve %s - will sleep for %s before trying again : %s",
				publicDID, sleep, retryErr)
		},
	)
	if err != nil {
		return fmt.Errorf("failed to resolve %s : %w", publicDID, err)
	}

	return nil
}

func (s *Steps) newTrustBlocDID(agentID string) (*did.Doc, error) {
	keys := [3]struct {
		keyID string
		bits  []byte
	}{}

	var err error

	for i := range keys {
		keys[i].keyID, keys[i].bits, err = s.controller.CreateKey(agentID, kms.ED25519Type)
		if err != nil {
			return nil, fmt.Errorf("'%s' failed to create a new key set: %w", agentID, err)
		}
	}

	trustblocClient := trustblocdid.New(trustblocdid.WithTLSConfig(&tls.Config{
		RootCAs: s.context.TLSConfig().RootCAs, MinVersion: tls.VersionTLS12,
	}))

	didDoc, err := trustblocClient.CreateDID(
		trustblocDIDMethodDomain,
		trustblocdid.WithPublicKey(&trustblocdid.PublicKey{
			ID:       keys[0].keyID,
			Type:     trustblocdid.JWSVerificationKey2020,
			Encoding: trustblocdid.PublicKeyEncodingJwk,
			KeyType:  trustblocdid.Ed25519KeyType,
			Purpose:  []string{trustblocdid.KeyPurposeGeneral, trustblocdid.KeyPurposeAuth, trustblocdid.KeyPurposeAssertion},
			Value:    keys[0].bits,
		}),
		trustblocdid.WithPublicKey(&trustblocdid.PublicKey{
			ID:       keys[1].keyID,
			Encoding: trustblocdid.PublicKeyEncodingJwk,
			KeyType:  trustblocdid.Ed25519KeyType,
			Value:    keys[1].bits,
			Recovery: true,
		}),
		trustblocdid.WithPublicKey(&trustblocdid.PublicKey{
			ID:       keys[2].keyID,
			Encoding: trustblocdid.PublicKeyEncodingJwk,
			KeyType:  trustblocdid.Ed25519KeyType,
			Value:    keys[2].bits,
			Update:   true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new trustbloc did: %w", err)
	}

	friendlyName := uuid.New().String()

	_, err = bddutil.ResolveDID(s.context.VDRI, didDoc.ID, 10)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve did=%s err: %w", didDoc.ID, err)
	}

	err = s.controller.SaveDID(agentID, friendlyName, didDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to save new trustbloc did: %w", err)
	}

	return didDoc, nil
}

func (s *Steps) lookupClientID(label string) error {
	u, err := url.Parse(hydraAdminURL)
	if err != nil {
		return fmt.Errorf("failed to parse hydraAdminURL %s : %w", hydraAdminURL, err)
	}

	hydra := client.NewHTTPClientWithConfig(
		nil,
		&client.TransportConfig{
			Schemes:  []string{u.Scheme},
			Host:     u.Host,
			BasePath: u.Path,
		},
	).Admin

	request := admin.NewListOAuth2ClientsParamsWithHTTPClient(&http.Client{
		Transport: &http.Transport{TLSClientConfig: s.context.TLSConfig()},
	})
	request.SetContext(context.Background())

	list, err := hydra.ListOAuth2Clients(request)
	if err != nil {
		return fmt.Errorf("failed to list oauth2 clients at hydra url %s : %w", hydraAdminURL, err)
	}

	tenantCtx := s.tenantCtx[label]

	for _, c := range list.Payload {
		if c.ClientID == tenantCtx.ClientID {
			return validateTenantRegistration(tenantCtx, c)
		}
	}

	return fmt.Errorf(
		"rp tenant with label %s and clientID %s is not registered at hydra url %s",
		label, s.tenantCtx[label].ClientID, hydraAdminURL)
}

func validateTenantRegistration(expected *tenantContext, result *models.OAuth2Client) error {
	if !stringsContain(result.RedirectUris, expected.callbackURL) {
		return fmt.Errorf(
			"expected tenant to be registered with callback %s but instead got %v",
			expected.callbackURL, result.RedirectUris)
	}

	expectedScopes := []string{oidc.ScopeOpenID, "credit_card_stmt:remote"}
	resultScopes := strings.Split(result.Scope, " ")

	for i := range expectedScopes {
		if !stringsContain(resultScopes, expectedScopes[i]) {
			return fmt.Errorf(
				"expected tenant to be registered with scope %s but instead got %v",
				expectedScopes[i], resultScopes)
		}
	}

	return nil
}

func (s *Steps) registerTenantFlow(label, scopesStr string) error {
	err := s.createTenant(label, scopesStr)
	if err != nil {
		return err
	}

	err = s.resolveDID(label)
	if err != nil {
		return err
	}

	return s.lookupClientID(label)
}

// nolint:funlen
func (s *Steps) redirectUserToAdapter(label, scope string) error {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to initialize cookie jar : %w", err)
	}

	browser := &http.Client{
		Transport: &http.Transport{TLSClientConfig: s.context.TLSConfig()},
		Jar:       cookieJar,
	}

	provider, err := oidc.NewProvider(oidc.ClientContext(context.Background(), browser), hydraPublicURL)
	if err != nil {
		return fmt.Errorf("failed to create an oidc provider : %w", err)
	}

	tenant := s.tenantCtx[label]

	oauth2Config := oauth2.Config{
		ClientID:     tenant.ClientID,
		ClientSecret: tenant.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  tenant.callbackURL,
		Scopes:       append([]string{oidc.ScopeOpenID}, strings.Split(scope, ",")...),
	}

	state := strings.ReplaceAll(uuid.New().String(), "-", "")
	redirectURL := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOnline)

	resp, err := browser.Get(redirectURL) //nolint:bodyclose
	if err != nil {
		return fmt.Errorf("failed to redirect user to rp adapter : %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	// should receive the contents of the UI here
	bits, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body of redirect to rp adapter : %w", err)
	}

	if !strings.HasPrefix(resp.Request.URL.String(), rpAdapterURL+"/ui") {
		return fmt.Errorf(
			"rp adapter failed to redirect user to the ui endpoint. Request returned in response: %+v. Response body: %s", //nolint:lll
			resp.Request, string(bits),
		)
	}

	handle := resp.Request.URL.Query().Get("h")

	if handle == "" {
		return errors.New("adapter failed to redirect user to UI with a handle")
	}

	tenant.oidcProvider = provider
	tenant.oauth2Config = &oauth2Config
	tenant.pdHandle = handle
	tenant.browser = browser
	tenant.scope = strings.Split(scope, ",")

	return nil
}

func (s *Steps) sendCHAPIRequestToWallet(tenantID, walletID string) error {
	tenant := s.tenantCtx[tenantID]

	//nolint:bodyclose
	resp, err := tenant.browser.Get(fmt.Sprintf("%s/presentations/create?h=%s", rpAdapterURL, tenant.pdHandle))
	if err != nil {
		return fmt.Errorf("rp adapter failed to produce a chapi request : %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	result := &operation.GetPresentationRequestResponse{}

	err = json.NewDecoder(resp.Body).Decode(result)
	if err != nil {
		return fmt.Errorf("failed to decode rp adapter's response : %w", err)
	}

	bits, err := json.Marshal(result.Inv)
	if err != nil {
		return fmt.Errorf("failed to marshal didcomm invitation : %w", err)
	}

	err = validatePresentationDefinitions(result.PD, tenant.scope)
	if err != nil {
		return fmt.Errorf("failed to validate presentation definitions for '%s': %w", tenantID, err)
	}

	err = validateGovernance(result.Credentials[0])
	if err != nil {
		return fmt.Errorf("failed to parse governance credential : %s", err.Error())
	}

	tenant.invitationID = result.Inv.ID
	tenant.presDefs = result.PD
	s.context.Store[bddutil.GetDIDConnectRequestKey(tenantID, walletID)] = string(bits)

	return nil
}

func validatePresentationDefinitions(pd *presexch.PresentationDefinitions, scope []string) error {
	file, err := os.Open("./fixtures/testdata/presentationdefinitions.json")
	if err != nil {
		return fmt.Errorf("failed open presentation definitions config file: %w", err)
	}

	defer func() {
		closeErr := file.Close()
		if closeErr != nil {
			fmt.Printf("WARNING - failed to close presentation definitions config file: %s", closeErr)
		}
	}()

	prov, err := presentationex.New(file)
	if err != nil {
		return fmt.Errorf("failed to init presentation definitions provider: %w", err)
	}

	reference, err := prov.Create(scope)
	if err != nil {
		return fmt.Errorf(
			"presentation definitions provider failed to create definitions for %+v: %w", scope, err)
	}

	actual := make([][]string, len(pd.InputDescriptors))

	for i := range pd.InputDescriptors {
		actual[i] = pd.InputDescriptors[i].Schema.URI
	}

	expected := make([][]string, len(reference.InputDescriptors))

	for i := range reference.InputDescriptors {
		expected[i] = reference.InputDescriptors[i].Schema.URI
	}

	if len(expected) != len(actual) {
		return fmt.Errorf(
			"unexpected number of descriptors in presentation definition: expected=%+v, actual=%+v",
			reference, pd)
	}

	for i := range expected {
		if !stringsIntersect(actual[i], expected[i]) {
			return fmt.Errorf(
				"presentation definition missing schema uri %s; expected=%+v, actual=%+v",
				expected[i], expected, actual)
		}
	}

	return nil
}

func validateGovernance(governanceVCBytes []byte) error {
	governanceVC, err := verifiable.ParseUnverifiedCredential(governanceVCBytes)
	if err != nil {
		return err
	}

	if len(governanceVC.Context) != governanceVCCTXSize {
		return fmt.Errorf("governance vc context not equal 2")
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

func (s *Steps) walletAcceptsDIDCommInvitation(walletID, tenantID string) error {
	marshalled := s.context.Store[bddutil.GetDIDConnectRequestKey(tenantID, walletID)]

	inv := &outofband.Invitation{}

	err := json.Unmarshal([]byte(marshalled), inv)
	if err != nil {
		return fmt.Errorf("failed to unmarshal oob invitation from bdd test store : %w", err)
	}

	connID, err := s.controller.AcceptOOBInvitation(walletID, inv, walletID)
	if err != nil {
		return fmt.Errorf("%s failed to accept invitation from %s : %w", walletID, tenantID, err)
	}

	s.tenantCtx[tenantID].walletConnID = connID

	return nil
}

func (s *Steps) validateConnection(walletID, tenantID string) error {
	tenant := s.tenantCtx[tenantID]

	err := backoff.RetryNotify(
		func() error {
			_, err := s.controller.ValidateConnection(walletID, tenant.walletConnID)
			return err
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 3),
		func(e error, d time.Duration) {
			logger.Debugf(
				"caught an error [%s] while validating connection status between %s and %s - will sleep for %s before trying again", //nolint:lll
				e.Error(), walletID, tenantID, d)
		},
	)

	return err
}

func (s *Steps) connectAgents(agentA, agentB string) error {
	return s.controller.Connect(agentA, agentB)
}

func (s *Steps) didexchangeFlow(tenantID, scopesStr, scope, walletID string) error {
	err := s.registerTenantFlow(tenantID, scopesStr)
	if err != nil {
		return err
	}

	err = s.redirectUserToAdapter(tenantID, scope)
	if err != nil {
		return err
	}

	err = s.sendCHAPIRequestToWallet(tenantID, walletID)
	if err != nil {
		return err
	}

	err = s.walletAcceptsDIDCommInvitation(walletID, tenantID)
	if err != nil {
		return err
	}

	return s.validateConnection(walletID, tenantID)
}

func (s *Steps) walletRespondsWithAuthorizationCredential(wallet, tenant, issuer string) error {
	return s.respondWithAuthZ(wallet, tenant, issuer, "")
}

func (s *Steps) respondWithAuthZ(wallet, tenant, issuer, routerURL string) error {
	submissionVP, err := s.walletCreatesAuthorizationCredential(wallet, tenant, issuer, routerURL)
	if err != nil {
		return fmt.Errorf("'%s' failed to create presentation submission VP : %w", wallet, err)
	}

	vpBytes, err := submissionVP.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal verifiable presentation : %w", err)
	}

	tenantCtx := s.tenantCtx[tenant]

	chapiResponseBytes, err := json.Marshal(&operation.HandleCHAPIResponse{
		InvitationID:           tenantCtx.invitationID,
		VerifiablePresentation: vpBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal chapi response : %w", err)
	}

	resp, err := tenantCtx.browser.Post( // nolint:bodyclose
		rpAdapterURL+"/presentations/handleResponse", "application/json", bytes.NewReader(chapiResponseBytes))
	if err != nil {
		return fmt.Errorf("'%s' failed to post response back to '%s': %w", wallet, tenant, err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respContents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read rp adapter response contents: %w", err)
	}

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf(
			"'%s' returned an unexpected status code. got: %d, want: %d, message: %s",
			tenant, resp.StatusCode, http.StatusAccepted, respContents)
	}

	return nil
}

func (s *Steps) walletRespondsWithBlindedRPAuthzCredential(wallet, tenant, routerURL, issuer string) error {
	return s.respondWithAuthZ(wallet, tenant, issuer, routerURL)
}

// nolint:funlen,gocyclo
func (s *Steps) walletCreatesAuthorizationCredential(wallet, tenant, issuer,
	routerURL string) (*verifiable.Presentation, error) {
	walletTenantConn, err := s.controller.GetConnectionBetweenAgents(wallet, tenant)
	if err != nil {
		return nil, err
	}

	if routerURL != "" {
		err = s.controller.BlindedRouting(wallet, walletTenantConn.ConnectionID, routerURL)
		if err != nil {
			return nil, err
		}
	}

	rpDID, err := s.controller.GetAuthZDIDDoc(wallet, walletTenantConn.ConnectionID)
	if err != nil {
		return nil, fmt.Errorf("%s failed to resolve %s's DID %s : %w", wallet, tenant, walletTenantConn.TheirDID, err)
	}

	walletIssuerConn, err := s.controller.GetConnectionBetweenAgents(wallet, issuer)
	if err != nil {
		return nil, err
	}

	issuerDID, err := s.controller.ResolveDID(wallet, walletIssuerConn.TheirDID)
	if err != nil {
		return nil, fmt.Errorf("%s failed to resolve %s's DID %s : %w", wallet, issuer, walletIssuerConn.TheirDID, err)
	}

	_, err = s.controller.CreateConnection(issuer, issuerDID.ID, tenant, rpDID)
	if err != nil {
		return nil, fmt.Errorf("%s failed to create a connection to %s : %w", issuer, tenant, err)
	}

	authzVC, err := newUserAuthorizationVC(walletTenantConn.MyDID, rpDID, issuerDID)
	if err != nil {
		return nil, fmt.Errorf("failed to create user authorization credential : %w", err)
	}

	// TODO the authZ credential the wallet is passing to the RP is currently signed by the issuer
	signedAuthzVC, err := s.controller.SignCredential(issuer, issuerDID.ID, authzVC)
	if err != nil {
		return nil, fmt.Errorf("'%s' failed to sign the authZ VC: %w", issuer, err)
	}

	localCred, err := s.findCred(tenant, localCredentials)
	if err != nil {
		return nil, fmt.Errorf("'%s' failed to find a remote test credential: %w", issuer, err)
	}

	// TODO this credential should ideally be signed by a different issuer
	signedLocalCred, err := s.controller.SignCredential(issuer, issuerDID.ID, localCred)
	if err != nil {
		return nil, fmt.Errorf("'%s' failed to sign the local VC: %w", issuer, err)
	}

	tenantCtx := s.tenantCtx[tenant]

	submissionVP, err := newPresentationSubmissionVP(
		&presexch.PresentationSubmission{
			DescriptorMap: []*presexch.InputDescriptorMapping{
				{
					ID:   tenantCtx.presDefs.InputDescriptors[0].ID,
					Path: "$.verifiableCredential[0]",
				},
				{
					ID:   tenantCtx.presDefs.InputDescriptors[1].ID,
					Path: "$.verifiableCredential[1]",
				},
			},
		},
		signedAuthzVC, signedLocalCred,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create presentation submission VP : %w", err)
	}

	// TODO the wallet should not be signing their presentation submission with a TB DID:
	//  https://github.com/trustbloc/edge-agent/issues/322
	signingDID, err := s.newTrustBlocDID(wallet)
	if err != nil {
		return nil, fmt.Errorf("'%s' failed to create a new trustbloc did for signing the vp: %w", wallet, err)
	}

	verificationMethod, err := crypto.GetVerificationMethodFromDID(signingDID, did.Authentication)
	if err != nil {
		return nil, fmt.Errorf(
			"'%s' failed to produce a verification method from did %s: %w", wallet, signingDID.ID, err)
	}

	signedSubmissionVP, err := s.controller.GeneratePresentation(wallet, signingDID.ID, verificationMethod, submissionVP)
	if err != nil {
		return nil, fmt.Errorf("'%s' failed to sign their presentation submission VP with did %s: %w",
			walletTenantConn.MyDID, wallet, err)
	}

	return signedSubmissionVP, nil
}

func (s *Steps) issuerRepliesWithUserData(issuer, tenant string) error {
	remoteCred, err := s.findCred(tenant, remoteCredentials)
	if err != nil {
		return fmt.Errorf("'%s' failed to find a remote test credential: %w", issuer, err)
	}

	// TODO - the issuer adapter is incorrectly using their public TB DID to sign presentations:
	//  https://github.com/trustbloc/edge-adapter/issues/302
	signingDID, err := s.newTrustBlocDID(issuer)
	if err != nil {
		return fmt.Errorf("'%s' failed to create a new trustbloc DID: %w", issuer, err)
	}

	signedRemoteCred, err := s.controller.SignCredential(issuer, signingDID.ID, remoteCred)
	if err != nil {
		return fmt.Errorf("'%s' failed to sign remote credential: %w", issuer, err)
	}

	vp, err := newPresentationSubmissionVP(nil, signedRemoteCred)
	if err != nil {
		return fmt.Errorf("failed to create verifiable presentation : %w", err)
	}

	verificationMethod, err := crypto.GetVerificationMethodFromDID(signingDID, did.Authentication)
	if err != nil {
		return fmt.Errorf("'%s' failed to get a verMethod from did %s: %w", issuer, signingDID.ID, err)
	}

	signedVP, err := s.controller.GeneratePresentation(issuer, signingDID.ID, verificationMethod, vp)
	if err != nil {
		return fmt.Errorf("'%s' failed to sign vp: %w", issuer, err)
	}

	err = s.controller.AcceptRequestPresentation(issuer, signedVP)
	if err != nil {
		return fmt.Errorf("%s failed to accept request-presentation : %w", issuer, err)
	}

	return nil
}

func (s *Steps) findCred(
	tenant string, suppliers map[string]func() *verifiable.Credential) (*verifiable.Credential, error) {
	tenantCtx := s.tenantCtx[tenant]

	var cred *verifiable.Credential

	for _, scope := range tenantCtx.scope {
		f, supported := suppliers[scope]
		if !supported {
			continue
		}

		cred = f()

		bits, err := json.Marshal(cred.Subject)
		if err != nil {
			return nil, fmt.Errorf(`failed to marshal credential subject: %w`, err)
		}

		expected := make(map[string]interface{})

		err = json.Unmarshal(bits, &expected)
		if err != nil {
			return nil, fmt.Errorf(`failed to unmarshal credential subject: %w`, err)
		}

		tenantCtx.expectedUserData[scope] = expected

		break
	}

	if cred == nil {
		return nil, fmt.Errorf(
			"scopes [%+v] not supported by test credential suppliers %+v", tenantCtx.scope, suppliers)
	}

	return cred, nil
}

// nolint:funlen,gocyclo
func (s *Steps) userRedirectBackToTenant(tenant string) error {
	tenantCtx := s.tenantCtx[tenant]

	result := &operation.HandleCHAPIResponseResult{}

	err := backoff.RetryNotify(
		func() error {
			req := fmt.Sprintf("%s/presentations/result?h=%s", rpAdapterURL, tenantCtx.invitationID)

			resp, serviceErr := tenantCtx.browser.Get(req) // nolint:bodyclose
			if serviceErr != nil {
				return fmt.Errorf("'%s' failed to respond to wallet response status request: %w", tenant, serviceErr)
			}

			defer bddutil.CloseResponseBody(resp.Body)

			respContents, serviceErr := ioutil.ReadAll(resp.Body)
			if serviceErr != nil {
				return fmt.Errorf("failed to read the response contents: %w", serviceErr)
			}

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf(
					"unexpected status from '%s': got: %d, want: %d, contents: %s",
					tenant, resp.StatusCode, http.StatusOK, respContents)
			}

			serviceErr = json.NewDecoder(bytes.NewReader(respContents)).Decode(result)
			if serviceErr != nil {
				return fmt.Errorf("failed to decode response [%s] from '%s': %w", respContents, tenant, serviceErr)
			}

			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 20),
		func(err error, duration time.Duration) {
			fmt.Printf("failed to fetch redirectURL from the rp adapter. Error=[%s]. Will retry in %s.\n",
				err.Error(), duration)
		},
	)
	if err != nil {
		return err
	}

	if result.RedirectURL == "" {
		return fmt.Errorf("'%s' did not return a redirect url", tenant)
	}

	resp, err := tenantCtx.browser.Get(result.RedirectURL) //nolint:bodyclose
	if err != nil {
		return fmt.Errorf("failed to redirect user to %s : %w", result.RedirectURL, err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected %d but rp results page returned %d", http.StatusOK, resp.StatusCode)
	}

	resultsPage, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read contents of rp results page : %w", err)
	}

	if relyingPartyResultsPageSimulation != string(resultsPage) {
		return fmt.Errorf("unexpected contents of rp results page : %s", resultsPage)
	}

	return nil
}

func (s *Steps) rpTenantRetrievesUserData(tenant string) error {
	tenantCtx := s.tenantCtx[tenant]

	oauth2Token, err := tenantCtx.oauth2Config.Exchange(
		context.WithValue(context.Background(), oauth2.HTTPClient, tenantCtx.browser),
		tenantCtx.callbackReceived.Query().Get("code"),
	)
	if err != nil {
		return fmt.Errorf(`"%s" failed to exchange code for oauth2 token : %w`, tenant, err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return fmt.Errorf(`"%s" did not receive an id_token from the adapter`, tenant)
	}

	verifier := tenantCtx.oidcProvider.Verifier(&oidc.Config{
		ClientID: tenantCtx.ClientID,
	})

	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		return fmt.Errorf(`"%s" failed to verify idToken "%s" : %w`, tenant, idToken, err)
	}

	return s.validate(tenant, idToken)
}

func (s *Steps) validate(tenant string, idToken *oidc.IDToken) error {
	tenantCtx := s.tenantCtx[tenant]
	claims := make(map[string]interface{})

	err := idToken.Claims(&claims)
	if err != nil {
		return fmt.Errorf(`"%s" failed to extract the claims from the id_token : %w`, tenant, err)
	}

	claimNames, found := claims["_claim_names"].(map[string]interface{})
	if !found {
		return fmt.Errorf("'%s' did not find '_claim_names' in the id_token", tenant)
	}

	claimSources, found := claims["_claim_sources"].(map[string]interface{})
	if !found {
		return fmt.Errorf("'%s' did not find '_claim_sources' in the id_token", tenant)
	}

	for scope, expected := range tenantCtx.expectedUserData {
		src, found := claimNames[scope].(string)
		if !found {
			return fmt.Errorf("'%s' did not find scope '%s' in _claim_names", tenant, scope)
		}

		received, found := claimSources[src].(map[string]interface{})
		if !found {
			return fmt.Errorf("'%s' did not find a claimSource for scope %s", tenant, scope)
		}

		actual, found := received["claims"].(map[string]interface{})
		if !found {
			return fmt.Errorf(
				"'%s' did not find a 'claims' container inside verified_claims for scope %s",
				tenant, scope)
		}

		if !reflect.DeepEqual(expected, actual) {
			return fmt.Errorf(
				"'%s' did not receive the data expected from the issuer. got: %+v want: %+v",
				tenant, actual, expected)
		}
	}

	return nil
}

func (s *Steps) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var tenantCtx *tenantContext

	for label, ctx := range s.tenantCtx {
		if strings.HasPrefix(r.URL.String(), "/"+label) {
			tenantCtx = ctx
			break
		}
	}

	if tenantCtx == nil {
		logger.Errorf("no tenant registered with callback: %s", r.URL)

		return
	}

	tenantCtx.callbackReceived = r.URL

	_, err := w.Write([]byte(relyingPartyResultsPageSimulation))
	if err != nil {
		logger.Warnf("failed to display rp screen to user : %s", err)
	}
}

func stringsContain(slice []string, val string) bool {
	for i := range slice {
		if slice[i] == val {
			return true
		}
	}

	return false
}

func stringsIntersect(a, b []string) bool {
	for i := range a {
		for j := range b {
			if a[i] == b[j] {
				return true
			}
		}
	}

	return false
}
