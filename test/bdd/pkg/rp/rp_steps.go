/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/coreos/go-oidc"
	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/trustbloc/edge-core/pkg/log"
	trustblocvdri "github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-adapter/pkg/restapi/rp/operation"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/agent"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
	bddctx "github.com/trustbloc/edge-adapter/test/bdd/pkg/context"
)

const (
	rpAdapterURL   = "http://localhost:8070"
	resolverURL    = "http://localhost:8072/1.0/identifiers"
	hydraAdminURL  = "https://localhost:4445/"
	hydraPublicURL = "https://localhost:4444/"
)

var logger = log.New("edge-adapter/bddtests/rp")

type tenantContext struct {
	*operation.CreateRPTenantResponse
	callback     string
	pdHandle     string
	browser      *http.Client
	walletConnID string
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
	g.Step(`^a request is sent to create an RP tenant with label "([^"]*)" and callback "([^"]*)"$`, s.createTenant)
	g.Step(`^the trustbloc DID of the tenant with label "([^"]*)" is resolvable$`, s.resolveDID)
	g.Step(`^the client ID of the tenant with label "([^"]*)" is registered at hydra$`, s.lookupClientID)
	g.Step(`^a registered rp tenant with label "([^"]*)" and callback "([^"]*)"$`, s.registerTenantFlow)
	g.Step(`^the rp tenant "([^"]*)" redirects the user to the rp adapter$`, s.redirectUserToAdapter)
	g.Step(`the rp adapter "([^"]*)" submits a CHAPI request to "([^"]*)" with presentation-definitions and a didcomm invitation to connect`, s.sendCHAPIRequestToWallet) //nolint:lll
	g.Step(`^"([^"]*)" accepts the didcomm invitation$`, s.walletAcceptsDIDCommInvitation)
	g.Step(`^"([^"]*)" connects with the RP adapter "([^"]*)"$`, s.validateConnection)
}

func (s *Steps) registerAgentController(agentID, inboundHost, inboundPort, controllerURL string) error {
	return s.controller.ValidateAgentConnection(agentID, inboundHost, inboundPort, controllerURL)
}

func (s *Steps) createTenant(label, callback string) error {
	requestBytes, err := json.Marshal(&operation.CreateRPTenantRequest{
		Label:    label,
		Callback: callback,
	})
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo( //nolint:bodyclose
		http.MethodPost,
		rpAdapterURL+"/relyingparties",
		"application/json",
		"",
		bytes.NewBuffer(requestBytes))
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
		callback:               callback,
	}

	return nil
}

func (s *Steps) resolveDID(label string) error {
	vdri := trustblocvdri.New(
		trustblocvdri.WithTLSConfig(s.context.TLSConfig()),
		trustblocvdri.WithResolverURL(resolverURL),
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
			fmt.Printf("WARNING - failed to resolve %s - will sleep for %s before trying again : %s\n",
				publicDID, sleep, retryErr)
		},
	)
	if err != nil {
		return fmt.Errorf("failed to resolve %s : %w", publicDID, err)
	}

	return nil
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
	if !stringsContain(result.RedirectUris, expected.callback) {
		return fmt.Errorf(
			"expected tenant to be registered with callback %s but instead got %v",
			expected.callback, result.RedirectUris)
	}

	expectedScopes := []string{oidc.ScopeOpenID, "CreditCardStatement"}
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

func (s *Steps) registerTenantFlow(label, callback string) error {
	err := s.createTenant(label, callback)
	if err != nil {
		return err
	}

	err = s.resolveDID(label)
	if err != nil {
		return err
	}

	return s.lookupClientID(label)
}

func (s *Steps) redirectUserToAdapter(label string) error {
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
		RedirectURL:  tenant.callback,
		Scopes:       []string{oidc.ScopeOpenID, "CreditCardStatement"},
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

	logger.Debugf("response request: %+v", resp.Request)
	logger.Debugf("received: %s", string(bits))

	if !strings.HasPrefix(resp.Request.URL.String(), rpAdapterURL+"/ui") {
		return errors.New("rp adapter failed to redirect user to the ui endpoint")
	}

	handle := resp.Request.URL.Query().Get("pd")

	if handle == "" {
		return errors.New("adapter failed to redirect user to UI with a handle")
	}

	tenant.pdHandle = handle
	tenant.browser = browser

	return nil
}

func (s *Steps) sendCHAPIRequestToWallet(tenantID, walletID string) error {
	err := s.fetchCHAPIRequest(tenantID, walletID)
	if err != nil {
		return fmt.Errorf("failed to send chapi request to wallet : %w", err)
	}

	return s.submitDIDCommInvitationToWallet(tenantID, walletID)
}

func (s *Steps) fetchCHAPIRequest(tenantID, walletID string) error {
	tenant := s.tenantCtx[tenantID]

	//nolint:bodyclose
	resp, err := tenant.browser.Get(fmt.Sprintf("%s/presentations/create?pd=%s", rpAdapterURL, tenant.pdHandle))
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

	s.context.Store[bddutil.GetDIDConnectRequestKey(tenantID, walletID)] = string(bits)

	return nil
}

func (s *Steps) submitDIDCommInvitationToWallet(tenantID, walletID string) error {
	inv := s.context.Store[bddutil.GetDIDConnectRequestKey(tenantID, walletID)]

	connID, err := s.controller.ReceiveInvitation(walletID, inv)
	if err != nil {
		return fmt.Errorf("%s failed to receive invitation from %s : %w", walletID, tenantID, err)
	}

	s.tenantCtx[tenantID].walletConnID = connID

	return nil
}

func (s *Steps) walletAcceptsDIDCommInvitation(walletID string) error {
	err := s.controller.ApproveInvitation(walletID)
	if err != nil {
		return fmt.Errorf("%s failed to approve the invitation : %w", walletID, err)
	}

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
			logger.Warnf(
				"caught an error [%s] while validating connection status between %s and %s - will sleep for %s before trying again", //nolint:lll
				e.Error(), walletID, tenantID, d)
		},
	)

	return err
}

func stringsContain(slice []string, val string) bool {
	for i := range slice {
		if slice[i] == val {
			return true
		}
	}

	return false
}
