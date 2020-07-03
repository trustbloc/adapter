/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/coreos/go-oidc"
	"github.com/cucumber/godog"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	trustblocvdri "github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"

	"github.com/trustbloc/edge-adapter/pkg/restapi/rp/operation"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
	bddctx "github.com/trustbloc/edge-adapter/test/bdd/pkg/context"
)

const (
	rpAdapterURL = "http://localhost:8070"
	resolverURL  = "http://localhost:8072/1.0/identifiers"
	hydraURL     = "https://localhost:4445"
)

type tenantContext struct {
	*operation.CreateRPTenantResponse
	callback string
}

// Steps is the BDD steps for the RP Adapter BDD tests.
type Steps struct {
	context   *bddctx.BDDContext
	tenantCtx map[string]*tenantContext
}

// NewSteps returns new agent from client SDK.
func NewSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{
		context:   ctx,
		tenantCtx: make(map[string]*tenantContext),
	}
}

// RegisterSteps registers agent steps.
func (s *Steps) RegisterSteps(g *godog.Suite) {
	g.Step(`^a request is sent to create an RP tenant with label "([^"]*)" and callback "([^"]*)"$`, s.createTenant)
	g.Step(`^the trustbloc DID of the tenant with label "([^"]*)" is resolvable$`, s.resolveDID)
	g.Step(`^the client ID of the tenant with label "([^"]*)" is registered at hydra$`, s.lookupClientID)
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
	u, err := url.Parse(hydraURL)
	if err != nil {
		return fmt.Errorf("failed to parse hydraURL %s : %w", hydraURL, err)
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
		return fmt.Errorf("failed to list oauth2 clients at hydra url %s : %w", hydraURL, err)
	}

	tenantCtx := s.tenantCtx[label]

	for _, c := range list.Payload {
		if c.ClientID == tenantCtx.ClientID {
			return validateTenantRegistration(tenantCtx, c)
		}
	}

	return fmt.Errorf(
		"rp tenant with label %s and clientID %s is not registered at hydra url %s",
		label, s.tenantCtx[label].ClientID, hydraURL)
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

func stringsContain(slice []string, val string) bool {
	for i := range slice {
		if slice[i] == val {
			return true
		}
	}

	return false
}
