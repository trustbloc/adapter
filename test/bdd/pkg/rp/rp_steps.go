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
	"time"

	"github.com/cenkalti/backoff"
	"github.com/cucumber/godog"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
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

// Steps is the BDD steps for the RP Adapter BDD tests.
type Steps struct {
	context *bddctx.BDDContext
	tenants map[string]*operation.CreateRPTenantResponse
}

// NewSteps returns new agent from client SDK.
func NewSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{
		context: ctx,
		tenants: make(map[string]*operation.CreateRPTenantResponse),
	}
}

// RegisterSteps registers agent steps.
func (s *Steps) RegisterSteps(g *godog.Suite) {
	g.Step(`^a request is sent to create an RP tenant with label "([^"]*)"$`, s.createTenant)
	g.Step(`^the trustbloc DID of the tenant with label "([^"]*)" is resolvable$`, s.resolveDID)
	g.Step(`^the client ID of the tenant with label "([^"]*)" is registered at hydra$`, s.lookupClientID)
}

func (s *Steps) createTenant(label string) error {
	requestBytes, err := json.Marshal(&operation.CreateRPTenantRequest{Label: label})
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

	s.tenants[label] = response

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

	publicDID := s.tenants[label].PublicDID

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

	for _, c := range list.Payload {
		if c.ClientID == s.tenants[label].ClientID {
			return nil
		}
	}

	return fmt.Errorf(
		"rp tenant with label %s and clientID %s is not registered at hydra url %s",
		label, s.tenants[label].ClientID, hydraURL)
}
