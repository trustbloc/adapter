/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hydra

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"

	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
)

// Hydra is the client used to interface with the Hydra service.
type hydra interface {
	GetLoginRequest(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error)
	AcceptLoginRequest(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error)
	GetConsentRequest(*admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error)
	AcceptConsentRequest(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error)
	CreateOAuth2Client(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error)
}

// Client decorates the default hydra admin client with TLS configuration.
type Client struct {
	hydraClient hydra
	httpClient  *http.Client
}

// NewClient returns a new Client.
func NewClient(hydraURL *url.URL, rootCAs *x509.CertPool) *Client {
	return &Client{
		hydraClient: client.NewHTTPClientWithConfig(
			nil,
			&client.TransportConfig{
				Schemes:  []string{hydraURL.Scheme},
				Host:     hydraURL.Host,
				BasePath: hydraURL.Path,
			},
		).Admin,
		httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}}},
	}
}

// GetLoginRequest fetches the login request at hydra.
func (c *Client) GetLoginRequest(params *admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
	params.SetHTTPClient(c.httpClient)
	return c.hydraClient.GetLoginRequest(params)
}

// AcceptLoginRequest accepts the login request at hydra.
func (c *Client) AcceptLoginRequest(params *admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
	params.SetHTTPClient(c.httpClient)
	return c.hydraClient.AcceptLoginRequest(params)
}

// GetConsentRequest fetches the consent request at hydra.
func (c *Client) GetConsentRequest(params *admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
	params.SetHTTPClient(c.httpClient)
	return c.hydraClient.GetConsentRequest(params)
}

// AcceptConsentRequest accepts the consent request at hydra.
func (c *Client) AcceptConsentRequest(params *admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
	params.SetHTTPClient(c.httpClient)
	return c.hydraClient.AcceptConsentRequest(params)
}

// CreateOAuth2Client creates an oauth2 client at hydra.
func (c *Client) CreateOAuth2Client(params *admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
	params.SetHTTPClient(c.httpClient)
	return c.hydraClient.CreateOAuth2Client(params)
}
