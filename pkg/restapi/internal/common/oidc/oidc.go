/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/trustbloc/edge-core/pkg/log"
	"golang.org/x/oauth2"
)

var logger = log.New("oidc")

// Client for oidc
type Client struct {
	oidcProvider       *oidc.Provider
	oidcClientID       string
	oidcClientSecret   string
	secretExpiry       int // TODO use
	oidcCallbackURL    string
	oauth2ConfigFunc   func(...string) *oauth2.Config
	tlsConfig          *tls.Config
	defaultOAuthConfig *oauth2.Config
	candidateScopes    map[string]struct{}
}

// Config defines configuration for oidc client
type Config struct {
	TLSConfig              *tls.Config
	OIDCProviderURL        string
	OIDCClientID           string
	OIDCClientSecret       string
	OIDCClientSecretExpiry int
	OIDCCallbackURL        string
	// Scopes scopes that oidc.Client is allowed to request.
	Scopes []string
}

// New returns client instance
func New(config *Config) (*Client, error) {
	svc := &Client{
		oidcClientID:     config.OIDCClientID,
		oidcClientSecret: config.OIDCClientSecret,
		secretExpiry:     config.OIDCClientSecretExpiry,
		oidcCallbackURL:  config.OIDCCallbackURL,
		tlsConfig:        config.TLSConfig,
		candidateScopes:  map[string]struct{}{},
	}

	for _, scope := range config.Scopes {
		svc.candidateScopes[scope] = struct{}{}
	}

	idp, err := oidc.NewProvider(
		oidc.ClientContext(
			context.Background(),
			&http.Client{
				Transport: &http.Transport{TLSClientConfig: config.TLSConfig},
			},
		),
		config.OIDCProviderURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init oidc provider with url [%s] : %w", config.OIDCProviderURL, err)
	}

	svc.oidcProvider = idp

	svc.oauth2ConfigFunc = func(scopes ...string) *oauth2.Config {
		config := &oauth2.Config{
			ClientID:     svc.oidcClientID,
			ClientSecret: svc.oidcClientSecret,
			Endpoint:     svc.oidcProvider.Endpoint(),
			RedirectURL:  svc.oidcCallbackURL,
		}

		if len(scopes) > 0 {
			config.Scopes = append(config.Scopes, scopes...)
		}

		return config
	}

	svc.defaultOAuthConfig = svc.oauth2ConfigFunc()

	return svc, nil
}

// CreateOIDCRequest create oidc request
func (c *Client) CreateOIDCRequest(state, scopeString string) string {
	potentialScopes := strings.Split(scopeString, " ")

	var scopes []string

	for _, scope := range potentialScopes {
		if _, ok := c.candidateScopes[scope]; ok {
			scopes = append(scopes, scope)
		}
	}

	redirectURL := c.oauth2ConfigFunc(scopes...).AuthCodeURL(state, oauth2.AccessTypeOffline)

	logger.Debugf("redirectURL: %s", redirectURL)

	return redirectURL
}

// GetIDTokenClaims handle oidc callback and get claims from ID token
func (c *Client) GetIDTokenClaims(reqContext context.Context, code string) ([]byte, error) {
	_, oidcToken, err := c.HandleOIDCCallback(reqContext, code)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve tokens : %s", err)
	}

	if oidcToken == nil {
		return nil, fmt.Errorf("missing id_token")
	}

	userData := make(map[string]interface{})

	err = oidcToken.Claims(&userData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract user data from id_token : %s", err)
	}

	bits, err := json.Marshal(userData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user data : %s", err)
	}

	return bits, nil
}

// CheckRefresh refreshes the given token if necessary, returning the original token if not.
func (c *Client) CheckRefresh(tok *oauth2.Token) (*oauth2.Token, error) {
	ts := c.oauth2ConfigFunc().TokenSource(context.Background(), tok)

	newTok, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return newTok, nil
}

// HandleOIDCCallback handle oidc callback and returns access token and optional refresh and ID tokens
func (c *Client) HandleOIDCCallback(reqContext context.Context, code string) (*oauth2.Token, *oidc.IDToken, error) {
	oauthToken, err := c.oauth2ConfigFunc().Exchange(
		context.WithValue(
			reqContext,
			oauth2.HTTPClient,
			&http.Client{Transport: &http.Transport{TLSClientConfig: c.tlsConfig}},
		),
		code)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange oauth2 code for token : %s", err)
	}

	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		return oauthToken, nil, nil
	}

	oidcToken, err := c.oidcProvider.Verifier(&oidc.Config{
		ClientID: c.oidcClientID,
	}).Verify(reqContext, rawIDToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify id_token : %s", err)
	}

	return oauthToken, oidcToken, nil
}
