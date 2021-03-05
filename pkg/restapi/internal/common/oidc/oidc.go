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
	tokenSource        oauth2.TokenSource
	defaultOAuthConfig *oauth2.Config
}

// Config defines configuration for oidc client
type Config struct {
	TLSConfig              *tls.Config
	OIDCProviderURL        string
	OIDCClientID           string
	OIDCClientSecret       string
	OIDCClientSecretExpiry int
	OIDCCallbackURL        string
	RefreshToken           string
}

// TODO: add an oauth2.TokenSource (which is given the refresh token) to the Client,
//  for getting the access token with automatic refreshing

// New returns client instance
func New(config *Config) (*Client, error) {
	svc := &Client{
		oidcClientID:     config.OIDCClientID,
		oidcClientSecret: config.OIDCClientSecret,
		secretExpiry:     config.OIDCClientSecretExpiry,
		oidcCallbackURL:  config.OIDCCallbackURL,
		tlsConfig:        config.TLSConfig,
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

	if config.RefreshToken != "" {
		// without an access token, this will refresh the first time the token source is used
		tok := oauth2.Token{RefreshToken: config.RefreshToken}
		svc.tokenSource = svc.defaultOAuthConfig.TokenSource(context.Background(), &tok)
	}

	return svc, nil
}

// CreateOIDCRequest create oidc request
func (c *Client) CreateOIDCRequest(state, scope string) string {
	redirectURL := c.oauth2ConfigFunc(strings.Split(scope, " ")...).AuthCodeURL(state, oauth2.AccessTypeOffline)

	logger.Debugf("redirectURL: %s", redirectURL)

	return redirectURL
}

// GetIDTokenClaims handle oidc callback and get claims from ID token
func (c *Client) GetIDTokenClaims(reqContext context.Context, code string) ([]byte, error) {
	oauthToken, err := c.oauth2ConfigFunc().Exchange(
		context.WithValue(
			reqContext,
			oauth2.HTTPClient,
			&http.Client{Transport: &http.Transport{TLSClientConfig: c.tlsConfig}},
		),
		code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange oauth2 code for token : %s", err)
	}

	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing id_token")
	}

	oidcToken, err := c.oidcProvider.Verifier(&oidc.Config{
		ClientID: c.oidcClientID,
	}).Verify(reqContext, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify id_token : %s", err)
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
