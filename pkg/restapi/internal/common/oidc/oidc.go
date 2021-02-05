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

const (
	oauth2CallbackPath = "/oauth2/callback"
)

var logger = log.New("oidc")

// Client for oidc
type Client struct {
	oidcProvider     *oidc.Provider
	oidcClientID     string
	oidcClientSecret string
	secretExpiry     int // TODO use
	oidcCallbackURL  string
	oauth2ConfigFunc func(...string) *oauth2.Config
	tlsConfig        *tls.Config
}

// Config defines configuration for oidc client
type Config struct {
	TLSConfig              *tls.Config
	OIDCProviderURL        string
	OIDCClientID           string
	OIDCClientSecret       string
	OIDCClientSecretExpiry int
	OIDCCallbackURL        string
}

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
			RedirectURL:  fmt.Sprintf("%s%s", svc.oidcCallbackURL, oauth2CallbackPath),
			Scopes:       []string{oidc.ScopeOpenID},
		}

		if len(scopes) > 0 {
			config.Scopes = append(config.Scopes, scopes...)
		}

		return config
	}

	return svc, nil
}

// CreateOIDCRequest create oidc request
func (c *Client) CreateOIDCRequest(state, scope string) string {
	redirectURL := c.oauth2ConfigFunc(strings.Split(scope, " ")...).AuthCodeURL(state, oauth2.AccessTypeOnline)

	logger.Debugf("redirectURL: %s", redirectURL)

	return redirectURL
}

// HandleOIDCCallback handle oidc callback
func (c *Client) HandleOIDCCallback(reqContext context.Context, code string) ([]byte, error) {
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
		return nil, fmt.Errorf("missing id_token : %s", err)
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
