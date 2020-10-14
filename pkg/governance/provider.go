/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package governance

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
)

var logger = log.New("edge-adapter/governance")

const (
	governanceProfileName         = "governance" // TODO make it configurable
	issueCredentialURLFormat      = "%s/governance/%s" + "/issueCredential"
	storeName                     = "governance"
	governanceVCKey               = "%s_governance_vc"
	vcsGovernanceRequestTokenName = "vcs_governance" //nolint: gosec
	didParts                      = 4
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// issueCredentialRequest request for issuing credential.
type issueCredentialRequest struct {
	DID string `json:"did,omitempty"`
}

// Provider provide governance operation.
type Provider struct {
	governanceVCSUrl string
	httpClient       httpClient
	store            storage.Store
	requestTokens    map[string]string
	domain           string
}

// New return new provider for governance provider.
func New(governanceVCSUrl string, tlsConfig *tls.Config, s storage.Provider,
	requestTokens map[string]string, domain string) (*Provider, error) {
	err := s.CreateStore(storeName)
	if err != nil && !errors.Is(err, storage.ErrDuplicateStore) {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	store, err := s.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("failed to open store : %w", err)
	}

	return &Provider{governanceVCSUrl: governanceVCSUrl,
		httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}, store: store,
		requestTokens: requestTokens, domain: domain}, nil
}

// IssueCredential issue credential.
func (p *Provider) IssueCredential(didID, profileID string) ([]byte, error) {
	_, err := p.GetCredential(profileID)
	if err != nil {
		if errors.Is(err, storage.ErrValueNotFound) {
			return p.issueCredential(p.replaceCanonicalDIDWithDomainDID(didID), profileID)
		}

		return nil, err
	}

	return nil, fmt.Errorf("governance vc already issued")
}

func (p *Provider) replaceCanonicalDIDWithDomainDID(didID string) string {
	if strings.HasPrefix(didID, "did:trustbloc") {
		split := strings.Split(didID, ":")
		if len(split) == didParts {
			domainDIDID := fmt.Sprintf("%s:%s:%s:%s", split[0], split[1], p.domain, split[3])

			return domainDIDID
		}
	}

	return didID
}

func (p *Provider) issueCredential(didID, profileID string) ([]byte, error) {
	req := &issueCredentialRequest{DID: didID}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	endpointURL := fmt.Sprintf(issueCredentialURLFormat, p.governanceVCSUrl, governanceProfileName)

	httpReq, err := http.NewRequest(http.MethodPost, endpointURL, bytes.NewBuffer(reqBytes))

	if err != nil {
		return nil, err
	}

	data, err := sendHTTPRequest(httpReq, p.httpClient, http.StatusCreated,
		p.requestTokens[vcsGovernanceRequestTokenName])

	if err != nil {
		return nil, err
	}

	if err := p.store.Put(fmt.Sprintf(governanceVCKey, profileID), data); err != nil {
		return nil, err
	}

	return data, nil
}

// GetCredential get governance credential.
func (p *Provider) GetCredential(profileID string) ([]byte, error) {
	return p.store.Get(fmt.Sprintf(governanceVCKey, profileID))
}

func sendHTTPRequest(req *http.Request, client httpClient, status int, bearerToken string) ([]byte, error) {
	if bearerToken != "" {
		req.Header.Add("Authorization", "Bearer "+bearerToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request : %w", err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Warnf("failed to close response body")
		}
	}()

	if resp.StatusCode != status {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Warnf("failed to read response body for status: %d", resp.StatusCode)
		}

		return nil, fmt.Errorf("http request: %d %s", resp.StatusCode, string(body))
	}

	return ioutil.ReadAll(resp.Body)
}
