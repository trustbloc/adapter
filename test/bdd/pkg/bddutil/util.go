/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddutil

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	log "github.com/sirupsen/logrus"
)

// HTTPDo util to send http requests.
func HTTPDo(method, url, contentType, token string, body io.Reader, tlsConfig *tls.Config) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if contentType != "" {
		req.Header.Add("Content-Type", contentType)
	}

	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	return httpClient.Do(req)
}

// ExpectedStatusCodeError formats the status code error message.
func ExpectedStatusCodeError(expected, actual int, respBytes []byte) error {
	return fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
		expected, actual, respBytes)
}

// CloseResponseBody closes the response body.
func CloseResponseBody(respBody io.Closer) {
	err := respBody.Close()
	if err != nil {
		log.Errorf("Failed to close response body: %s", err.Error())
	}
}

// ResolveDID waits for the DID to become available for resolution.
func ResolveDID(vdriRegistry vdriapi.Registry, did string, maxRetry int) (*docdid.Doc, error) {
	var didDoc *docdid.Doc

	for i := 1; i <= maxRetry; i++ {
		var err error
		didDoc, err = vdriRegistry.Resolve(did)

		if err != nil {
			if !strings.Contains(err.Error(), "DID does not exist") {
				return nil, err
			}

			fmt.Printf("did %s not found will retry %d of %d\n", did, i, maxRetry)
			time.Sleep(3 * time.Second) // nolint:gomnd

			continue
		}
	}

	return didDoc, nil
}

// GetDIDConnectRequestKey key for storing DID Connect request.
func GetDIDConnectRequestKey(issuerID, agentID string) string {
	return issuerID + agentID + "-didconnect-request"
}

// GetDIDConnectResponseKey key for storing DID Connect response.
func GetDIDConnectResponseKey(issuerID, agentID string) string {
	return issuerID + agentID + "-didconnect-response"
}

// JSONMarshaller can marshal itself to JSON bytes.
type JSONMarshaller interface {
	MarshalJSON() ([]byte, error)
}

// DecodeJSONMarshaller decodes the JSONMarshaller into the given object.
func DecodeJSONMarshaller(jm JSONMarshaller, custom interface{}) error {
	bits, err := jm.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to execute MarshalJSON() : %w", err)
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(custom)
	if err != nil {
		return fmt.Errorf("failed to decode custom jsonmarshaller : %w", err)
	}

	return nil
}

// StringsContains check if the string is present in the string array.
func StringsContains(val string, slice []string) bool {
	for _, s := range slice {
		if val == s {
			return true
		}
	}

	return false
}
