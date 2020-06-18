/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package adapterutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// DecodeIntoCustomCredential converts credential into custom credentials.
func DecodeIntoCustomCredential(credential *verifiable.Credential, custom interface{}) error {
	vcBytes, err := credential.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal credential as json : %w", err)
	}

	err = json.NewDecoder(bytes.NewReader(vcBytes)).Decode(custom)
	if err != nil {
		return fmt.Errorf("failed to decode custom credential : %w", err)
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

// ValidHTTPURL checks if the string is a valid http url.
func ValidHTTPURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
