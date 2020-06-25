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
)

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

// ValidHTTPURL checks if the string is a valid http url.
func ValidHTTPURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
