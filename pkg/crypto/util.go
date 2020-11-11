/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

const (
	creatorParts = 2

	invalidFormatErrMsgFmt = "verificationMethod value %s should be in did#keyID format"
)

// GetKeyIDFromVerificationMethod fetches keyid from the verification method.
func GetKeyIDFromVerificationMethod(creator string) (string, error) {
	idSplit := strings.Split(creator, "#")
	if len(idSplit) != creatorParts {
		return "", fmt.Errorf(fmt.Sprintf(invalidFormatErrMsgFmt, creator))
	}

	return idSplit[1], nil
}

// GetDIDFromVerificationMethod fetches did from the verification method.
func GetDIDFromVerificationMethod(method string) (string, error) {
	idSplit := strings.Split(method, "#")
	if len(idSplit) != creatorParts {
		return "", fmt.Errorf(invalidFormatErrMsgFmt, method)
	}

	id, err := did.Parse(idSplit[0])
	if err != nil {
		return "", fmt.Errorf("failed to parse DID URI [%s]: %w", idSplit[0], err)
	}

	return id.String(), nil
}

// GetVerificationMethodFromDID returns the first verification method found with the given relationship.
func GetVerificationMethodFromDID(d *did.Doc, rel did.VerificationRelationship) (string, error) {
	methods := d.VerificationMethods(rel)

	if len(methods) == 0 || len(methods[rel]) == 0 {
		return "", fmt.Errorf("did %s does not declare the requested verification method", d.ID)
	}

	method := methods[rel][0].VerificationMethod.ID

	if method == "" {
		return "", fmt.Errorf("did %s has a public key with no id for verification method %d", d.ID, rel)
	}

	// TODO remove this workaround when we are working with did docs that have correct verification method IDs:
	//  - aries framework: https://github.com/hyperledger/aries-framework-go/issues/2145
	//  - trustbloc did method: https://github.com/trustbloc/trustbloc-did-method/issues/169
	if strings.HasPrefix(method, "#") {
		method = fmt.Sprintf("%s%s", d.ID, method)
	}

	return method, nil
}
