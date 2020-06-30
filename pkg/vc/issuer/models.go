/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import "encoding/json"

// DIDConnectCredential is a VC that contains the DID Connection response data.
type DIDConnectCredential struct {
	Subject *DIDConnectCredentialSubject `json:"credentialSubject"`
}

// DIDConnectCredentialSubject is the custom credentialSubject of a DIDConnectCredential.
type DIDConnectCredentialSubject struct {
	ID              string `json:"id"`
	InviteeDID      string `json:"inviteeDID"`
	InviterDID      string `json:"inviterDID"`
	InviterLabel    string `json:"inviterLabel"`
	ThreadID        string `json:"threadID"`
	ConnectionState string `json:"connectionState"`
}

// DIDCommInitCredential is a VC that contains the DIDDoc.
type DIDCommInitCredential struct {
	Subject *DIDCommInitCredentialSubject `json:"credentialSubject"`
}

// DIDCommInitCredentialSubject struct for sending the issuer DIDDoc to wallet.
type DIDCommInitCredentialSubject struct {
	ID     string          `json:"id"`
	DIDDoc json.RawMessage `json:"didDoc"`
}
