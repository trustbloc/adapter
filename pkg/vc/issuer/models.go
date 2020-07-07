/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

// ManifestCredential issuer manifest vc.
type ManifestCredential struct {
	Subject *ManifestCredentialSubject `json:"credentialSubject"`
}

// ManifestCredentialSubject struct for sending the issuer supported contexts.
type ManifestCredentialSubject struct {
	ID       string   `json:"id"`
	Contexts []string `json:"contexts"`
}

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
