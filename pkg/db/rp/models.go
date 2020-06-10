/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rp

import "github.com/trustbloc/edge-adapter/pkg/presentationex"

// Tenant describes the Relying Party.
type Tenant struct {
	ClientID  string
	PublicDID string
	Label     string
}

// UserConnection describes a connection a relying party has with a user.
type UserConnection struct {
	User    *User
	RP      *Tenant
	Request *DataRequest
}

// User is an end user.
type User struct {
	Subject string
	DID     string
}

// DataRequest is a request for data by the relying party with the user as subject.
type DataRequest struct {
	Scope []string
	PD    *presentationex.PresentationDefinitions
}
