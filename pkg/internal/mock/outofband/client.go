/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import "github.com/hyperledger/aries-framework-go/pkg/client/outofband"

// MockClient is a mock out-of-band client used in tests.
type MockClient struct {
	CreateInvVal *outofband.Invitation
	CreateInvErr error
}

// CreateInvitation creates a mock outofband invitation.
func (m *MockClient) CreateInvitation([]interface{}, ...outofband.MessageOption) (*outofband.Invitation, error) {
	return m.CreateInvVal, m.CreateInvErr
}
