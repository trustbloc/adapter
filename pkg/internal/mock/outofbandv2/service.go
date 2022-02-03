/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
)

// MockService is a mock outofband service.
type MockService struct {
	SaveInvitationErr error
}

// AcceptInvitation mock.
func (m *MockService) AcceptInvitation(*outofbandv2.Invitation, ...outofbandv2.AcceptOption) (string, error) {
	panic("implement me")
}

// SaveInvitation mock.
func (m *MockService) SaveInvitation(*outofbandv2.Invitation) error {
	return m.SaveInvitationErr
}
