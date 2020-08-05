/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
)

// MockService is a mock outofband service.
type MockService struct {
	SaveInvitationErr error
}

// RegisterActionEvent mock.
func (m *MockService) RegisterActionEvent(ch chan<- service.DIDCommAction) error {
	panic("implement me")
}

// UnregisterActionEvent mock.
func (m *MockService) UnregisterActionEvent(ch chan<- service.DIDCommAction) error {
	panic("implement me")
}

// RegisterMsgEvent mock.
func (m *MockService) RegisterMsgEvent(ch chan<- service.StateMsg) error {
	panic("implement me")
}

// UnregisterMsgEvent mock.
func (m *MockService) UnregisterMsgEvent(ch chan<- service.StateMsg) error {
	panic("implement me")
}

// AcceptRequest mock.
func (m *MockService) AcceptRequest(request *outofband.Request, s string) (string, error) {
	panic("implement me")
}

// AcceptInvitation mock.
func (m *MockService) AcceptInvitation(invitation *outofband.Invitation, s string) (string, error) {
	panic("implement me")
}

// SaveRequest mock.
func (m *MockService) SaveRequest(request *outofband.Request) error {
	panic("implement me")
}

// SaveInvitation mock.
func (m *MockService) SaveInvitation(invitation *outofband.Invitation) error {
	return m.SaveInvitationErr
}

// Actions mock.
func (m *MockService) Actions() ([]outofband.Action, error) {
	panic("implement me")
}

// ActionContinue mock.
func (m *MockService) ActionContinue(s string, options outofband.Options) error {
	panic("implement me")
}

// ActionStop mock.
func (m *MockService) ActionStop(s string, err error) error {
	panic("implement me")
}
