/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

// MockClient is a mock didexchange.MockClient used in tests.
type MockClient struct {
	ActionEventFunc      func(chan<- service.DIDCommAction) error
	MsgEventFunc         func(chan<- service.StateMsg) error
	CreateInvWithDIDFunc func(string, string) (*didexchange.Invitation, error)
	CreateInvFunc        func(string) (*didexchange.Invitation, error)
}

// RegisterActionEvent registers the action event channel.
func (s *MockClient) RegisterActionEvent(actions chan<- service.DIDCommAction) error {
	if s.ActionEventFunc != nil {
		return s.ActionEventFunc(actions)
	}

	return nil
}

// RegisterMsgEvent registers the message event channel.
func (s *MockClient) RegisterMsgEvent(msgs chan<- service.StateMsg) error {
	if s.MsgEventFunc != nil {
		return s.MsgEventFunc(msgs)
	}

	return nil
}

// CreateInvitationWithDID creates an implicit invitation with the given DID.
func (s *MockClient) CreateInvitationWithDID(label, didID string) (*didexchange.Invitation, error) {
	return s.CreateInvWithDIDFunc(label, didID)
}

// CreateInvitation creates an explicit invitation.
func (s *MockClient) CreateInvitation(label string) (*didexchange.Invitation, error) {
	return s.CreateInvFunc(label)
}
