/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

// MockClient is a mock didexchange.MockClient used in tests.
type MockClient struct {
	ActionEventFunc      func(chan<- service.DIDCommAction) error
	MsgEventFunc         func(chan<- service.StateMsg) error
	CreateInvWithDIDFunc func(string, string) (*didexchange.Invitation, error)
	CreateInvFunc        func(string) (*didexchange.Invitation, error)
	GetConnectionErr     error
	CreateConnectionFunc func(string, *did.Doc, ...didexchange.ConnectionOption) (string, error)
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

// CreateConnection creates a didcomm connection between myDID and theirDID.
func (s *MockClient) CreateConnection(
	myDID string, theirDID *did.Doc, options ...didexchange.ConnectionOption) (string, error) {
	if s.CreateConnectionFunc != nil {
		return s.CreateConnectionFunc(myDID, theirDID, options...)
	}

	return "", nil
}

// GetConnection fetches connection record based on connID.
func (s *MockClient) GetConnection(connectionID string) (*didexchange.Connection, error) {
	if s.GetConnectionErr != nil {
		return nil, s.GetConnectionErr
	}

	return &didexchange.Connection{Record: &connection.Record{ConnectionID: connectionID}}, nil
}
