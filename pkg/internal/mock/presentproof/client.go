/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

// MockClient is a mock presentproof.MockClient used in tests.
type MockClient struct {
	RegisterActionFunc      func(chan<- service.DIDCommAction) error
	RequestPresentationFunc func(*presentproof.RequestPresentation, *connection.Record) (string, error)
}

// RegisterActionEvent registers the action event channel.
func (s *MockClient) RegisterActionEvent(ch chan<- service.DIDCommAction) error {
	if s.RegisterActionFunc != nil {
		return s.RegisterActionFunc(ch)
	}

	return nil
}

// UnregisterActionEvent unregisters the action channnel.
func (s *MockClient) UnregisterActionEvent(ch chan<- service.DIDCommAction) error {
	panic("implement me")
}

// RegisterMsgEvent registers the message event channel.
func (s *MockClient) RegisterMsgEvent(ch chan<- service.StateMsg) error {
	panic("implement me")
}

// UnregisterMsgEvent unregisters the msg event channel.
func (s *MockClient) UnregisterMsgEvent(ch chan<- service.StateMsg) error {
	panic("implement me")
}

// SendRequestPresentation simulates the action of sending a request presentation to theirDID.
func (s *MockClient) SendRequestPresentation(
	presentation *presentproof.RequestPresentation, connRec *connection.Record) (string, error) {
	if s.RequestPresentationFunc != nil {
		return s.RequestPresentationFunc(presentation, connRec)
	}

	return "", nil
}
