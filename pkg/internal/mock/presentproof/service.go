/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
)

// MockPresentProofSvc mock present proof service.
type MockPresentProofSvc struct {
	ProtocolName           string
	HandleFunc             func(service.DIDCommMsg) (string, error)
	HandleOutboundFunc     func(msg service.DIDCommMsg, myDID, theirDID string) (string, error)
	AcceptFunc             func(string) bool
	RegisterActionEventErr error
}

// HandleInbound msg.
func (m *MockPresentProofSvc) HandleInbound(msg service.DIDCommMsg, _ service.DIDCommContext) (string, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
	}

	return uuid.New().String(), nil
}

// HandleOutbound msg.
func (m *MockPresentProofSvc) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.HandleOutboundFunc != nil {
		return m.HandleOutboundFunc(msg, myDID, theirDID)
	}

	return uuid.New().String(), nil
}

// Accept msg checks the msg type.
func (m *MockPresentProofSvc) Accept(msgType string) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(msgType)
	}

	return true
}

// Name return service name.
func (m *MockPresentProofSvc) Name() string {
	return presentproof.Name
}

// RegisterActionEvent register action event.
func (m *MockPresentProofSvc) RegisterActionEvent(ch chan<- service.DIDCommAction) error {
	return m.RegisterActionEventErr
}

// UnregisterActionEvent unregister action event.
func (m *MockPresentProofSvc) UnregisterActionEvent(ch chan<- service.DIDCommAction) error {
	return nil
}

// RegisterMsgEvent register message event.
func (m *MockPresentProofSvc) RegisterMsgEvent(ch chan<- service.StateMsg) error {
	return nil
}

// UnregisterMsgEvent unregister message event.
func (m *MockPresentProofSvc) UnregisterMsgEvent(ch chan<- service.StateMsg) error {
	return nil
}

// Actions returns actions.
func (m *MockPresentProofSvc) Actions() ([]presentproof.Action, error) {
	return nil, nil
}

// ActionContinue continues action.
func (m *MockPresentProofSvc) ActionContinue(piID string, opt presentproof.Opt) error {
	return nil
}

// ActionStop stops action.
func (m *MockPresentProofSvc) ActionStop(piID string, err error) error {
	return nil
}
