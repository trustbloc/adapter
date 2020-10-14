/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package message

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"

// msgService msg service implementation.
type msgService struct {
	svcName string
	msgType string
	msgCh   chan service.DIDCommMsg
}

// newMsgSvc new msg service.
func newMsgSvc(name, msgType string, msgCh chan service.DIDCommMsg) *msgService {
	return &msgService{
		svcName: name,
		msgType: msgType,
		msgCh:   msgCh,
	}
}

// Name svc name.
func (m *msgService) Name() string {
	return m.svcName
}

// Accept validates whether the service handles msgType and purpose.
func (m *msgService) Accept(msgType string, _ []string) bool {
	return m.msgType == msgType
}

// HandleInbound handles inbound didcomm msg.
func (m *msgService) HandleInbound(msg service.DIDCommMsg, _, _ string) (string, error) {
	go func() {
		m.msgCh <- msg
	}()

	return "", nil
}
