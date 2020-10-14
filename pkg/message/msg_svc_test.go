/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package message

import (
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/stretchr/testify/require"
)

func TestNewMsgSvc(t *testing.T) {
	name := "msg-123"
	msgType := "http://example.com/message/test"
	purpose := "msg-123"
	msgCh := make(chan service.DIDCommMsg)

	msgSvc := newMsgSvc(name, msgType, msgCh)
	require.Equal(t, name, msgSvc.Name())

	require.True(t, msgSvc.Accept(msgType, []string{purpose, "purpose2"}))
	require.False(t, msgSvc.Accept(purpose, []string{purpose}))
	require.False(t, msgSvc.Accept("", nil))

	done := make(chan struct{})

	go func() {
		<-msgCh
		done <- struct{}{}
	}()

	msg := service.NewDIDCommMsgMap(struct {
		Type string `json:"@type,omitempty"`
	}{Type: msgType})

	_, err := msgSvc.HandleInbound(msg, "", "")
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated due to timeout")
	}
}
