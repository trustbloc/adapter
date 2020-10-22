/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	mediatorsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"

	mockconn "github.com/trustbloc/edge-adapter/pkg/internal/mock/connection"
	mockdidex "github.com/trustbloc/edge-adapter/pkg/internal/mock/didexchange"
	mockmediator "github.com/trustbloc/edge-adapter/pkg/internal/mock/mediator"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/messenger"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)
		require.NotEmpty(t, c)
	})

	t.Run("store error", func(t *testing.T) {
		config := config()
		config.TransientStore = &mockstorage.Provider{ErrCreateStore: errors.New("create db error")}

		c, err := New(config)
		require.Error(t, err)
		require.Contains(t, err.Error(), "store: create db error")
		require.Empty(t, c)

		config.TransientStore = &mockstorage.Provider{ErrOpenStoreHandle: errors.New("open db error")}

		_, err = New(config)
		require.Error(t, err)
		require.Contains(t, err.Error(), "store: open db error")
	})
}

func TestDIDCommMsgListener(t *testing.T) {
	t.Run("unsupported message type", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		done := make(chan struct{})

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &DIDDocResp{}
				err = msg.Decode(pMsg)
				require.NoError(t, err)

				require.Contains(t, pMsg.Data.ErrorMsg, "unsupported message service type : unsupported-message-type")
				require.Empty(t, pMsg.Data.DIDDoc)

				done <- struct{}{}

				return nil
			},
		}

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(struct {
			Type string `json:"@type,omitempty"`
		}{Type: "unsupported-message-type"})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("messenger reply error", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				return errors.New("reply error")
			},
		}

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(struct {
			Type string `json:"@type,omitempty"`
		}{Type: "unsupported-message-type"})}
	})

	t.Run("did doc request", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		done := make(chan struct{})

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &DIDDocResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)

				didDoc, dErr := did.ParseDocument(pMsg.Data.DIDDoc)
				require.NoError(t, dErr)

				require.Contains(t, didDoc.ID, "did:")
				require.Equal(t, pMsg.Type, didDocResp)

				done <- struct{}{}

				return nil
			},
		}

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
			ID:   uuid.New().String(),
			Type: didDocReq,
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("register route request", func(t *testing.T) {
		config := config()

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}

				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, registerRouteResp)
				require.Empty(t, pMsg.Data)

				done <- struct{}{}

				return nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		didDoc := mockdiddoc.GetMockDIDDoc()
		txnID := uuid.New().String()

		err = c.tStore.Put(txnID, []byte(didDoc.ID))
		require.NoError(t, err)

		didDocBytes, err := didDoc.JSONBytes()
		require.NoError(t, err)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(ConnReq{
			ID:   uuid.New().String(),
			Type: registerRouteReq,
			Thread: &decorator.Thread{
				PID: txnID,
			},
			Data: &ConnReqData{
				DIDDoc: didDocBytes,
			},
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})
}

func TestDIDDocReq(t *testing.T) {
	t.Run("create did doc error", func(t *testing.T) {
		config := config()

		done := make(chan struct{})
		config.VDRIRegistry = &mockvdr.MockVDRegistry{CreateErr: errors.New("create did error")}
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, didDocResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "create new peer did")

				done <- struct{}{}

				return nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
			ID:   uuid.New().String(),
			Type: didDocReq,
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("store error", func(t *testing.T) {
		config := config()

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, didDocResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "save txn data")

				done <- struct{}{}

				return nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		c.tStore = &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: errors.New("save error")}

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
			ID:   uuid.New().String(),
			Type: didDocReq,
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})
}

func TestRegisterRouteReq(t *testing.T) { // nolint:gocyclo
	t.Run("missing parent thread id", func(t *testing.T) {
		c, err := New(config())
		require.NoError(t, err)

		done := make(chan struct{})
		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, registerRouteResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "parent thread id mandatory")

				done <- struct{}{}

				return nil
			},
		}

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(ConnReq{
			ID:   uuid.New().String(),
			Type: registerRouteReq,
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("empty did doc in the request", func(t *testing.T) {
		config := config()

		c, err := New(config)
		require.NoError(t, err)

		done := make(chan struct{})
		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, registerRouteResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "did document mandatory")

				done <- struct{}{}

				return nil
			},
		}

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(ConnReq{
			ID:   uuid.New().String(),
			Type: registerRouteReq,
			Thread: &decorator.Thread{
				PID: uuid.New().String(),
			},
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("invalid did doc in the request", func(t *testing.T) {
		config := config()

		done := make(chan struct{})
		config.VDRIRegistry = &mockvdr.MockVDRegistry{CreateErr: errors.New("create did error")}

		c, err := New(config)
		require.NoError(t, err)

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, registerRouteResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "parse did doc")

				done <- struct{}{}

				return nil
			},
		}

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(ConnReq{
			ID:   uuid.New().String(),
			Type: registerRouteReq,
			Thread: &decorator.Thread{
				PID: uuid.New().String(),
			},
			Data: &ConnReqData{
				DIDDoc: []byte("invalid-did-doc"),
			},
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("store error", func(t *testing.T) {
		config := config()

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, registerRouteResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "fetch txn data")

				done <- struct{}{}

				return nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		didDoc := mockdiddoc.GetMockDIDDoc()
		didDocBytes, err := didDoc.JSONBytes()
		require.NoError(t, err)

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(ConnReq{
			ID:   uuid.New().String(),
			Type: registerRouteReq,
			Thread: &decorator.Thread{
				PID: uuid.New().String(),
			},
			Data: &ConnReqData{
				DIDDoc: didDocBytes,
			},
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("create connection error", func(t *testing.T) {
		config := config()
		config.DIDExchangeClient = &mockdidex.MockClient{
			CreateConnectionFunc: func(s string, doc *did.Doc, option ...didexchange.ConnectionOption) (string, error) {
				return "", errors.New("create conn error")
			},
		}

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, registerRouteResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "create connection")

				done <- struct{}{}

				return nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		didDoc := mockdiddoc.GetMockDIDDoc()
		txnID := uuid.New().String()

		err = c.tStore.Put(txnID, []byte(didDoc.ID))
		require.NoError(t, err)

		didDocBytes, err := didDoc.JSONBytes()
		require.NoError(t, err)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(ConnReq{
			ID:   uuid.New().String(),
			Type: registerRouteReq,
			Thread: &decorator.Thread{
				PID: txnID,
			},
			Data: &ConnReqData{
				DIDDoc: didDocBytes,
			},
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("register route error", func(t *testing.T) {
		config := config()
		config.MediatorClient = &mockmediator.MockClient{
			RegisterErr: errors.New("register route error"),
		}

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, registerRouteResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "route registration")

				done <- struct{}{}

				return nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		didDoc := mockdiddoc.GetMockDIDDoc()
		txnID := uuid.New().String()

		err = c.tStore.Put(txnID, []byte(didDoc.ID))
		require.NoError(t, err)

		didDocBytes, err := didDoc.JSONBytes()
		require.NoError(t, err)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(ConnReq{
			ID:   uuid.New().String(),
			Type: registerRouteReq,
			Thread: &decorator.Thread{
				PID: txnID,
			},
			Data: &ConnReqData{
				DIDDoc: didDocBytes,
			},
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("connection id look up error", func(t *testing.T) {
		config := config()
		config.ConnectionLookup = &mockconn.MockConnectionsLookup{ConnIDByDIDsErr: errors.New("lookup error")}

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, registerRouteResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "get connection by dids")

				done <- struct{}{}

				return nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		msgCh := make(chan routeMsg, 1)
		go c.didCommMsgListener(msgCh)

		didDoc := mockdiddoc.GetMockDIDDoc()
		txnID := uuid.New().String()

		err = c.tStore.Put(txnID, []byte(didDoc.ID))
		require.NoError(t, err)

		didDocBytes, err := didDoc.JSONBytes()
		require.NoError(t, err)

		msgCh <- routeMsg{didCommMsg: service.NewDIDCommMsgMap(ConnReq{
			ID:   uuid.New().String(),
			Type: registerRouteReq,
			Thread: &decorator.Thread{
				PID: txnID,
			},
			Data: &ConnReqData{
				DIDDoc: didDocBytes,
			},
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})
}

func TestGetDIDService(t *testing.T) {
	t.Run("success (registered route)", func(t *testing.T) {
		config := config()

		routerEndpoint := "http://router.com"
		keys := []string{"abc", "xyz"}

		mediatorConfig := mediatorsvc.NewConfig(routerEndpoint, keys)
		config.MediatorClient = &mockmediator.MockClient{
			GetConfigFunc: func(connID string) (*mediatorsvc.Config, error) {
				return mediatorConfig, nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		connID := uuid.New().String()
		err = c.tStore.Put(connID, []byte(uuid.New().String()))
		require.NoError(t, err)

		didSvc, err := c.GetDIDService(connID)
		require.NoError(t, err)
		require.Equal(t, routerEndpoint, didSvc.ServiceEndpoint)
		require.Equal(t, keys, didSvc.RoutingKeys)
	})

	t.Run("success (default)", func(t *testing.T) {
		config := config()

		mediatorConfig := &mediatorsvc.Config{}
		config.MediatorClient = &mockmediator.MockClient{
			GetConfigFunc: func(connID string) (*mediatorsvc.Config, error) {
				return mediatorConfig, nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		didSvc, err := c.GetDIDService("")
		require.NoError(t, err)
		require.Equal(t, config.ServiceEndpoint, didSvc.ServiceEndpoint)
	})

	t.Run("get config error (registered route)", func(t *testing.T) {
		config := config()
		config.MediatorClient = &mockmediator.MockClient{
			GetConfigFunc: func(connID string) (*mediatorsvc.Config, error) {
				return nil, errors.New("mediator config error")
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		connID := uuid.New().String()
		err = c.tStore.Put(connID, []byte(uuid.New().String()))
		require.NoError(t, err)

		_, err = c.GetDIDService(connID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get mediator config")
	})

	t.Run("store error", func(t *testing.T) {
		config := config()

		c, err := New(config)
		require.NoError(t, err)

		c.tStore = &mockstorage.MockStore{Store: make(map[string][]byte), ErrGet: errors.New("get error")}

		connID := uuid.New().String()
		err = c.tStore.Put(connID, []byte(uuid.New().String()))
		require.NoError(t, err)

		_, err = c.GetDIDService(connID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get conn id to router conn id mapping")
	})
}
