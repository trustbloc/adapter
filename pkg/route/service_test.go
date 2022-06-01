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
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	mediatorsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-adapter/pkg/aries/message"
	mockconn "github.com/trustbloc/edge-adapter/pkg/internal/mock/connection"
	mockdidex "github.com/trustbloc/edge-adapter/pkg/internal/mock/didexchange"
	mockmediator "github.com/trustbloc/edge-adapter/pkg/internal/mock/mediator"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/messenger"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		c, err := New(config())
		require.NoError(t, err)
		require.NotEmpty(t, c)
	})

	t.Run("store error", func(t *testing.T) {
		t.Parallel()

		config := config()

		config.Store = &mockstorage.Provider{ErrOpenStore: errors.New("open db error")}

		_, err := New(config)
		require.Error(t, err)
		require.Contains(t, err.Error(), "store: open db error")
	})
}

func TestDIDCommMsgListener(t *testing.T) {
	t.Parallel()

	t.Run("unsupported message type", func(t *testing.T) {
		t.Parallel()

		c, err := New(config())
		require.NoError(t, err)

		done := make(chan struct{})

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
				pMsg := &DIDDocResp{}
				err = msg.Decode(pMsg)
				require.NoError(t, err)

				require.Contains(t, pMsg.Data.ErrorMsg, "unsupported message service type : unsupported-message-type")
				require.Empty(t, pMsg.Data.DIDDoc)

				done <- struct{}{}

				return nil
			},
		}

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(struct {
			Type string `json:"@type,omitempty"`
		}{Type: "unsupported-message-type"})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("messenger reply error", func(t *testing.T) {
		t.Parallel()

		c, err := New(config())
		require.NoError(t, err)

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
				return errors.New("reply error")
			},
		}

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(struct {
			Type string `json:"@type,omitempty"`
		}{Type: "unsupported-message-type"})}
	})

	t.Run("did doc request", func(t *testing.T) {
		t.Parallel()

		c, err := New(config())
		require.NoError(t, err)

		done := make(chan struct{})

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
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

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
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
		t.Parallel()

		config := config()

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
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

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		txnID := uuid.New().String()

		err = c.store.Put(txnID, []byte(didDoc.ID))
		require.NoError(t, err)

		didDocBytes, err := didDoc.JSONBytes()
		require.NoError(t, err)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(ConnReq{
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
	t.Parallel()

	t.Run("create did doc vm error", func(t *testing.T) {
		t.Parallel()

		config := config()

		expectErr := "expected err"

		config.KeyManager = &mockkms.KeyManager{CrAndExportPubKeyErr: errors.New(expectErr)}

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, didDocResp)
				require.Contains(t, pMsg.Data.ErrorMsg, expectErr)

				done <- struct{}{}

				return nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
			ID:   uuid.New().String(),
			Type: didDocReq,
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("create did doc keyagreement vm error", func(t *testing.T) {
		t.Parallel()

		config := config()

		config.KeyAgrType = "foo"

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, didDocResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "failed to create new keyagreement VM")

				done <- struct{}{}

				return nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
			ID:   uuid.New().String(),
			Type: didDocReq,
		})}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})

	t.Run("create did doc error", func(t *testing.T) {
		t.Parallel()

		config := config()

		done := make(chan struct{})
		config.VDRIRegistry = &mockvdr.MockVDRegistry{CreateErr: errors.New("create did error")}
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, didDocResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "create did error")

				done <- struct{}{}

				return nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
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
		t.Parallel()

		config := config()

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
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

		c.store = &mockstorage.Store{ErrPut: errors.New("save error")}

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(DIDDocReq{
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

func TestRegisterRouteReq(t *testing.T) { // nolint:gocyclo,cyclop
	t.Parallel()

	t.Run("missing parent thread id", func(t *testing.T) {
		t.Parallel()

		c, err := New(config())
		require.NoError(t, err)

		done := make(chan struct{})
		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, registerRouteResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "parent thread id mandatory")

				done <- struct{}{}

				return nil
			},
		}

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(ConnReq{
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
		t.Parallel()

		config := config()

		c, err := New(config)
		require.NoError(t, err)

		done := make(chan struct{})
		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, registerRouteResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "did document mandatory")

				done <- struct{}{}

				return nil
			},
		}

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(ConnReq{
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
		t.Parallel()

		config := config()

		done := make(chan struct{})
		config.VDRIRegistry = &mockvdr.MockVDRegistry{CreateErr: errors.New("create did error")}

		c, err := New(config)
		require.NoError(t, err)

		c.messenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
				pMsg := &ErrorResp{}
				dErr := msg.Decode(pMsg)
				require.NoError(t, dErr)
				require.Equal(t, pMsg.Type, registerRouteResp)
				require.Contains(t, pMsg.Data.ErrorMsg, "parse did doc")

				done <- struct{}{}

				return nil
			},
		}

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(ConnReq{
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
		t.Parallel()

		config := config()

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
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

		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		didDocBytes, err := didDoc.JSONBytes()
		require.NoError(t, err)

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(ConnReq{
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
		t.Parallel()

		config := config()
		config.DIDExchangeClient = &mockdidex.MockClient{
			CreateConnectionFunc: func(s string, doc *did.Doc, option ...didexchange.ConnectionOption) (string, error) {
				return "", errors.New("create conn error")
			},
		}

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
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

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		txnID := uuid.New().String()

		err = c.store.Put(txnID, []byte(didDoc.ID))
		require.NoError(t, err)

		didDocBytes, err := didDoc.JSONBytes()
		require.NoError(t, err)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(ConnReq{
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
		t.Parallel()

		config := config()
		config.MediatorClient = &mockmediator.MockClient{
			RegisterErr: errors.New("register route error"),
		}

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
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

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		txnID := uuid.New().String()

		err = c.store.Put(txnID, []byte(didDoc.ID))
		require.NoError(t, err)

		didDocBytes, err := didDoc.JSONBytes()
		require.NoError(t, err)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(ConnReq{
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
		t.Parallel()

		config := config()
		config.ConnectionLookup = &mockconn.MockConnectionsLookup{ConnIDByDIDsErr: errors.New("lookup error")}

		done := make(chan struct{})
		config.AriesMessenger = &messenger.MockMessenger{
			ReplyToFunc: func(msgID string, msg service.DIDCommMsgMap, _ ...service.Opt) error {
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

		msgCh := make(chan message.Msg, 1)
		go c.didCommMsgListener(msgCh)

		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		txnID := uuid.New().String()

		err = c.store.Put(txnID, []byte(didDoc.ID))
		require.NoError(t, err)

		didDocBytes, err := didDoc.JSONBytes()
		require.NoError(t, err)

		msgCh <- message.Msg{DIDCommMsg: service.NewDIDCommMsgMap(ConnReq{
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
	t.Parallel()

	t.Run("success (registered route)", func(t *testing.T) {
		t.Parallel()

		config := config()

		routerEndpoint := "http://router.com"
		keys := []string{"abc", "xyz"}
		config.VDRIRegistry = &mockvdr.MockVDRegistry{CreateValue: &did.Doc{
			Service: []did.Service{
				{
					ID:              uuid.New().String(),
					Type:            didCommServiceType,
					ServiceEndpoint: model.NewDIDCommV1Endpoint(routerEndpoint),
					RoutingKeys:     keys,
					RecipientKeys:   []string{"1ert5", "x5356s"},
				},
			},
		}}

		mediatorConfig := mediatorsvc.NewConfig(routerEndpoint, keys)
		config.MediatorClient = &mockmediator.MockClient{
			GetConfigFunc: func(connID string) (*mediatorsvc.Config, error) {
				return mediatorConfig, nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		connID := uuid.New().String()
		err = c.store.Put(connID, []byte(uuid.New().String()))
		require.NoError(t, err)

		doc, err := c.GetDIDDoc(connID, false, true)
		require.NoError(t, err)
		uri, err := doc.Service[0].ServiceEndpoint.URI()
		require.NoError(t, err)
		require.Equal(t, routerEndpoint, uri)
		require.Equal(t, keys, doc.Service[0].RoutingKeys)
	})

	t.Run("success (default)", func(t *testing.T) {
		t.Parallel()

		config := config()
		config.VDRIRegistry = &mockvdr.MockVDRegistry{CreateValue: &did.Doc{
			Service: []did.Service{
				{
					ID:              uuid.New().String(),
					Type:            didCommServiceType,
					ServiceEndpoint: model.NewDIDCommV1Endpoint(config.ServiceEndpoint),
				},
			},
		}}

		mediatorConfig := &mediatorsvc.Config{}
		config.MediatorClient = &mockmediator.MockClient{
			GetConfigFunc: func(connID string) (*mediatorsvc.Config, error) {
				return mediatorConfig, nil
			},
		}

		config.Store = &mockstorage.Provider{OpenStoreReturn: &mockstorage.Store{ErrGet: storage.ErrDataNotFound}}

		c, err := New(config)
		require.NoError(t, err)

		doc, err := c.GetDIDDoc("", false, false)
		require.NoError(t, err)
		uri, err := doc.Service[0].ServiceEndpoint.URI()
		require.NoError(t, err)
		require.Equal(t, config.ServiceEndpoint, uri)
	})

	t.Run("create verification method error", func(t *testing.T) {
		t.Parallel()

		expectErr := errors.New("expected error")

		config := config()
		config.KeyManager = &mockkms.KeyManager{CrAndExportPubKeyErr: expectErr}

		c, err := New(config)
		require.NoError(t, err)

		connID := uuid.New().String()
		err = c.store.Put(connID, []byte(uuid.New().String()))
		require.NoError(t, err)

		_, err = c.GetDIDDoc(connID, false, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new verification method")
		require.ErrorIs(t, err, expectErr)
	})

	t.Run("create keyagreement error", func(t *testing.T) {
		t.Parallel()

		config := config()
		config.KeyAgrType = "#foo"

		c, err := New(config)
		require.NoError(t, err)

		connID := uuid.New().String()
		err = c.store.Put(connID, []byte(uuid.New().String()))
		require.NoError(t, err)

		_, err = c.GetDIDDoc(connID, false, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new keyagreement VM")
	})

	t.Run("error when not registered and blinded routing is required", func(t *testing.T) {
		t.Parallel()

		config := config()

		mediatorConfig := &mediatorsvc.Config{}
		config.MediatorClient = &mockmediator.MockClient{
			GetConfigFunc: func(connID string) (*mediatorsvc.Config, error) {
				return mediatorConfig, nil
			},
		}

		config.Store = &mockstorage.Provider{OpenStoreReturn: &mockstorage.Store{ErrGet: storage.ErrDataNotFound}}

		c, err := New(config)
		require.NoError(t, err)

		_, err = c.GetDIDDoc("", true, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no router registered to support blinded routing")
	})

	t.Run("get config error (registered route)", func(t *testing.T) {
		t.Parallel()

		config := config()
		config.MediatorClient = &mockmediator.MockClient{
			GetConfigFunc: func(connID string) (*mediatorsvc.Config, error) {
				return nil, errors.New("mediator config error")
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		connID := uuid.New().String()
		err = c.store.Put(connID, []byte(uuid.New().String()))
		require.NoError(t, err)

		_, err = c.GetDIDDoc(connID, false, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get mediator config")
	})

	t.Run("store error", func(t *testing.T) {
		t.Parallel()

		config := config()

		c, err := New(config)
		require.NoError(t, err)

		c.store = &mockstorage.Store{ErrGet: errors.New("get error")}

		connID := uuid.New().String()
		err = c.store.Put(connID, []byte(uuid.New().String()))
		require.NoError(t, err)

		_, err = c.GetDIDDoc(connID, false, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get conn id to router conn id mapping")
	})

	t.Run("missing did-comm service type", func(t *testing.T) {
		t.Parallel()

		config := config()

		config.VDRIRegistry = &mockvdr.MockVDRegistry{CreateValue: &did.Doc{
			Service: []did.Service{
				{
					ID:   uuid.New().String(),
					Type: "randomService",
				},
			},
		}}

		config.MediatorClient = &mockmediator.MockClient{
			GetConfigFunc: func(connID string) (*mediatorsvc.Config, error) {
				return &mediatorsvc.Config{}, nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		connID := uuid.New().String()
		err = c.store.Put(connID, []byte(uuid.New().String()))
		require.NoError(t, err)

		_, err = c.GetDIDDoc(connID, false, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "did document missing did-communication service type")
	})

	t.Run("did create error", func(t *testing.T) {
		t.Parallel()

		config := config()

		config.VDRIRegistry = &mockvdr.MockVDRegistry{CreateErr: errors.New("create error")}

		config.MediatorClient = &mockmediator.MockClient{
			GetConfigFunc: func(connID string) (*mediatorsvc.Config, error) {
				return &mediatorsvc.Config{}, nil
			},
		}

		c, err := New(config)
		require.NoError(t, err)

		connID := uuid.New().String()
		err = c.store.Put(connID, []byte(uuid.New().String()))
		require.NoError(t, err)

		_, err = c.GetDIDDoc(connID, false, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create error")
	})

	t.Run("add key to router error", func(t *testing.T) {
		t.Parallel()

		config := config()

		config.VDRIRegistry = &mockvdr.MockVDRegistry{CreateValue: getDIDDoc()}

		config.MediatorClient = &mockmediator.MockClient{
			GetConfigFunc: func(connID string) (*mediatorsvc.Config, error) {
				return &mediatorsvc.Config{}, nil
			},
		}

		config.MediatorSvc = &mockroute.MockMediatorSvc{AddKeyErr: errors.New("add key error")}

		c, err := New(config)
		require.NoError(t, err)

		connID := uuid.New().String()
		err = c.store.Put(connID, []byte(uuid.New().String()))
		require.NoError(t, err)

		_, err = c.GetDIDDoc(connID, false, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "register did doc recipient key")
	})

	t.Run("add keyagreement key to router error", func(t *testing.T) {
		t.Parallel()

		config := config()

		didDoc := &did.Doc{
			Service: []did.Service{
				{
					ID:   uuid.New().String(),
					Type: didCommServiceType,
				},
			},
			KeyAgreement: []did.Verification{
				{
					VerificationMethod: did.VerificationMethod{
						ID: "foo",
					},
				},
			},
		}

		config.VDRIRegistry = &mockvdr.MockVDRegistry{CreateValue: didDoc}

		config.MediatorClient = &mockmediator.MockClient{
			GetConfigFunc: func(connID string) (*mediatorsvc.Config, error) {
				return &mediatorsvc.Config{}, nil
			},
		}

		expectErr := errors.New("add key error")

		config.MediatorSvc = &mockroute.MockMediatorSvc{AddKeyErr: expectErr}

		c, err := New(config)
		require.NoError(t, err)

		connID := uuid.New().String()
		err = c.store.Put(connID, []byte(uuid.New().String()))
		require.NoError(t, err)

		_, err = c.GetDIDDoc(connID, false, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "register did doc keyAgreement key")
		require.ErrorIs(t, err, expectErr)
	})
}

func TestService_newVerificationMethod(t *testing.T) {
	t.Parallel()

	t.Run("success: ed25519", func(t *testing.T) {
		t.Parallel()

		config := config()

		config.KeyManager = realKMS(t)

		c, err := New(config)
		require.NoError(t, err)

		vm, err := c.newVerificationMethod(kms.ED25519Type)
		require.NoError(t, err)
		require.Equal(t, ed25519VerificationKey2018, vm.Type)
	})

	t.Run("success: x25519", func(t *testing.T) {
		t.Parallel()

		config := config()

		config.KeyManager = realKMS(t)

		c, err := New(config)
		require.NoError(t, err)

		vm, err := c.newVerificationMethod(kms.X25519ECDHKWType)
		require.NoError(t, err)
		require.Equal(t, x25519KeyAgreementKey2019, vm.Type)
	})

	t.Run("success: jwk", func(t *testing.T) {
		t.Parallel()

		config := config()

		config.KeyManager = realKMS(t)

		c, err := New(config)
		require.NoError(t, err)

		vm, err := c.newVerificationMethod(kms.NISTP256ECDHKWType)
		require.NoError(t, err)
		require.Equal(t, jsonWebKey2020, vm.Type)
	})

	t.Run("fail: create key", func(t *testing.T) {
		t.Parallel()

		config := config()

		expectErr := errors.New("expected err")

		config.KeyManager = &mockkms.KeyManager{CrAndExportPubKeyErr: expectErr}

		c, err := New(config)
		require.NoError(t, err)

		_, err = c.newVerificationMethod(kms.ED25519Type)
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating public key")
		require.ErrorIs(t, err, expectErr)
	})

	t.Run("fail: invalid x25519 key", func(t *testing.T) {
		t.Parallel()

		config := config()

		config.KeyManager = &mockkms.KeyManager{CrAndExportPubKeyValue: []byte("foo")}

		c, err := New(config)
		require.NoError(t, err)

		_, err = c.newVerificationMethod(kms.X25519ECDHKWType)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal X25519 key")
	})

	t.Run("fail: invalid jwk key", func(t *testing.T) {
		t.Parallel()

		config := config()

		config.KeyManager = &mockkms.KeyManager{CrAndExportPubKeyValue: []byte("foo")}

		c, err := New(config)
		require.NoError(t, err)

		_, err = c.newVerificationMethod(kms.NISTP256ECDHKWType)
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating jwk")
	})
}
