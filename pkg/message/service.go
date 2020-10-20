/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package message

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
)

// Msg svc constants.
const (
	msgTypeBaseURI = "https://trustbloc.github.io/blinded-routing/1.0"
	peerDIDDocReq  = msgTypeBaseURI + "/diddoc-req"
	peerDIDDocResp = msgTypeBaseURI + "/diddoc-resp"
	connReq        = msgTypeBaseURI + "/conn-req"
	connResp       = msgTypeBaseURI + "/conn-resp"
)

const (
	txnStoreName = "msgsvc_txn"
)

var logger = log.New("edge-adapter/msgsvc")

// DIDExchange client.
type DIDExchange interface {
	CreateConnection(myDID string, theirDID *did.Doc, options ...didexchange.ConnectionOption) (string, error)
}

// Config holds configuration.
type Config struct {
	DIDExchangeClient DIDExchange
	ServiceEndpoint   string
	AriesMessenger    service.Messenger
	MsgRegistrar      *msghandler.Registrar
	VDRIRegistry      vdr.Registry
	TransientStore    storage.Provider
}

// Service svc.
type Service struct {
	didExchange  DIDExchange
	messenger    service.Messenger
	vdriRegistry vdr.Registry
	endpoint     string
	tStore       storage.Store
}

// New returns a new Service.
func New(config *Config) (*Service, error) {
	tStore, err := getTxnStore(config.TransientStore)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	o := &Service{
		didExchange:  config.DIDExchangeClient,
		messenger:    config.AriesMessenger,
		vdriRegistry: config.VDRIRegistry,
		endpoint:     config.ServiceEndpoint,
		tStore:       tStore,
	}

	msgCh := make(chan service.DIDCommMsg, 1)

	err = config.MsgRegistrar.Register(
		newMsgSvc("peer-diddoc-req", peerDIDDocReq, msgCh),
		newMsgSvc("create-conn-req", peerDIDDocReq, msgCh),
	)
	if err != nil {
		return nil, fmt.Errorf("message service client: %w", err)
	}

	go o.didCommMsgListener(msgCh)

	return o, nil
}

func (o *Service) didCommMsgListener(ch <-chan service.DIDCommMsg) {
	for msg := range ch {
		var err error

		var msgMap service.DIDCommMsgMap

		switch msg.Type() {
		case peerDIDDocReq:
			msgMap, err = o.handleDIDDocReq(msg)
		case connReq:
			msgMap, err = o.handleConnReq(msg)
		default:
			err = fmt.Errorf("unsupported message service type : %s", msg.Type())
		}

		if err != nil {
			msgType := msg.Type()

			switch msg.Type() {
			case peerDIDDocReq:
				msgType = peerDIDDocResp
			case connReq:
				msgType = connResp
			}

			msgMap = service.NewDIDCommMsgMap(&ErrorResp{
				ID:   uuid.New().String(),
				Type: msgType,
				Data: &ErrorRespData{ErrorMsg: err.Error()},
			})

			logger.Errorf("msgType=[%s] id=[%s] errMsg=[%s]", msg.Type(), msg.ID(), err.Error())
		}

		err = o.messenger.ReplyTo(msg.ID(), msgMap)
		if err != nil {
			logger.Errorf("sendReply : msgType=[%s] id=[%s] errMsg=[%s]", msg.Type(), msg.ID(), err.Error())

			continue
		}

		logger.Infof("msgType=[%s] id=[%s] msg=[%s]", msg.Type(), msg.ID(), "success")
	}
}

func (o *Service) handleDIDDocReq(msg service.DIDCommMsg) (service.DIDCommMsgMap, error) {
	// create peer DID
	newDidDoc, err := o.vdriRegistry.Create("peer", vdr.WithServices(did.Service{ServiceEndpoint: o.endpoint}))
	if err != nil {
		return nil, fmt.Errorf("create new peer did : %w", err)
	}

	err = o.tStore.Put(msg.ID(), []byte(newDidDoc.ID))
	if err != nil {
		return nil, fmt.Errorf("save txn data : %w", err)
	}

	docBytes, err := newDidDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("marshal did doc : %w", err)
	}

	// send the did doc
	return service.NewDIDCommMsgMap(&DIDDocResp{
		ID:   uuid.New().String(),
		Type: peerDIDDocResp,
		Data: &DIDDocRespData{
			DIDDoc: docBytes,
		},
	}), nil
}

func (o *Service) handleConnReq(msg service.DIDCommMsg) (service.DIDCommMsgMap, error) {
	pMsg := ConnReq{}

	err := msg.Decode(&pMsg)
	if err != nil {
		return nil, fmt.Errorf("parse didcomm message : %w", err)
	}

	if msg.ParentThreadID() == "" {
		return nil, errors.New("parent thread id mandatory")
	}

	if pMsg.Data == nil || pMsg.Data.DIDDoc == nil {
		return nil, errors.New("did document mandatory")
	}

	didDoc, err := did.ParseDocument(pMsg.Data.DIDDoc)
	if err != nil {
		return nil, fmt.Errorf("parse did doc : %w", err)
	}

	txnID, err := o.tStore.Get(msg.ParentThreadID())
	if err != nil {
		return nil, fmt.Errorf("fetch txn data : %w", err)
	}

	_, err = o.didExchange.CreateConnection(string(txnID), didDoc)
	if err != nil {
		return nil, fmt.Errorf("create connection : %w", err)
	}

	// TODO https://github.com/trustbloc/edge-adapter/issues/342 register with router

	return service.NewDIDCommMsgMap(&ConnResp{
		ID:   uuid.New().String(),
		Type: connResp,
	}), nil
}

func getTxnStore(prov storage.Provider) (storage.Store, error) {
	err := prov.CreateStore(txnStoreName)
	if err != nil && !errors.Is(err, storage.ErrDuplicateStore) {
		return nil, err
	}

	txnStore, err := prov.OpenStore(txnStoreName)
	if err != nil {
		return nil, err
	}

	return txnStore, nil
}
