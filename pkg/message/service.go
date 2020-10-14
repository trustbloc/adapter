/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package message

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/trustbloc/edge-core/pkg/log"
)

// Msg svc constants.
const (
	msgTypeBaseURI = "https://trustbloc.github.io/blinded-routing/1.0"
	peerDIDDocReq  = msgTypeBaseURI + "/diddoc-req"
	peerDIDDocResp = msgTypeBaseURI + "/diddoc-resp"
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
	VDRIRegistry      vdri.Registry
}

// Service svc.
type Service struct {
	didExchange  DIDExchange
	messenger    service.Messenger
	vdriRegistry vdri.Registry
	endpoint     string
}

// New returns a new Service.
func New(config *Config) (*Service, error) {
	o := &Service{
		didExchange:  config.DIDExchangeClient,
		messenger:    config.AriesMessenger,
		vdriRegistry: config.VDRIRegistry,
		endpoint:     config.ServiceEndpoint,
	}

	msgCh := make(chan service.DIDCommMsg, 1)

	msgSvc := newMsgSvc("create-connection", peerDIDDocReq, msgCh)

	err := config.MsgRegistrar.Register(msgSvc)
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
			msgMap, err = o.handleDIDDocReq()
		default:
			err = fmt.Errorf("unsupported message service type : %s", msg.Type())
		}

		if err != nil {
			msgMap = service.NewDIDCommMsgMap(&DIDDocResp{
				ID:   uuid.New().String(),
				Type: msg.Type(),
				Data: &DIDDocRespData{ErrorMsg: err.Error()},
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

func (o *Service) handleDIDDocReq() (service.DIDCommMsgMap, error) {
	// create peer DID
	newDidDoc, err := o.vdriRegistry.Create("peer", vdri.WithServices(did.Service{ServiceEndpoint: o.endpoint}))
	if err != nil {
		return nil, fmt.Errorf("create new peer did : %w", err)
	}

	docBytes, err := newDidDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("marshal did doc : %w", err)
	}

	// send the did doc
	return service.NewDIDCommMsgMap(&DIDDocResp{
		ID:   uuid.New().String(),
		Type: peerDIDDocResp,
		Data: &DIDDocRespData{DIDDoc: docBytes},
	}), nil
}
