/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	mediatorsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
)

// Msg svc constants.
const (
	msgTypeBaseURI    = "https://trustbloc.dev/blinded-routing/1.0"
	didDocReq         = msgTypeBaseURI + "/diddoc-req"
	didDocResp        = msgTypeBaseURI + "/diddoc-resp"
	registerRouteReq  = msgTypeBaseURI + "/register-route-req"
	registerRouteResp = msgTypeBaseURI + "/register-route-resp"
)

const (
	txnStoreName = "msgsvc_txn"
)

var logger = log.New("edge-adapter/msgsvc")

// DIDExchange client.
type DIDExchange interface {
	CreateConnection(myDID string, theirDID *did.Doc, options ...didexchange.ConnectionOption) (string, error)
}

// Mediator client.
type Mediator interface {
	Register(connectionID string) error
	GetConfig(connID string) (*mediatorsvc.Config, error)
}

type connectionRecorder interface {
	GetConnectionIDByDIDs(string, string) (string, error)
}

// Config holds configuration.
type Config struct {
	DIDExchangeClient DIDExchange
	MediatorClient    Mediator
	ServiceEndpoint   string
	AriesMessenger    service.Messenger
	MsgRegistrar      *msghandler.Registrar
	VDRIRegistry      vdr.Registry
	TransientStore    storage.Provider
	ConnectionLookup  connectionRecorder
}

// Service svc.
type Service struct {
	didExchange      DIDExchange
	mediator         Mediator
	messenger        service.Messenger
	vdriRegistry     vdr.Registry
	endpoint         string
	tStore           storage.Store
	connectionLookup connectionRecorder
}

// New returns a new Service.
func New(config *Config) (*Service, error) {
	tStore, err := getTxnStore(config.TransientStore)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	o := &Service{
		didExchange:      config.DIDExchangeClient,
		mediator:         config.MediatorClient,
		messenger:        config.AriesMessenger,
		vdriRegistry:     config.VDRIRegistry,
		endpoint:         config.ServiceEndpoint,
		tStore:           tStore,
		connectionLookup: config.ConnectionLookup,
	}

	msgCh := make(chan routeMsg, 1)

	err = config.MsgRegistrar.Register(
		newMsgSvc("diddoc-req", didDocReq, msgCh),
		newMsgSvc("register-route-req", registerRouteReq, msgCh),
	)
	if err != nil {
		return nil, fmt.Errorf("message service client: %w", err)
	}

	go o.didCommMsgListener(msgCh)

	return o, nil
}

// GetDIDService returns the did svc block with router endpoint/keys if its registered, else returns default endpoint.
func (o *Service) GetDIDService(connID string) (*did.Service, error) {
	// get routers connection ID
	routerConnID, err := o.tStore.Get(connID)
	if err != nil && !errors.Is(err, storage.ErrValueNotFound) {
		return nil, fmt.Errorf("get conn id to router conn id mapping: %w", err)
	}

	// TODO https://github.com/trustbloc/edge-adapter/issues/339 Enforce blinded routing (should throw
	//  error if route is not registered)
	if errors.Is(err, storage.ErrValueNotFound) {
		return &did.Service{
			ServiceEndpoint: o.endpoint,
		}, nil
	}

	config, err := o.mediator.GetConfig(string(routerConnID))
	if err != nil {
		return nil, fmt.Errorf("get mediator config: %w", err)
	}

	return &did.Service{
		ServiceEndpoint: config.Endpoint(),
		RoutingKeys:     config.Keys(),
	}, nil
}

func (o *Service) didCommMsgListener(ch <-chan routeMsg) {
	for msg := range ch {
		var err error

		var msgMap service.DIDCommMsgMap

		switch msg.didCommMsg.Type() {
		case didDocReq:
			msgMap, err = o.handleDIDDocReq(msg.didCommMsg)
		case registerRouteReq:
			msgMap, err = o.handleRouteRegistration(msg)
		default:
			err = fmt.Errorf("unsupported message service type : %s", msg.didCommMsg.Type())
		}

		if err != nil {
			msgType := msg.didCommMsg.Type()

			switch msg.didCommMsg.Type() {
			case didDocReq:
				msgType = didDocResp
			case registerRouteReq:
				msgType = registerRouteResp
			}

			msgMap = service.NewDIDCommMsgMap(&ErrorResp{
				ID:   uuid.New().String(),
				Type: msgType,
				Data: &ErrorRespData{ErrorMsg: err.Error()},
			})

			logger.Errorf("msgType=[%s] id=[%s] errMsg=[%s]", msg.didCommMsg.Type(), msg.didCommMsg.ID(), err.Error())
		}

		err = o.messenger.ReplyTo(msg.didCommMsg.ID(), msgMap)
		if err != nil {
			logger.Errorf("sendReply : msgType=[%s] id=[%s] errMsg=[%s]",
				msg.didCommMsg.Type(), msg.didCommMsg.ID(), err.Error())

			continue
		}

		logger.Infof("msgType=[%s] id=[%s] msg=[%s]", msg.didCommMsg.Type(), msg.didCommMsg.ID(), "success")
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
		Type: didDocResp,
		Data: &DIDDocRespData{
			DIDDoc: docBytes,
		},
	}), nil
}

func (o *Service) handleRouteRegistration(msg routeMsg) (service.DIDCommMsgMap, error) { // nolint: gocyclo
	pMsg := ConnReq{}

	err := msg.didCommMsg.Decode(&pMsg)
	if err != nil {
		return nil, fmt.Errorf("parse didcomm message : %w", err)
	}

	if msg.didCommMsg.ParentThreadID() == "" {
		return nil, errors.New("parent thread id mandatory")
	}

	if pMsg.Data == nil || pMsg.Data.DIDDoc == nil {
		return nil, errors.New("did document mandatory")
	}

	didDoc, err := did.ParseDocument(pMsg.Data.DIDDoc)
	if err != nil {
		return nil, fmt.Errorf("parse did doc : %w", err)
	}

	txnID, err := o.tStore.Get(msg.didCommMsg.ParentThreadID())
	if err != nil {
		return nil, fmt.Errorf("fetch txn data : %w", err)
	}

	routerConnID, err := o.didExchange.CreateConnection(string(txnID), didDoc)
	if err != nil {
		return nil, fmt.Errorf("create connection : %w", err)
	}

	err = o.mediator.Register(routerConnID)
	if err != nil {
		return nil, fmt.Errorf("route registration : %w", err)
	}

	connID, err := o.connectionLookup.GetConnectionIDByDIDs(msg.myDID, msg.theirDID)
	if err != nil {
		return nil, fmt.Errorf("get connection by dids : %w", err)
	}

	err = o.tStore.Put(connID, []byte(routerConnID))
	if err != nil {
		return nil, fmt.Errorf("save connID to routerConnID mapping : %w", err)
	}

	return service.NewDIDCommMsgMap(&ConnResp{
		ID:   uuid.New().String(),
		Type: registerRouteResp,
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
