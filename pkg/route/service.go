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
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-adapter/pkg/aries/message"
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
	txnStoreName       = "msgsvc_txn"
	didCommServiceType = "did-communication"
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
	Store             storage.Provider
	ConnectionLookup  connectionRecorder
	MediatorSvc       mediatorsvc.ProtocolService
}

// Service svc.
type Service struct {
	didExchange      DIDExchange
	mediator         Mediator
	messenger        service.Messenger
	vdriRegistry     vdr.Registry
	endpoint         string
	store            storage.Store
	connectionLookup connectionRecorder
	mediatorSvc      mediatorsvc.ProtocolService
}

// New returns a new Service.
func New(config *Config) (*Service, error) {
	store, err := getTxnStore(config.Store)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	o := &Service{
		didExchange:      config.DIDExchangeClient,
		mediator:         config.MediatorClient,
		messenger:        config.AriesMessenger,
		vdriRegistry:     config.VDRIRegistry,
		endpoint:         config.ServiceEndpoint,
		store:            store,
		connectionLookup: config.ConnectionLookup,
		// TODO https://github.com/trustbloc/edge-adapter/issues/361 use function from client
		mediatorSvc: config.MediatorSvc,
	}

	msgCh := make(chan message.Msg, 1)

	err = config.MsgRegistrar.Register(
		message.NewMsgSvc("diddoc-req", didDocReq, msgCh),
		message.NewMsgSvc("register-route-req", registerRouteReq, msgCh),
	)
	if err != nil {
		return nil, fmt.Errorf("message service client: %w", err)
	}

	go o.didCommMsgListener(msgCh)

	return o, nil
}

// GetDIDDoc returns the did doc with router endpoint/keys if its registered, else returns the doc
// with default endpoint.
func (o *Service) GetDIDDoc(connID string, requiresBlindedRoute bool) (*did.Doc, error) { //nolint:gocyclo
	// get routers connection ID
	routerConnID, err := o.store.Get(connID)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return nil, fmt.Errorf("get conn id to router conn id mapping: %w", err)
	}

	if errors.Is(err, storage.ErrDataNotFound) {
		if requiresBlindedRoute {
			return nil, errors.New("no router registered to support blinded routing")
		}

		docResolution, errCreate := o.vdriRegistry.Create(
			peer.DIDMethod,
			&did.Doc{Service: []did.Service{{
				ServiceEndpoint: o.endpoint,
			}}})
		if errCreate != nil {
			return nil, errCreate
		}

		return docResolution.DIDDocument, nil
	}

	config, err := o.mediator.GetConfig(string(routerConnID))
	if err != nil {
		return nil, fmt.Errorf("get mediator config: %w", err)
	}

	docResolution, err := o.vdriRegistry.Create(
		peer.DIDMethod,
		&did.Doc{Service: []did.Service{{
			ServiceEndpoint: config.Endpoint(),
			RoutingKeys:     config.Keys(),
		}}})
	if err != nil {
		return nil, err
	}

	newDidDoc := docResolution.DIDDocument

	didSvc, ok := did.LookupService(newDidDoc, didCommServiceType)
	if !ok {
		return nil, fmt.Errorf("did document missing %s service type", didCommServiceType)
	}

	for _, val := range didSvc.RecipientKeys {
		err = mediatorsvc.AddKeyToRouter(o.mediatorSvc, string(routerConnID), val)
		if err != nil {
			return nil, fmt.Errorf("register did doc recipient key : %w", err)
		}
	}

	return newDidDoc, nil
}

func (o *Service) didCommMsgListener(ch <-chan message.Msg) {
	for msg := range ch {
		var err error

		var msgMap service.DIDCommMsgMap

		switch msg.DIDCommMsg.Type() {
		case didDocReq:
			msgMap, err = o.handleDIDDocReq(msg.DIDCommMsg)
		case registerRouteReq:
			msgMap, err = o.handleRouteRegistration(msg)
		default:
			err = fmt.Errorf("unsupported message service type : %s", msg.DIDCommMsg.Type())
		}

		if err != nil {
			msgType := msg.DIDCommMsg.Type()

			switch msg.DIDCommMsg.Type() {
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

			logger.Errorf("msgType=[%s] id=[%s] errMsg=[%s]", msg.DIDCommMsg.Type(), msg.DIDCommMsg.ID(), err.Error())
		}

		err = o.messenger.ReplyTo(msg.DIDCommMsg.ID(), msgMap) // nolint:staticcheck //issue#403
		if err != nil {
			logger.Errorf("sendReply : msgType=[%s] id=[%s] errMsg=[%s]",
				msg.DIDCommMsg.Type(), msg.DIDCommMsg.ID(), err.Error())

			continue
		}

		logger.Infof("msgType=[%s] id=[%s] msg=[%s]", msg.DIDCommMsg.Type(), msg.DIDCommMsg.ID(), "success")
	}
}

func (o *Service) handleDIDDocReq(msg service.DIDCommMsg) (service.DIDCommMsgMap, error) {
	docResolution, err := o.vdriRegistry.Create(
		peer.DIDMethod,
		&did.Doc{Service: []did.Service{{
			ServiceEndpoint: o.endpoint,
		}}})
	if err != nil {
		return nil, err
	}

	newDidDoc := docResolution.DIDDocument

	err = o.store.Put(msg.ID(), []byte(newDidDoc.ID))
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

func (o *Service) handleRouteRegistration(msg message.Msg) (service.DIDCommMsgMap, error) { // nolint: gocyclo
	pMsg := ConnReq{}

	err := msg.DIDCommMsg.Decode(&pMsg)
	if err != nil {
		return nil, fmt.Errorf("parse didcomm message : %w", err)
	}

	if msg.DIDCommMsg.ParentThreadID() == "" {
		return nil, errors.New("parent thread id mandatory")
	}

	if pMsg.Data == nil || pMsg.Data.DIDDoc == nil {
		return nil, errors.New("did document mandatory")
	}

	didDoc, err := did.ParseDocument(pMsg.Data.DIDDoc)
	if err != nil {
		return nil, fmt.Errorf("parse did doc : %w", err)
	}

	txnID, err := o.store.Get(msg.DIDCommMsg.ParentThreadID())
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

	connID, err := o.connectionLookup.GetConnectionIDByDIDs(msg.MyDID, msg.TheirDID)
	if err != nil {
		return nil, fmt.Errorf("get connection by dids : %w", err)
	}

	err = o.store.Put(connID, []byte(routerConnID))
	if err != nil {
		return nil, fmt.Errorf("save connID to routerConnID mapping : %w", err)
	}

	return service.NewDIDCommMsgMap(&ConnResp{
		ID:   uuid.New().String(),
		Type: registerRouteResp,
	}), nil
}

func getTxnStore(prov storage.Provider) (storage.Store, error) {
	txnStore, err := prov.OpenStore(txnStoreName)
	if err != nil {
		return nil, err
	}

	return txnStore, nil
}
