/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	mediatorsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
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
	txnStoreName         = "msgsvc_txn"
	didCommServiceType   = "did-communication"
	didCommV2ServiceType = "DIDCommMessaging"
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
	KeyManager        kms.KeyManager
	KeyType           kms.KeyType
	KeyAgrType        kms.KeyType
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
	keyManager       kms.KeyManager
	keyType          kms.KeyType
	keyAgrType       kms.KeyType
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
		keyManager:  config.KeyManager,
		keyType:     config.KeyType,
		keyAgrType:  config.KeyAgrType,
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
//nolint:gocyclo,funlen,cyclop
func (o *Service) GetDIDDoc(connID string, requiresBlindedRoute, isDIDcommV1 bool) (*did.Doc, error) {
	verMethod, err := o.newVerificationMethod(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create new verification method: %w", err)
	}

	kaVM, err := o.newVerificationMethod(o.keyAgrType)
	if err != nil {
		return nil, fmt.Errorf("failed to create new keyagreement VM: %w", err)
	}

	ka := did.NewReferencedVerification(kaVM, did.KeyAgreement)

	// get routers connection ID
	routerConnID, err := o.store.Get(connID)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return nil, fmt.Errorf("get conn id to router conn id mapping: %w", err)
	}

	if errors.Is(err, storage.ErrDataNotFound) {
		if requiresBlindedRoute {
			return nil, errors.New("no router registered to support blinded routing")
		}

		svc := did.Service{Type: didCommV2ServiceType, ServiceEndpoint: model.NewDIDCommV2Endpoint(
			[]model.DIDCommV2Endpoint{{URI: o.endpoint}})}

		if isDIDcommV1 {
			svc = did.Service{Type: didCommServiceType, ServiceEndpoint: model.NewDIDCommV1Endpoint(o.endpoint)}
		}

		docResolution, errCreate := o.vdriRegistry.Create(
			peer.DIDMethod,
			&did.Doc{
				Service:            []did.Service{svc},
				VerificationMethod: []did.VerificationMethod{*verMethod},
				KeyAgreement:       []did.Verification{*ka},
			},
		)
		if errCreate != nil {
			return nil, fmt.Errorf("failed to create peer did: %w", errCreate)
		}

		return docResolution.DIDDocument, nil
	}

	config, err := o.mediator.GetConfig(string(routerConnID))
	if err != nil {
		return nil, fmt.Errorf("get mediator config [routerConnID=%s]: %w", routerConnID, err)
	}

	svc := did.Service{Type: didCommV2ServiceType,
		ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{{
			URI:         config.Endpoint(),
			RoutingKeys: config.Keys()}})}

	if isDIDcommV1 {
		svc = did.Service{Type: didCommServiceType, RoutingKeys: config.Keys(),
			ServiceEndpoint: model.NewDIDCommV1Endpoint(config.Endpoint())}
	}

	docResolution, err := o.vdriRegistry.Create(
		peer.DIDMethod,
		&did.Doc{
			Service:            []did.Service{svc},
			VerificationMethod: []did.VerificationMethod{*verMethod},
			KeyAgreement:       []did.Verification{*ka},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create peer did: %w", err)
	}

	newDidDoc := docResolution.DIDDocument

	didSvc, ok := did.LookupService(newDidDoc, didCommServiceType)
	if !ok {
		didSvc, ok = did.LookupService(newDidDoc, didCommV2ServiceType)
		if !ok {
			return nil, fmt.Errorf("did document missing %s service type", didCommServiceType)
		}
	}

	for _, val := range didSvc.RecipientKeys {
		err = mediatorsvc.AddKeyToRouter(o.mediatorSvc, string(routerConnID), val)
		if err != nil {
			return nil, fmt.Errorf("register did doc recipient key : %w", err)
		}
	}

	for _, kaV := range newDidDoc.KeyAgreement {
		kaID := kaV.VerificationMethod.ID
		if strings.HasPrefix(kaID, "#") {
			kaID = newDidDoc.ID + kaID
		}

		err = mediatorsvc.AddKeyToRouter(o.mediatorSvc, string(routerConnID), kaID)
		if err != nil {
			return nil, fmt.Errorf("register did doc keyAgreement key : %w", err)
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
	verMethod, err := o.newVerificationMethod(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create new verification method: %w", err)
	}

	kaVM, err := o.newVerificationMethod(o.keyAgrType)
	if err != nil {
		return nil, fmt.Errorf("failed to create new keyagreement VM: %w", err)
	}

	ka := did.NewReferencedVerification(kaVM, did.KeyAgreement)

	docResolution, err := o.vdriRegistry.Create(
		peer.DIDMethod,
		&did.Doc{
			Service: []did.Service{{
				Type:            didCommServiceType,
				ServiceEndpoint: model.NewDIDCommV1Endpoint(o.endpoint),
			}},
			VerificationMethod: []did.VerificationMethod{*verMethod},
			KeyAgreement:       []did.Verification{*ka},
		})
	if err != nil {
		return nil, fmt.Errorf("failed to create peer did: %w", err)
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

const (
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
	jsonWebKey2020             = "JsonWebKey2020"
)

// TODO: copied from mediator, should push shared code upstream
func (o *Service) newVerificationMethod(kt kms.KeyType) (*did.VerificationMethod, error) {
	kid, pkBytes, err := o.keyManager.CreateAndExportPubKeyBytes(kt)
	if err != nil {
		return nil, fmt.Errorf("creating public key: %w", err)
	}

	id := "#" + kid

	var vm *did.VerificationMethod

	switch kt { // nolint:exhaustive // most cases can use the default.
	case kms.ED25519Type:
		vm = did.NewVerificationMethodFromBytes(id, ed25519VerificationKey2018, "", pkBytes)
	case kms.X25519ECDHKWType:
		key := &ariescrypto.PublicKey{}

		err = json.Unmarshal(pkBytes, key)
		if err != nil {
			return nil, fmt.Errorf("unmarshal X25519 key: %w", err)
		}

		vm = did.NewVerificationMethodFromBytes(id, x25519KeyAgreementKey2019, "", key.X)
	default:
		j, err := jwkkid.BuildJWK(pkBytes, kt)
		if err != nil {
			return nil, fmt.Errorf("creating jwk: %w", err)
		}

		j.KeyID = kid

		vm, err = did.NewVerificationMethodFromJWK(id, jsonWebKey2020, "", j)
		if err != nil {
			return nil, fmt.Errorf("creating verification method: %w", err)
		}
	}

	return vm, nil
}

func (o *Service) handleRouteRegistration(msg message.Msg) (service.DIDCommMsgMap, error) { // nolint: gocyclo,cyclop
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
		return nil, fmt.Errorf("failed to open txn store: %w", err)
	}

	return txnStore, nil
}
