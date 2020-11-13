/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	routerops "github.com/trustbloc/hub-router/pkg/restapi/operation"

	routesvc "github.com/trustbloc/edge-adapter/pkg/route"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
)

const (
	// msg service paths.
	msgServiceOperationID = "/message"
	msgServiceList        = msgServiceOperationID + "/services"
	registerMsgService    = msgServiceOperationID + "/register-service"
	unregisterMsgService  = msgServiceOperationID + "/unregister-service"
	sendNewMsg            = msgServiceOperationID + "/send"
	sendReplyMsg          = msgServiceOperationID + "/reply"
)

func getServicesList(controllerURL string) ([]string, error) {
	result := &messaging.RegisteredServicesResponse{}

	err := bddutil.SendHTTP(http.MethodGet, controllerURL+msgServiceList, nil, result)
	if err != nil {
		return nil, fmt.Errorf("get message service list : %w", err)
	}

	return result.Names, nil
}

// UnregisterAllMsgServices unregisters all the message services.
func UnregisterAllMsgServices(controllerURL string) error {
	svcNames, err := getServicesList(controllerURL)
	if err != nil {
		return fmt.Errorf("unregister message services : %w", err)
	}

	for _, svcName := range svcNames {
		params := messaging.UnregisterMsgSvcArgs{
			Name: svcName,
		}

		reqBytes, err := json.Marshal(params)
		if err != nil {
			return err
		}

		err = bddutil.SendHTTP(http.MethodPost, controllerURL+unregisterMsgService, reqBytes, nil)
		if err != nil {
			return fmt.Errorf("unregister message services : %w", err)
		}
	}

	return nil
}

func adapterDIDDocReq(controllerURL, webhookURL, connectionID string) (string, *did.Doc, error) {
	msgSvcName := uuid.New().String()

	// issuer adapter - wallet
	// register for message service
	err := RegisterMsgService(controllerURL, msgSvcName,
		"https://trustbloc.dev/blinded-routing/1.0/diddoc-resp")
	if err != nil {
		return "", nil, err
	}

	// send message
	err = sendMessage(controllerURL, connectionID, &routesvc.DIDDocReq{
		ID:   uuid.New().String(),
		Type: "https://trustbloc.dev/blinded-routing/1.0/diddoc-req",
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to send message : %w", err)
	}

	// get the response
	return getDIDDocResp(webhookURL, msgSvcName)
}

func routerConnReq(controllerURL, webhookURL, connectionID string, adapterDIDDoc *did.Doc) (*did.Doc, error) {
	msgSvcName := uuid.New().String()

	// wallet - router
	// register for message service
	err := RegisterMsgService(controllerURL, msgSvcName,
		"https://trustbloc.dev/blinded-routing/1.0/create-conn-resp")
	if err != nil {
		return nil, err
	}

	docBytes, err := adapterDIDDoc.JSONBytes()
	if err != nil {
		return nil, err
	}

	// send message
	err = sendMessage(controllerURL, connectionID, &routerops.CreateConnReq{
		ID:   uuid.New().String(),
		Type: "https://trustbloc.dev/blinded-routing/1.0/create-conn-req",
		Data: &routerops.CreateConnReqData{
			DIDDoc: docBytes,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send message : %w", err)
	}

	// get the response
	return getRouterCreateConnResp(webhookURL, msgSvcName)
}

func adapterCreateConnReq(controllerURL, webhookURL, msgID string, adapterDIDDoc *did.Doc) error {
	msgSvcName := uuid.New().String()

	// issuer adapter - wallet
	// register for message service
	err := RegisterMsgService(controllerURL, msgSvcName,
		"https://trustbloc.dev/blinded-routing/1.0/register-route-resp")
	if err != nil {
		return err
	}

	docBytes, err := adapterDIDDoc.JSONBytes()
	if err != nil {
		return err
	}

	// send message
	err = sendReply(controllerURL, msgID, &routesvc.ConnReq{
		ID:   uuid.New().String(),
		Type: "https://trustbloc.dev/blinded-routing/1.0/register-route-req",
		Data: &routesvc.ConnReqData{
			DIDDoc: docBytes,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to send message : %w", err)
	}

	// get the response
	return getAdapterConnResp(webhookURL, msgSvcName)
}

func authZDIDDocReq(controllerURL, webhookURL, connectionID string) (string, *did.Doc, error) {
	msgSvcName := uuid.New().String()

	err := RegisterMsgService(controllerURL, msgSvcName, "https://trustbloc.dev/adapter/1.0/diddoc-resp")
	if err != nil {
		return "", nil, err
	}

	// send message
	err = sendMessage(controllerURL, connectionID, &routesvc.DIDDocReq{
		ID:   uuid.New().String(),
		Type: "https://trustbloc.dev/adapter/1.0/diddoc-req",
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to send message : %w", err)
	}

	return getDIDDocResp(webhookURL, msgSvcName)
}

// RegisterMsgService registers a new message services.
func RegisterMsgService(controllerURL, msgSvcName, msgType string) error {
	// register create conn msg service
	params := messaging.RegisterMsgSvcArgs{
		Name: msgSvcName,
		Type: msgType,
	}

	reqBytes, err := json.Marshal(params)
	if err != nil {
		return err
	}

	err = bddutil.SendHTTP(http.MethodPost, controllerURL+registerMsgService, reqBytes, nil)
	if err != nil {
		return err
	}

	// verify if the msg service created successfully
	result, err := getServicesList(controllerURL)
	if err != nil {
		return err
	}

	var found bool

	for _, svcName := range result {
		if svcName == msgSvcName {
			found = true

			break
		}
	}

	if !found {
		return fmt.Errorf("registered service not found : name=%s", msgSvcName)
	}

	return nil
}

func sendMessage(controllerURL, connID string, msg interface{}) error {
	rawBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to get raw message bytes:  %w", err)
	}

	request := &messaging.SendNewMessageArgs{
		ConnectionID: connID,
		MessageBody:  rawBytes,
	}

	reqBytes, err := json.Marshal(request)
	if err != nil {
		return err
	}

	// call controller to send message
	err = bddutil.SendHTTP(http.MethodPost, controllerURL+sendNewMsg, reqBytes, nil)
	if err != nil {
		return fmt.Errorf("failed to send message : %w", err)
	}

	return nil
}

func sendReply(controllerURL, msgID string, msg interface{}) error {
	rawBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to get raw message bytes:  %w", err)
	}

	request := &messaging.SendReplyMessageArgs{
		StartNewThread: true,
		MessageID:      msgID,
		MessageBody:    rawBytes,
	}

	reqBytes, err := json.Marshal(request)
	if err != nil {
		return err
	}

	// call controller to send message
	err = bddutil.SendHTTP(http.MethodPost, controllerURL+sendReplyMsg, reqBytes, nil)
	if err != nil {
		return fmt.Errorf("failed to send message : %w", err)
	}

	return nil
}

func getDIDDocResp(controllerURL, msgSvcName string) (string, *did.Doc, error) {
	webhookMsg, err := pullMsgFromWebhookURL(controllerURL, msgSvcName)
	if err != nil {
		return "", nil, fmt.Errorf("failed to pull incoming message from webhook : %w", err)
	}

	// validate the response
	var message struct {
		Message routesvc.DIDDocResp `json:"message"`
	}

	err = webhookMsg.Decode(&message)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read message: %w", err)
	}

	if message.Message.Data == nil {
		return "", nil, errors.New("no data received from the adapter")
	}

	if message.Message.Data.ErrorMsg != "" {
		return "", nil, fmt.Errorf("error received from the route : %s", message.Message.Data.ErrorMsg)
	}

	if message.Message.Data.DIDDoc == nil {
		return "", nil, errors.New("no did document received from the adapter")
	}

	doc, err := did.ParseDocument(message.Message.Data.DIDDoc)
	if err != nil {
		return "", nil, fmt.Errorf("parse adapter did document: %w", err)
	}

	return message.Message.ID, doc, nil
}

func getRouterCreateConnResp(controllerURL, msgSvcName string) (*did.Doc, error) {
	webhookMsg, err := pullMsgFromWebhookURL(controllerURL, msgSvcName)
	if err != nil {
		return nil, fmt.Errorf("failed to pull incoming message from webhook : %w", err)
	}

	// validate the response
	var message struct {
		Message routerops.CreateConnResp `json:"message"`
	}

	err = webhookMsg.Decode(&message)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	if message.Message.Data == nil {
		return nil, errors.New("no data received from the router")
	}

	if message.Message.Data.ErrorMsg != "" {
		return nil, fmt.Errorf("error received from the router : %s", message.Message.Data.ErrorMsg)
	}

	if message.Message.Data.DIDDoc == nil {
		return nil, errors.New("no did document received from the router")
	}

	doc, err := did.ParseDocument(message.Message.Data.DIDDoc)
	if err != nil {
		return nil, fmt.Errorf("parse router did document: %w", err)
	}

	return doc, nil
}

func getAdapterConnResp(controllerURL, msgSvcName string) error {
	webhookMsg, err := pullMsgFromWebhookURL(controllerURL, msgSvcName)
	if err != nil {
		return fmt.Errorf("failed to pull incoming message from webhook : %w", err)
	}

	// validate the response
	var message struct {
		Message routesvc.ErrorResp `json:"message"`
	}

	err = webhookMsg.Decode(&message)
	if err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	}

	if message.Message.Data != nil && message.Message.Data.ErrorMsg != "" {
		return fmt.Errorf("adapter create connection failed : errMsg=%s", message.Message.Data.ErrorMsg)
	}

	return nil
}

// GetDIDExStateCompResp get didex state complete message.
func GetDIDExStateCompResp(controllerURL, msgSvcName string) error {
	_, err := pullMsgFromWebhookURL(controllerURL, msgSvcName)
	if err != nil {
		return fmt.Errorf("failed to pull incoming message from webhook : %w", err)
	}

	return nil
}
