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

	msgsvc "github.com/trustbloc/edge-adapter/pkg/message"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
)

const (
	// msg service paths.
	msgServiceOperationID = "/message"
	msgServiceList        = msgServiceOperationID + "/services"
	registerMsgService    = msgServiceOperationID + "/register-service"
	unregisterMsgService  = msgServiceOperationID + "/unregister-service"
	sendNewMsg            = msgServiceOperationID + "/send"
)

func registerCreateConnMsgServices(controllerURL, msgSvcName string) error {
	// unregister all the msg services (to clear older data)
	err := unregisterAllMsgServices(controllerURL)
	if err != nil {
		return err
	}

	// register create conn msg service
	params := messaging.RegisterMsgSvcArgs{
		Name: msgSvcName,
		Type: "https://trustbloc.github.io/blinded-routing/1.0/diddoc-resp",
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

func getServicesList(controllerURL string) ([]string, error) {
	result := &messaging.RegisteredServicesResponse{}

	err := bddutil.SendHTTP(http.MethodGet, controllerURL+msgServiceList, nil, result)
	if err != nil {
		return nil, fmt.Errorf("get message service list : %w", err)
	}

	return result.Names, nil
}

func unregisterAllMsgServices(controllerURL string) error {
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

func sendDIDDocReq(controllerURL, connID string) error {
	msg := &msgsvc.DIDDocReq{
		ID:   uuid.New().String(),
		Type: "https://trustbloc.github.io/blinded-routing/1.0/diddoc-req",
	}

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

func getDIDDocResp(controllerURL, msgSvcName string) (*did.Doc, error) {
	webhookMsg, err := pullMsgFromWebhookURL(controllerURL, msgSvcName)
	if err != nil {
		return nil, fmt.Errorf("failed to pull incoming message from webhook : %w", err)
	}

	// validate the response
	var message struct {
		Message msgsvc.DIDDocResp `json:"message"`
	}

	err = webhookMsg.Decode(&message)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	if message.Message.Data == nil {
		return nil, errors.New("no data received from the adapter")
	}

	if message.Message.Data.ErrorMsg != "" {
		return nil, fmt.Errorf("error received from the route : %s", message.Message.Data.ErrorMsg)
	}

	if message.Message.Data.DIDDoc == nil {
		return nil, errors.New("no did document received from the adapter")
	}

	doc, err := did.ParseDocument(message.Message.Data.DIDDoc)
	if err != nil {
		return nil, fmt.Errorf("parse adapter did document: %w", err)
	}

	return doc, nil
}
