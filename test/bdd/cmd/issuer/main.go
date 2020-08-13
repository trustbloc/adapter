/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("edge-adapter/issuer")

const (
	addressPattern = ":%s"
)

func main() {
	port := os.Getenv("ISSUER_PORT")
	if port == "" {
		panic("port to be passed as ENV variable")
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/data", createUserDataVCHandler).Methods(http.MethodPost)

	logger.Fatalf("issuer server start error %s", http.ListenAndServe(fmt.Sprintf(addressPattern, port), router))
}

func createUserDataVCHandler(rw http.ResponseWriter, req *http.Request) {
	msg, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf("[issuer] failed to read request - err:%s", err.Error())
		rw.WriteHeader(http.StatusBadRequest)
	}

	// TODO add validation, for now return VC

	_, err = rw.Write([]byte(prCardData))
	if err != nil {
		logger.Errorf("[issuer] failed to send vc - err:%s", err.Error())
		rw.WriteHeader(http.StatusBadRequest)
	}

	rw.WriteHeader(http.StatusOK)

	logger.Infof("[issuer] req: %s resp=%s", string(msg), prCardData)
}

const (
	prCardData = `{
	   "data":{
		  "id":"http://example.com/b34ca6cd37bbf23",
		  "givenName":"JOHN",
		  "familyName":"SMITH",
		  "gender":"Male",
		  "image":"data:image/png;base64,iVBORw0KGgo...kJggg==",
		  "residentSince":"2015-01-01",
		  "lprCategory":"C09",
		  "lprNumber":"999-999-999",
		  "commuterClassification":"C1",
		  "birthCountry":"Bahamas",
		  "birthDate":"1958-07-17"
	   },
	   "metadata":{
		  "contexts":["https://w3id.org/citizenship/v1"],
		  "scopes":["PermanentResidentCard"]
	   }
	}`
)
