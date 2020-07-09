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
	router.HandleFunc("/credential", createUserDataVCHandler).Methods(http.MethodPost)

	logger.Fatalf("issuer server start error %s", http.ListenAndServe(fmt.Sprintf(addressPattern, port), router))
}

func createUserDataVCHandler(rw http.ResponseWriter, req *http.Request) {
	msg, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf("[issuer] failed to read request - err:%s", err.Error())
		rw.WriteHeader(http.StatusBadRequest)
	}

	// TODO add validation, for now return VC

	_, err = rw.Write([]byte(prCardVC))
	if err != nil {
		logger.Errorf("[issuer] failed to send vc - err:%s", err.Error())
		rw.WriteHeader(http.StatusBadRequest)
	}

	rw.WriteHeader(http.StatusOK)

	logger.Infof("[issuer] req: %s resp=%s", string(msg), prCardVC)
}

const (
	prCardVC = `{
	  "@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/citizenship/v1"
	  ],
	  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
	  "type": [
		"VerifiableCredential",
		"PermanentResidentCard"
	  ],
	  "name": "Permanent Resident Card",
	  "description": "Permanent Resident Card",
	  "issuer": "did:example:28394728934792387",
	  "issuanceDate": "2019-12-03T12:19:52Z",
	  "expirationDate": "2029-12-03T12:19:52Z",
	  "credentialSubject": {
		"id": "did:example:b34ca6cd37bbf23",
		"type": [
		  "PermanentResident",
		  "Person"
		],
		"givenName": "JOHN",
		"familyName": "SMITH",
		"gender": "Male",
		"image": "data:image/png;base64,iVBORw0KGgo...kJggg==",
		"residentSince": "2015-01-01",
		"lprCategory": "C09",
		"lprNumber": "999-999-999",
		"commuterClassification": "C1",
		"birthCountry": "Bahamas",
		"birthDate": "1958-07-17"
	  }
	}`
)
