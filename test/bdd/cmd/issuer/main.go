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
	router.HandleFunc("/{issuer}/data", createUserDataVCHandler).Methods(http.MethodPost)

	logger.Fatalf("issuer server start error %s", http.ListenAndServe(fmt.Sprintf(addressPattern, port), router))
}

func createUserDataVCHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)

	msg, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf("[issuer] failed to read request - err:%s", err.Error())
		rw.WriteHeader(http.StatusBadRequest)
	}

	// TODO add validation, for now return VC

	_, err = rw.Write([]byte(dataMap[vars["issuer"]]))
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

	creditCardData = `{
	   "data":{
		  "stmt":{
			 "description":"June 2020 CreditCardStatement",
			 "url":"http://acmebank.com/invoice.pdf",
			 "accountId":"xxxx-xxxx-xxxx-1234",
			 "customer":{
				"@type":"Person",
				"name":"Jane Doe"
			 },
			 "paymentDueDate":"2020-06-30T12:00:00",
			 "minimumPaymentDue":{
				"@type":"PriceSpecification",
				"price":15.00,
				"priceCurrency":"CAD"
			 },
			 "totalPaymentDue":{
				"@type":"PriceSpecification",
				"price":200.00,
				"priceCurrency":"CAD"
			 },
			 "billingPeriod":"P30D",
			 "paymentStatus":"http://schema.org/PaymentDue"
		  }
	   },
	   "metadata":{
		  "contexts":[
			 "https://trustbloc.github.io/context/vc/examples/credit-card-v1.jsonld"
		  ],
		  "scopes":[
			 "CreditCardStatement"
		  ]
	   }
	}`
)

var (
	// nolint:gochecknoglobals
	dataMap = make(map[string]string)
)

// nolint:gochecknoinits
func init() {
	dataMap["prCard"] = prCardData
	dataMap["creditCard"] = creditCardData
}
