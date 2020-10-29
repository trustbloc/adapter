/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("edge-adapter/issuer")

const (
	addressPattern = ":%s"
)

var (
	// nolint:gochecknoglobals
	dataMap          = make(map[string]string)
	assuranceDataMap = make(map[string]string)
	tokenStore       = make(map[string]bool)
)

// nolint:gochecknoinits
func init() {
	dataMap["prCard"] = prCardData
	dataMap["creditCard"] = creditCardData
	dataMap["driversLicense"] = driversLicenceData

	assuranceDataMap["driversLicense"] = driversLicenceAssuranceData
}

func main() {
	port := os.Getenv("ISSUER_PORT")
	if port == "" {
		panic("port to be passed as ENV variable")
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/{issuer}/token", tokenHandler).Methods(http.MethodPost)
	router.HandleFunc("/{issuer}/data", createUserDataVCHandler).Methods(http.MethodPost)
	router.HandleFunc("/{issuer}/assurance", createAssuranceDataVCHandler).Methods(http.MethodPost)

	logger.Fatalf("issuer server start error %s", http.ListenAndServe(fmt.Sprintf(addressPattern, port), router))
}

func tokenHandler(rw http.ResponseWriter, req *http.Request) {
	token := uuid.New().String()

	resp := &issuerTokenResp{
		Token: token,
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			fmt.Sprintf("[issuer] failed to send token resp - err:%s", err.Error()), req.RequestURI, logger)
	}

	tokenStore[token] = true

	_, err = rw.Write(respBytes)
	if err != nil {
		WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			fmt.Sprintf("[issuer] failed to send token resp - err:%s", err.Error()), req.RequestURI, logger)
	}

	rw.WriteHeader(http.StatusOK)
}

func createUserDataVCHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)

	data := &userDataReq{}

	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			fmt.Sprintf("[issuer] invalid request - err:%s", err.Error()), req.RequestURI, logger)
	}

	tokenStore[data.Token] = true

	_, ok := tokenStore[data.Token]
	if !ok {
		WriteErrorResponseWithLog(rw, http.StatusBadRequest, "invalid token", req.RequestURI, logger)
	}

	_, err := rw.Write([]byte(dataMap[vars["issuer"]]))
	if err != nil {
		WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			fmt.Sprintf("[issuer] failed to send vc - err:%s", err.Error()), req.RequestURI, logger)
	}

	rw.WriteHeader(http.StatusOK)

	logger.Infof("[issuer] issuer:%s req: %s resp=%s", vars["issuer"], data.Token, dataMap[vars["issuer"]])
}

func createAssuranceDataVCHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)

	data := &userDataReq{}

	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		WriteErrorResponseWithLog(rw, http.StatusBadRequest,
			fmt.Sprintf("[issuer] invalid request - err:%s", err.Error()), req.RequestURI, logger)
	}

	tokenStore[data.Token] = true

	_, ok := tokenStore[data.Token]
	if !ok {
		WriteErrorResponseWithLog(rw, http.StatusBadRequest, "invalid token", req.RequestURI, logger)
	}

	_, err := rw.Write([]byte(assuranceDataMap[vars["issuer"]]))
	if err != nil {
		WriteErrorResponseWithLog(rw, http.StatusInternalServerError,
			fmt.Sprintf("[issuer] failed to send assurance data - err:%s", err.Error()), req.RequestURI, logger)
	}

	rw.WriteHeader(http.StatusOK)

	logger.Infof("[issuer-assurance] issuer:%s req: %s resp=%s", vars["issuer"], data.Token, assuranceDataMap[vars["issuer"]])
}

type userDataReq struct {
	Token string `json:"token,omitempty"`
}

type issuerTokenResp struct {
	Token string `json:"token,omitempty"`
}

type errorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

func WriteErrorResponseWithLog(rw http.ResponseWriter, status int, msg, endpoint string, logger log.Logger) {
	logger.Errorf("endpoint=[%s] status=[%d] errMsg=[%s]", endpoint, status, msg)

	rw.WriteHeader(status)

	err := json.NewEncoder(rw).Encode(errorResponse{
		Message: msg,
	})

	if err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
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
		  "contexts":["https://trustbloc.github.io/context/vc/examples/citizenship-v1.jsonld"],
		  "scopes":["PermanentResidentCard"],
		  "name":"Permanent Resident Card",
		  "description":"Permanent Resident Card for John Smith"
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
		  ],
		  "name":"Credit Card Statement",
		  "description":"Credit Card Statement for Jane Doe"
	   }
	}`

	driversLicenceData = `{
	   "data":{
		  "given_name":"John",
		  "family_name":"Smith",
		  "document_number":"123-456-789"
	   },
	   "metadata":{
		  "contexts":[
			 "https://trustbloc.github.io/context/vc/examples/mdl-v1.jsonld"
		  ],
		  "scopes":[
			 "mDL"
		  ],
		  "name":"Drivers License",
		  "description":"Drivers License for John Smith"
	   }
	}`

	driversLicenceAssuranceData = `{
	   "data":{
		  "document_number":"123-456-789"
	   },
	   "metadata":{
		  "contexts":[
			 "https://trustbloc.github.io/context/vc/examples/driver-license-evidence-v1.jsonld"
		  ],
		  "scopes":[
			 "DrivingLicenseEvidence"
		  ],
		  "name":"Drivers License Evidence",
		  "description":"Drivers License Evidence for John Smith"
	   }
	}`
)
