/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edge-adapter/pkg/aries"
	"github.com/trustbloc/edge-adapter/pkg/internal/common/support"
	"github.com/trustbloc/edge-adapter/pkg/profile/issuer"
	commhttp "github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/http"
)

const (
	// API endpoints
	issuerBasePath  = "/issuer"
	didCommBasePath = issuerBasePath + "/didcomm"

	profileEndpoint            = "/profile"
	getProfileEndpoint         = profileEndpoint + "/{id}"
	walletConnectEndpoint      = "/{id}/connect/wallet"
	generateInvitationEndpoint = didCommBasePath + "/invitation"

	// http params
	idPathParam = "id"
)

var logger = log.New("edge-adapter/issuer-operations")

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Config defines configuration for issuer operations.
type Config struct {
	AriesCtx      aries.CtxProvider
	UIEndpoint    string
	StoreProvider storage.Provider
}

// New returns issuer rest instance.
func New(config *Config) (*Operation, error) {
	didExClient, err := didExchangeClient(config.AriesCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create aries did exchange client : %s", err)
	}

	p, err := issuer.New(config.StoreProvider)
	if err != nil {
		return nil, err
	}

	return &Operation{
		didExClient:  didExClient,
		uiEndpoint:   config.UIEndpoint,
		profileStore: p,
	}, nil
}

// Operation defines handlers for rp operations.
type Operation struct {
	didExClient  *didexchange.Client
	uiEndpoint   string
	profileStore *issuer.Profile
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		// profile
		support.NewHTTPHandler(profileEndpoint, http.MethodPost, o.createIssuerProfileHandler),
		support.NewHTTPHandler(getProfileEndpoint, http.MethodGet, o.getIssuerProfileHandler),

		// didcomm
		support.NewHTTPHandler(walletConnectEndpoint, http.MethodGet, o.walletConnect),
		support.NewHTTPHandler(generateInvitationEndpoint, http.MethodGet, o.generateInvitation),
	}
}

func (o *Operation) createIssuerProfileHandler(rw http.ResponseWriter, req *http.Request) {
	data := &issuer.ProfileData{}

	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err.Error()))

		return
	}

	profile, err := o.profileStore.GetProfile(data.ID)
	if err != nil && !errors.Is(err, storage.ErrValueNotFound) {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	if profile != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("profile %s already exists", profile.ID))

		return
	}

	if err = validateProfileRequest(data); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	err = o.profileStore.SaveProfile(data)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	rw.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(rw, data)
}

func (o *Operation) getIssuerProfileHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)[idPathParam]

	profile, err := o.profileStore.GetProfile(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	commhttp.WriteResponse(rw, profile)
}

func (o *Operation) walletConnect(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)[idPathParam]

	_, err := o.profileStore.GetProfile(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	http.Redirect(rw, req, o.uiEndpoint, http.StatusFound)
}

func (o *Operation) generateInvitation(rw http.ResponseWriter, _ *http.Request) {
	logger.Debugf("handling request to generate did-exchange invitation")

	invitation, err := o.didExClient.CreateInvitation("issuer")
	if err != nil {
		msg := fmt.Sprintf("failed to create invitation : %s", err.Error())
		logger.Errorf(msg)

		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, msg)

		return
	}

	commhttp.WriteResponse(rw, invitation)
	logger.Debugf("response: %+v", invitation)
}

func didExchangeClient(ariesCtx aries.CtxProvider) (*didexchange.Client, error) {
	didExClient, err := didexchange.New(ariesCtx)
	if err != nil {
		return nil, err
	}

	actionCh := make(chan service.DIDCommAction, 1)

	err = didExClient.RegisterActionEvent(actionCh)
	if err != nil {
		return nil, err
	}

	go service.AutoExecuteActionEvent(actionCh)

	return didExClient, nil
}

func validateProfileRequest(pr *issuer.ProfileData) error {
	if pr.ID == "" {
		return fmt.Errorf("missing profile id")
	}

	if pr.Name == "" {
		return fmt.Errorf("missing profile name")
	}

	if pr.CallbackURL == "" {
		return fmt.Errorf("missing callback url")
	}

	return nil
}
