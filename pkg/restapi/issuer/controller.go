/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"github.com/trustbloc/edge-adapter/pkg/restapi/issuer/operation"
)

// New returns new controller instance.
func New(config *operation.Config) (*Controller, error) {
	issuerService, err := operation.New(config)
	if err != nil {
		return nil, err
	}

	handlers := issuerService.GetRESTHandlers()

	return &Controller{handlers: handlers}, nil
}

// Controller contains handlers for controller.
type Controller struct {
	handlers []operation.Handler
}

// GetOperations returns all controller endpoints.
func (c *Controller) GetOperations() []operation.Handler {
	return c.handlers
}
