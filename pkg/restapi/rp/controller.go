/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package rp

import (
	"fmt"

	"github.com/trustbloc/edge-adapter/pkg/restapi"
	"github.com/trustbloc/edge-adapter/pkg/restapi/rp/operation"
)

// New returns new controller instance.
func New(config *operation.Config) (*Controller, error) {
	var allHandlers []restapi.Handler

	rpService, err := operation.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to init operations: %w", err)
	}

	handlers := rpService.GetRESTHandlers()

	allHandlers = append(allHandlers, handlers...)

	return &Controller{handlers: allHandlers}, nil
}

// Controller contains handlers for controller.
type Controller struct {
	handlers []restapi.Handler
}

// GetOperations returns all controller endpoints.
func (c *Controller) GetOperations() []restapi.Handler {
	return c.handlers
}
