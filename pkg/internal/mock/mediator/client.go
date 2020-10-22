/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import mediatorsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"

// MockClient mock mediator client.
type MockClient struct {
	RegisterErr   error
	GetConfigFunc func(connID string) (*mediatorsvc.Config, error)
}

// Register registers with the router.
func (c *MockClient) Register(connectionID string) error {
	if c.RegisterErr != nil {
		return c.RegisterErr
	}

	return nil
}

// GetConfig gets the router config.
func (c *MockClient) GetConfig(connID string) (*mediatorsvc.Config, error) {
	return c.GetConfigFunc(connID)
}
