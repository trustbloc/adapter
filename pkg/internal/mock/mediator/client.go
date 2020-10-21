/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

// MockClient mock mediator client.
type MockClient struct {
	RegisterErr error
}

// Register registers with the router.
func (c *MockClient) Register(connectionID string) error {
	if c.RegisterErr != nil {
		return c.RegisterErr
	}

	return nil
}
