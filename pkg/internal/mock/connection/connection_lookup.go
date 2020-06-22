/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

// ConnectionsLookup mock connections lookup.
type ConnectionsLookup struct {
	ConnIDByDIDs    string
	ConnIDByDIDsErr error
	ConnRecord      *connection.Record
	ConnRecordErr   error
}

// GetConnectionIDByDIDs returns the connection id based on dids (my or their did) metadata.
func (c *ConnectionsLookup) GetConnectionIDByDIDs(myDID, theirDID string) (string, error) {
	switch {
	case c.ConnIDByDIDsErr != nil:
		return "", c.ConnIDByDIDsErr
	case c.ConnIDByDIDs != "":
		return c.ConnIDByDIDs, nil
	}

	return "", errors.New("invalid test setup - need either connID or error")
}

// GetConnectionRecord returns the connection record based on the connection ID.
func (c *ConnectionsLookup) GetConnectionRecord(id string) (*connection.Record, error) {
	switch {
	case c.ConnRecordErr != nil:
		return nil, c.ConnRecordErr
	case c.ConnRecord != nil:
		return c.ConnRecord, nil
	}

	return nil, errors.New("invalid test setup - need either connRecord or error")
}
