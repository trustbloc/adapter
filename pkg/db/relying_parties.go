/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"database/sql"
	"fmt"
)

const (
	sqlInsertRelyingParty         = `insert into relying_party (client_id) values (?)`
	sqlRelyingPartyFindByClientID = `select * from relying_party where client_id = ?`
)

// RelyingParty represents the relying party.
type RelyingParty struct {
	ID       int64
	ClientID string
}

// RelyingParties is a RelyingParty DAO.
type RelyingParties struct {
	DB *sql.DB
}

// NewRelyingParties returns a new RelyingParties.
func NewRelyingParties(db *sql.DB) *RelyingParties {
	return &RelyingParties{DB: db}
}

// Insert the relying party.
func (r *RelyingParties) Insert(rp *RelyingParty) error {
	result, err := r.DB.Exec(sqlInsertRelyingParty, rp.ClientID)
	if err != nil {
		return fmt.Errorf("failed to insert relying party : %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to retrieve auto generated id : %w", err)
	}

	rp.ID = id

	return nil
}

// FindByClientID returns the RelyingParty registered with the given clientID.
func (r *RelyingParties) FindByClientID(id string) (*RelyingParty, error) {
	result := &RelyingParty{}

	err := r.DB.QueryRow(sqlRelyingPartyFindByClientID, id).Scan(&result.ID, &result.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to query relying_party by client_id : %w", err)
	}

	return result, nil
}
