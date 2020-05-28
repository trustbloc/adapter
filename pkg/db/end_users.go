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
	sqlCreateEndUser = `
CREATE TABLE end_user (
    id int PRIMARY KEY AUTO_INCREMENT,
    sub VARCHAR(2000) NOT NULL
)`
	sqlInsertEndUser = `insert into end_user (sub) values (?)`
)

// EndUser is human user operating the User Agent and the Web Wallet.
type EndUser struct {
	ID  int64
	Sub string
}

// NewEndUsers returns a new EndUsers.
func NewEndUsers(db *sql.DB) *EndUsers {
	return &EndUsers{DB: db}
}

// EndUsers is an EndUser DAO.
type EndUsers struct {
	DB *sql.DB
}

// Insert the EndUser to the DB.
func (e *EndUsers) Insert(u *EndUser) error {
	r, err := e.DB.Exec(sqlInsertEndUser, u.Sub)
	if err != nil {
		return fmt.Errorf("failed to insert user %+v : %w", u, err)
	}

	u.ID, err = r.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to retrieve last insert id : %w", err)
	}

	return nil
}
