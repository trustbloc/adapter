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
	sqlInsertEndUser      = `insert into end_user (sub) values (?)`
	sqlSelectEndUserBySub = `select * from end_user where sub = ?`
)

// EndUser is the human user operating the User Agent and the Web Wallet.
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

// FindBySub returns an EndUser with the given subject.
func (e *EndUsers) FindBySub(s string) (*EndUser, error) {
	result := &EndUser{}

	err := e.DB.QueryRow(sqlSelectEndUserBySub, s).Scan(&result.ID, &result.Sub)
	if err != nil {
		return nil, fmt.Errorf("failed to query user by sub : %w", err)
	}

	return result, nil
}
