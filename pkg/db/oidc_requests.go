/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"database/sql"
	"fmt"
	"strings"
)

const (
	sqlCreateOidcRequest = `
CREATE TABLE oidc_request (
    id int PRIMARY KEY AUTO_INCREMENT,
    end_user_id int NOT NULL,
    scopes varchar(2000) NOT NULL,
    FOREIGN KEY (end_user_id) REFERENCES end_user(id)
)`
	sqlInsertOIDCRequest = "insert into oidc_request (end_user_id, scopes) values (?, ?)"
)

// OIDCRequest is a Relying Party's OIDC request for user data.
type OIDCRequest struct {
	ID        int64
	EndUserID int64
	Scopes    []string
}

// NewOIDCRequests returns a new OIDCRequests.
func NewOIDCRequests(db *sql.DB) *OIDCRequests {
	return &OIDCRequests{DB: db}
}

// OIDCRequests is an OIDCRequest DAO.
type OIDCRequests struct {
	DB *sql.DB
}

// Insert this oidc request to the DB.
func (o *OIDCRequests) Insert(r *OIDCRequest) error {
	result, err := o.DB.Exec(sqlInsertOIDCRequest, r.EndUserID, strings.Join(r.Scopes, ","))
	if err != nil {
		return fmt.Errorf("failed to insert oidc request %+v : %w", r, err)
	}

	r.ID, err = result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to retrieve last insert id : %w", err)
	}

	return nil
}
