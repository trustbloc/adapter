/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

/*
    Initial version.
*/

-- +migrate Up
CREATE TABLE end_user (
    id int PRIMARY KEY AUTO_INCREMENT,
    sub VARCHAR(255) NOT NULL
);

CREATE INDEX end_user_sub_idx ON end_user (sub);

CREATE TABLE relying_party (
    id int PRIMARY KEY AUTO_INCREMENT,
	client_id varchar(255) NOT NULL
);

create index relying_party_clientid_idx on relying_party(client_id);

CREATE TABLE oidc_request (
    id int PRIMARY KEY AUTO_INCREMENT,
    end_user_id int NOT NULL,
	relying_party_id int NOT NULL,
    scopes varchar(2000) NOT NULL,
    scopes_hash varchar(128) NOT NULL,
	pres_def text(65535),
    FOREIGN KEY (end_user_id) REFERENCES end_user(id),
    FOREIGN KEY (relying_party_id) REFERENCES relying_party(id)
);

CREATE INDEX oidc_requests_scopeshash_idx ON oidc_request(scopes_hash);

-- +migrate Down
DROP TABLE oidc_request;
DROP TABLE relying_party;
DROP TABLE end_user;