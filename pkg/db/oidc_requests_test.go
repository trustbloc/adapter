/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"database/sql"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-adapter/pkg/presentationex"
)

func TestOIDCRequests_Insert(t *testing.T) {
	t.Run("inserts request", func(t *testing.T) {
		db := newDB(t)

		user := &EndUser{Sub: "test"}
		rp := &RelyingParty{ClientID: uuid.New().String()}
		err := NewEndUsers(db).Insert(user)
		require.NoError(t, err)
		err = NewRelyingParties(db).Insert(rp)
		require.NoError(t, err)

		expected := &OIDCRequest{
			EndUserID:      user.ID,
			RelyingPartyID: rp.ID,
			Scopes:         []string{"foo", "bar"},
			PresDef:        presDefs(),
		}

		err = NewOIDCRequests(db).Insert(expected)
		require.NoError(t, err)
		require.NotZero(t, expected.ID)
		verifyOidcRequest(t, expected, db)
	})

	t.Run("cannot insert request without relation to user and relying_party", func(t *testing.T) {
		expected := &OIDCRequest{
			Scopes: []string{"foo", "bar"},
		}
		db := newDB(t)
		o := NewOIDCRequests(db)

		err := o.Insert(expected)
		require.Error(t, err)
	})
}

func TestOIDCRequests_FindBySubRPClientIDAndScopes(t *testing.T) {
	t.Run("returns oidc request", func(t *testing.T) {
		user := &EndUser{Sub: uuid.New().String()}
		rp := &RelyingParty{ClientID: uuid.New().String()}

		db := newDB(t)
		err := NewEndUsers(db).Insert(user)
		require.NoError(t, err)
		err = NewRelyingParties(db).Insert(rp)
		require.NoError(t, err)

		expected := &OIDCRequest{
			EndUserID:      user.ID,
			RelyingPartyID: rp.ID,
			Scopes:         []string{"foo", "bar"},
			PresDef:        presDefs(),
		}

		err = NewOIDCRequests(db).Insert(expected)
		require.NoError(t, err)

		result, err := NewOIDCRequests(db).FindBySubRPClientIDAndScopes(user.Sub, rp.ClientID, expected.Scopes)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("fails if db is closed", func(t *testing.T) {
		db := newDB(t)
		err := db.Close()
		require.NoError(t, err)

		_, err = NewOIDCRequests(db).FindBySubRPClientIDAndScopes("abc", "123", []string{"xyz"})
		require.Error(t, err)
	})
}

func TestNewOIDCRequests_Update(t *testing.T) {
	t.Run("updates request", func(t *testing.T) {
		db := newDB(t)

		req := newPersistedOIDCRequest(t, db)
		req.Scopes = []string{uuid.New().String()}
		req.PresDef.InputDescriptors[0].ID = uuid.New().String()

		err := NewOIDCRequests(db).Update(req)
		require.NoError(t, err)
		verifyOidcRequest(t, req, db)
	})

	t.Run("fails if db is closed", func(t *testing.T) {
		db := newDB(t)
		err := db.Close()
		require.NoError(t, err)
		err = NewOIDCRequests(db).Update(&OIDCRequest{
			EndUserID:      rand.Int63(),
			RelyingPartyID: rand.Int63(),
			Scopes:         []string{uuid.New().String()},
		})
		require.Error(t, err)
	})
}

func verifyOidcRequest(t *testing.T, expected *OIDCRequest, db *sql.DB) {
	result := &OIDCRequest{}

	var (
		scopes     string
		scopesHash string
		presDef    string
	)

	err := db.QueryRow("select * from oidc_request where id = ?", expected.ID).
		Scan(&result.ID, &result.EndUserID, &result.RelyingPartyID, &scopes, &scopesHash, &presDef)
	require.NoError(t, err)

	result.Scopes = strings.Split(scopes, ",")
	result.PresDef = &presentationex.PresentationDefinitions{}

	err = json.Unmarshal([]byte(presDef), result.PresDef)
	require.NoError(t, err)

	require.Equal(t, expected, result)
}

func presDefs() *presentationex.PresentationDefinitions {
	return &presentationex.PresentationDefinitions{
		SubmissionRequirements: []presentationex.SubmissionRequirements{{
			Name:    "test",
			Purpose: "purpose",
			Rule: presentationex.Rule{
				Type:  "123",
				Count: 54,
				From:  []string{"bob"},
			},
		}},
		InputDescriptors: []presentationex.InputDescriptors{{
			ID:    uuid.New().String(),
			Group: []string{"test"},
			Schema: presentationex.Schema{
				URI:     "http://example.com/uri/1",
				Name:    "alice",
				Purpose: "testing",
			},
			Constraints: presentationex.Constraints{
				Fields: []presentationex.Fields{{
					Path:    []string{"abc"},
					Purpose: "xyz",
					Filter: presentationex.Filter{
						Type:      "a-filter",
						Pattern:   "this one",
						MinLength: 5,
						MaxLength: 100,
					},
				}},
			},
		}},
	}
}

func newPersistedOIDCRequest(t *testing.T, db *sql.DB) *OIDCRequest {
	user := &EndUser{Sub: "test"}
	rp := &RelyingParty{ClientID: uuid.New().String()}
	err := NewEndUsers(db).Insert(user)
	require.NoError(t, err)
	err = NewRelyingParties(db).Insert(rp)
	require.NoError(t, err)

	request := &OIDCRequest{
		EndUserID:      user.ID,
		RelyingPartyID: rp.ID,
		Scopes:         []string{"foo", "bar"},
		PresDef:        presDefs(),
	}

	err = NewOIDCRequests(db).Insert(request)
	require.NoError(t, err)

	return request
}
