/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rp

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	storeName = "relyingparties"
)

// Store is the RP Adapter's store.
type Store struct {
	Store storage.Store
}

// New returns the Store.
func New(p storage.Provider) (*Store, error) {
	err := p.CreateStore(storeName)
	if err != nil && !errors.Is(err, storage.ErrDuplicateStore) {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	store, err := p.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("failed to open store : %w", err)
	}

	return &Store{Store: store}, nil
}

// SaveRP saves the RP tenant.
func (s *Store) SaveRP(rp *Tenant) error {
	bits, err := json.Marshal(rp)
	if err != nil {
		return fmt.Errorf("failed to marshal relying parth : %w", err)
	}

	return s.Store.Put(clientIDKey(rp.ClientID), bits)
}

// GetRP fetches the RP tenant with the given clientID.
func (s *Store) GetRP(clientID string) (*Tenant, error) {
	bits, err := s.Store.Get(clientIDKey(clientID))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch relying party with key %s : %w", clientID, err)
	}

	result := &Tenant{}

	err = json.Unmarshal(bits, result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal relying party data : %w", err)
	}

	return result, nil
}

// SaveUserConnection saves the user connection.
func (s *Store) SaveUserConnection(uc *UserConnection) error {
	bits, err := json.Marshal(uc)
	if err != nil {
		return fmt.Errorf("failed to marshal user connection : %w", err)
	}

	return s.Store.Put(userConnectionKey(uc.RP.ClientID, uc.User.Subject), bits)
}

// GetUserConnection fetches the connection between the given RP and user.
func (s *Store) GetUserConnection(clientID, userSub string) (*UserConnection, error) {
	bits, err := s.Store.Get(userConnectionKey(clientID, userSub))
	if err != nil {
		return nil, fmt.Errorf(""+
			"failed to fetch user connection for clientID=%s userSub=%s : %w", clientID, userSub, err)
	}

	result := &UserConnection{}

	err = json.Unmarshal(bits, result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user connection : %w", err)
	}

	return result, nil
}

func clientIDKey(id string) string {
	return fmt.Sprintf("%s_clientID_%s", storeName, id)
}

func userConnectionKey(clientID, userSub string) string {
	return fmt.Sprintf("%s_%s_%s", storeName, clientID, userSub)
}
