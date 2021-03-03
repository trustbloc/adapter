/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

type transientData struct {
	s storage.Store
}

func newTransientStorage(s storage.Store) *transientData {
	return &transientData{s: s}
}

func (t *transientData) Put(k string, v interface{}) error {
	bits, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal transient data : %w", err)
	}

	return t.s.Put(k, bits)
}

func (t *transientData) GetConsentRequest(k string) (*consentRequestCtx, error) {
	bits, err := t.s.Get(k)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch consentRequest with handle %s : %w", k, err)
	}

	cr := &consentRequestCtx{}

	return cr, json.Unmarshal(bits, cr)
}
