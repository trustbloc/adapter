/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package governance

// MockProvider is a mock used in tests.
type MockProvider struct {
	IssueCredentialFunc func(didID, profileID string) ([]byte, error)
	GetCredentialFunc   func(profileID string) ([]byte, error)
}

// IssueCredential issue credential.
func (s *MockProvider) IssueCredential(didID, profileID string) ([]byte, error) {
	if s.IssueCredentialFunc != nil {
		return s.IssueCredentialFunc(didID, profileID)
	}

	return nil, nil
}

// GetCredential get credential.
func (s *MockProvider) GetCredential(profileID string) ([]byte, error) {
	if s.GetCredentialFunc != nil {
		return s.GetCredentialFunc(profileID)
	}

	return nil, nil
}
