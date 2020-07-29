/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package presentationex

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

const (
	// RuleTypeAll rule type all.
	RuleTypeAll = "all"
)

// Provider provide presentation exchange ops.
type Provider struct {
	inputDescriptors []InputDescriptors
}

// New return new provider for presentation exchange.
func New(inputDescriptorsFile string) (*Provider, error) {
	data, err := ioutil.ReadFile(inputDescriptorsFile) //nolint: gosec
	if err != nil {
		return nil, fmt.Errorf("failed to read input descriptors file '%s' : %w", inputDescriptorsFile, err)
	}

	var presentationDefinitions PresentationDefinitions

	if err := json.Unmarshal(data, &presentationDefinitions); err != nil {
		return nil, fmt.Errorf("failed unmarshal to input descriptors %w", err)
	}

	return &Provider{inputDescriptors: presentationDefinitions.InputDescriptors}, nil
}

// Create presentation exchange request.
func (p *Provider) Create(scopes []string) (*PresentationDefinitions, error) {
	return &PresentationDefinitions{SubmissionRequirements: []SubmissionRequirements{
		{Rule: RuleTypeAll, From: scopes}}, InputDescriptors: p.inputDescriptors}, nil
}
