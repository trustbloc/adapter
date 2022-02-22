/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package memcmdescriptor

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
)

// CMAttachmentDescriptors defines the part of properties of credential manifest
type CMAttachmentDescriptors struct {
	OutputDesc []*cm.OutputDescriptor `json:"output_descriptor,omitempty"`
	// TODO [#Issue-612] Support for submission requirement will put whole presentation_definition here
	// instead of input_descriptor
	InputDesc []*presexch.InputDescriptor `json:"input_descriptor,omitempty"`
	Options   map[string]string           `json:"options,omitempty"`
}

// Provider provide credential attachment descriptors ops.
type Provider struct {
	cmDescriptors map[string]*CMAttachmentDescriptors
}

// New return new provider for credential manifest descriptor provider.
func New(cmDescriptorsFile io.Reader) (*Provider, error) {
	p := &Provider{
		cmDescriptors: map[string]*CMAttachmentDescriptors{},
	}

	err := json.NewDecoder(cmDescriptorsFile).Decode(&p.cmDescriptors)
	if err != nil {
		return nil, fmt.Errorf("failed to decode credential manifest descriptors file: %w", err)
	}

	for _, descriptors := range p.cmDescriptors {
		err := cm.ValidateOutputDescriptors(descriptors.OutputDesc)
		if err != nil {
			return nil, fmt.Errorf("aries-framework - failed to validate output "+
				"descriptors: %w", err)
		}

		if descriptors.InputDesc != nil {
			presDef := presexch.PresentationDefinition{ID: uuid.NewString(), InputDescriptors: descriptors.InputDesc}

			err := presDef.ValidateSchema()
			if err != nil {
				return nil, fmt.Errorf("aries-framework - failed to validate input "+
					"descriptors: %w", err)
			}
		}
	}

	return p, nil
}

// FetchCMDescriptorsByScope allows to fetch the descriptor by scope
func (p *Provider) FetchCMDescriptorsByScope(scope string) (*CMAttachmentDescriptors, bool) {
	descriptor, ok := p.cmDescriptors[scope]

	return descriptor, ok
}
