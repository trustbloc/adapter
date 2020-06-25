/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package presentationex

// PresentationDefinitions presentation definitions (https://identity.foundation/presentation-exchange/).
type PresentationDefinitions struct {
	SubmissionRequirements []SubmissionRequirements `json:"submission_requirements,omitempty"`
	InputDescriptors       []InputDescriptors       `json:"input_descriptors,omitempty"`
}

// SubmissionRequirements submission requirements.
type SubmissionRequirements struct {
	Name    string `json:"name,omitempty"`
	Purpose string `json:"purpose,omitempty"`
	Rule    Rule   `json:"rule,omitempty"`
}

// Rule submission requirement rule.
type Rule struct {
	Type  string   `json:"type,omitempty"`
	Count int      `json:"count,omitempty"`
	From  []string `json:"from,omitempty"`
}

// InputDescriptors input descriptors.
type InputDescriptors struct {
	ID          string      `json:"id,omitempty"`
	Group       []string    `json:"group,omitempty"`
	Schema      Schema      `json:"schema,omitempty"`
	Constraints Constraints `json:"constraints,omitempty"`
}

// Schema input descriptor schema.
type Schema struct {
	URI     string `json:"uri,omitempty"`
	Name    string `json:"name,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

// Constraints input descriptor constraints.
type Constraints struct {
	Fields []Fields `json:"fields,omitempty"`
}

// Fields input descriptor fields.
type Fields struct {
	Path    []string `json:"path,omitempty"`
	Purpose string   `json:"purpose,omitempty"`
	Filter  Filter   `json:"filter,omitempty"`
}

// Filter input descriptor filter.
type Filter struct {
	Type      string `json:"type,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
	MinLength int    `json:"minLength,omitempty"`
	MaxLength int    `json:"maxLength,omitempty"`
}

// PresentationSubmission is the container for the descriptor_map:
// https://identity.foundation/presentation-exchange/#presentation-submission.
type PresentationSubmission struct {
	DescriptorMap []InputDescriptorMapping `json:"descriptor_map"`
}

// InputDescriptorMapping maps an InputDescriptor to a verifiable credential pointed to by the JSONPath in `Path`.
type InputDescriptorMapping struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}
