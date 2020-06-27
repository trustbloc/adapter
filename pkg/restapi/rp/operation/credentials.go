/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/pkg/errors"

	"github.com/trustbloc/edge-adapter/pkg/internal/common/adapterutil"
	"github.com/trustbloc/edge-adapter/pkg/presentationex"
	"github.com/trustbloc/edge-adapter/pkg/vc"
	"github.com/trustbloc/edge-adapter/pkg/vc/rp"
)

var errInvalidCredential = errors.New("malformed credential")

func parseWalletResponse(
	definitions *presentationex.PresentationDefinitions, vpBytes []byte) (*vc.UserConsentCredential, error) {
	vp, err := verifiable.ParsePresentation(vpBytes)
	if err != nil {
		return nil, errors.Wrapf(
			errInvalidCredential, fmt.Sprintf("error parsing a verifiable presentation : %s", err))
	}

	// TODO pass presentation definitions
	err = evaluatePresentationSubmission(definitions, vp)
	if err != nil {
		return nil, errors.Wrapf(errInvalidCredential, "invalid presentation submission : %s", err)
	}

	rawCreds, err := vp.MarshalledCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credentials from vp : %w", err)
	}

	var base *verifiable.Credential

	for i := range rawCreds {
		raw := rawCreds[i]

		cred, parseErr := verifiable.ParseCredential(raw)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse raw credential %s : %w", string(raw), parseErr)
		}

		if adapterutil.StringsContains(vc.UserConsentCredentialType, cred.Types) {
			base = cred
			break
		}

		logger.Warnf("ignoring credential with unrecognized types: %+v", cred.Types)
	}

	if base == nil {
		return nil, errors.Wrapf(
			errInvalidCredential, "no suitable credential of type %s found", vc.UserConsentCredentialType)
	}

	consentVC := &vc.UserConsentCredential{Base: base}

	err = adapterutil.DecodeJSONMarshaller(base, consentVC)
	if err != nil {
		return nil, fmt.Errorf("unable to decode user consent credential : %w", err)
	}

	return consentVC, nil
}

func parseIssuerResponse(definitions *presentationex.PresentationDefinitions,
	presentation *presentproof.Presentation) (*rp.PresentationSubmissionPresentation, error) {
	var attachmentID string

	for _, f := range presentation.Formats {
		if f.Format == presentationSubmissionFormat {
			attachmentID = f.AttachID
		}
	}

	if attachmentID == "" {
		return nil, fmt.Errorf("no attachment found with expected format %s", presentationSubmissionFormat)
	}

	a := getAttachmentByID(attachmentID, presentation.PresentationsAttach)
	if a == nil {
		return nil, fmt.Errorf("attachment referenced by ID %s from a format was not found", attachmentID)
	}

	vpBytes, err := a.Data.Fetch()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch contents of attachment with id %s : %w", attachmentID, err)
	}

	vp, err := verifiable.ParsePresentation(vpBytes)
	if err != nil {
		return nil,
			errors.Wrapf(errInvalidCredential, fmt.Sprintf("failed to parse a verifiable presentation : %s", err))
	}

	err = evaluatePresentationSubmission(definitions, vp)
	if err != nil {
		return nil, errors.Wrapf(errInvalidCredential, "invalid presentation submission : %s", err)
	}

	presentationSubmissionVP := &rp.PresentationSubmissionPresentation{
		Base: vp,
	}

	err = adapterutil.DecodeJSONMarshaller(vp, presentationSubmissionVP)
	if err != nil {
		return nil, fmt.Errorf("failed to decode presentation_submission VP : %w", err)
	}

	return presentationSubmissionVP, nil
}

// TODO validate presentation_submission against presentation_definitions
//  https://github.com/trustbloc/edge-adapter/issues/108
func evaluatePresentationSubmission(_ *presentationex.PresentationDefinitions, vp *verifiable.Presentation) error {
	if !adapterutil.StringsContains(rp.PresentationSubmissionPresentationType, vp.Type) {
		return errors.Wrapf(errInvalidCredential, "unexpected verifiable presentation type: %+v", vp.Type)
	}

	submission := &rp.PresentationSubmissionPresentation{
		Base: vp,
	}

	return adapterutil.DecodeJSONMarshaller(vp, submission)
}

func getAttachmentByID(id string, attachments []decorator.Attachment) *decorator.Attachment {
	for i := range attachments {
		if attachments[i].ID == id {
			return &attachments[i]
		}
	}

	return nil
}
