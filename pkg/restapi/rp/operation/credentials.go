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
	"github.com/trustbloc/edge-adapter/pkg/vc"
	"github.com/trustbloc/edge-adapter/pkg/vc/rp"
)

var errMalformedCredential = errors.New("malformed credential")

//nolint:unparam
func getDIDDocAndUserConsentCredentials(vpBytes []byte) (*rp.DIDDocumentCredential, *vc.UserConsentCredential, error) {
	creds, err := parseCredentials(vpBytes)
	if err != nil {
		return nil, nil, err
	}

	return parseDIDDocAndUserConsentCredentials(creds)
}

func parseCredentials(vpBytes []byte) ([2]*verifiable.Credential, error) {
	const numCredentialsRequired = 2

	vp, err := verifiable.ParsePresentation(vpBytes)
	if err != nil {
		return [2]*verifiable.Credential{},
			errors.Wrapf(errMalformedCredential, fmt.Sprintf("error parsing a verifiable presentation : %s", err))
	}

	rawCreds, err := vp.MarshalledCredentials()
	if err != nil {
		return [2]*verifiable.Credential{}, fmt.Errorf("failed to marshal credentials from vp : %w", err)
	}

	if len(rawCreds) != numCredentialsRequired {
		return [2]*verifiable.Credential{},
			errors.Wrapf(
				errMalformedCredential,
				fmt.Sprintf(
					"received %d but expecting 2 verifiable credentials in the verifiable presentation",
					len(rawCreds)))
	}

	var allCreds [2]*verifiable.Credential

	for i, raw := range rawCreds {
		cred, err := verifiable.ParseCredential(raw)
		if err != nil {
			return [2]*verifiable.Credential{},
				fmt.Errorf("failed to parse raw credential %s : %w", string(raw), err)
		}

		allCreds[i] = cred
	}

	return allCreds, nil
}

func parseDIDDocAndUserConsentCredentials(
	creds [2]*verifiable.Credential) (*rp.DIDDocumentCredential, *vc.UserConsentCredential, error) {
	var (
		issuerDIDVC *rp.DIDDocumentCredential
		consentVC   *vc.UserConsentCredential
	)

	for _, cred := range creds {
		if adapterutil.StringsContains(rp.DIDDocumentCredentialType, cred.Types) {
			if issuerDIDVC != nil {
				return nil, nil, errors.Wrapf(errMalformedCredential, "duplicate did doc credential")
			}

			issuerDIDVC = &rp.DIDDocumentCredential{}

			err := adapterutil.DecodeJSONMarshaller(cred, issuerDIDVC)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to decode did doc vc : %w", err)
			}

			continue
		}

		if adapterutil.StringsContains(vc.UserConsentCredentialType, cred.Types) {
			if consentVC != nil {
				return nil, nil, errors.Wrapf(errMalformedCredential, "duplicate user consent credential")
			}

			consentVC = &vc.UserConsentCredential{}

			err := adapterutil.DecodeJSONMarshaller(cred, consentVC)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to decode user consent credential : %w", err)
			}

			continue
		}

		return nil, nil, errors.Wrapf(errMalformedCredential, "unrecognized vc types %+v", cred.Types)
	}

	return issuerDIDVC, consentVC, nil
}

func getPresentationSubmissionVP(
	attachmentFormatID string, presentation *presentproof.Presentation) (*rp.PresentationSubmissionPresentation, error) {
	var attachmentID string

	for _, f := range presentation.Formats {
		if f.Format == attachmentFormatID {
			attachmentID = f.AttachID
		}
	}

	if attachmentID == "" {
		return nil, fmt.Errorf("no attachment found for given format %s", attachmentFormatID)
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
			errors.Wrapf(errMalformedCredential, fmt.Sprintf("failed to parse a verifiable presentation : %s", err))
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

func getAttachmentByID(id string, attachments []decorator.Attachment) *decorator.Attachment {
	for i := range attachments {
		if attachments[i].ID == id {
			return &attachments[i]
		}
	}

	return nil
}
