/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"

	"github.com/trustbloc/edge-adapter/pkg/internal/common/adapterutil"
	"github.com/trustbloc/edge-adapter/pkg/vc"
)

var errInvalidCredential = errors.New("malformed credential")

func parseWalletResponse(definitions *presexch.PresentationDefinition, vdriReg vdrapi.Registry,
	vpBytes []byte, docLoader ld.DocumentLoader) (local, remote map[string]*verifiable.Credential, err error) {
	vp, err := verifiable.ParsePresentation(
		vpBytes,
		verifiable.WithPresPublicKeyFetcher(verifiable.NewVDRKeyResolver(vdriReg).PublicKeyFetcher()),
		verifiable.WithPresJSONLDDocumentLoader(docLoader),
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%w: parseWalletResponse: failed to parse verifiable presentation: %s", errInvalidCredential, err.Error())
	}

	// TODO unable to verify credential proofs inside wallet's verifiable presentation - should remove the
	//  'WithDisabledCredProofCheck()' once we can: https://github.com/trustbloc/edge-adapter/issues/300
	matched, err := definitions.Match(
		vp, docLoader,
		presexch.WithCredentialOptions(
			verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(vdriReg).PublicKeyFetcher()),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(docLoader),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%w: parseWalletResponse: invalid presentation submission: %s", errInvalidCredential, err.Error())
	}

	local = make(map[string]*verifiable.Credential)
	remote = make(map[string]*verifiable.Credential)

	for id, cred := range matched {
		if !adapterutil.StringsContains(vc.AuthorizationCredentialType, cred.Types) {
			local[id] = cred

			continue
		}

		err := evaluateAuthorizationCredential(cred)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"%w: parseWalletResponse: invalid authorization credential: %s", errInvalidCredential, err.Error())
		}

		remote[id] = cred
	}

	return local, remote, nil
}

// TODO validate issuer's response against presentation_definitions
//  https://github.com/trustbloc/edge-adapter/issues/108
func parseIssuerResponse(pres *presentproof.Presentation,
	vdriReg vdrapi.Registry, docLoader ld.DocumentLoader) (*verifiable.Credential, error) {
	if len(pres.PresentationsAttach) == 0 {
		return nil, fmt.Errorf("%w: expected at least 1 attachment but got 0", errInvalidCredential)
	}

	attachment := pres.PresentationsAttach[0]

	vpBytes, err := attachment.Data.Fetch()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch contents of attachment with id %s : %w", attachment.ID, err)
	}

	vp, err := verifiable.ParsePresentation(
		vpBytes,
		verifiable.WithPresPublicKeyFetcher(verifiable.NewVDRKeyResolver(vdriReg).PublicKeyFetcher()),
		verifiable.WithPresJSONLDDocumentLoader(docLoader),
	)
	if err != nil {
		return nil,
			fmt.Errorf("%w: failed to parse verifiable presentation %s: %s", errInvalidCredential, vpBytes, err.Error())
	}

	if len(vp.Credentials()) != 1 {
		return nil, fmt.Errorf(
			"%w: expected one credential in the issuer's VP but got %d", errInvalidCredential, len(vp.Credentials()))
	}

	rawCred, err := vp.MarshalledCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal issuer's vp credentials: %w", err)
	}

	data, err := verifiable.ParseCredential(
		rawCred[0],
		verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(vdriReg).PublicKeyFetcher()),
		verifiable.WithJSONLDDocumentLoader(docLoader),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer's credential: %w", err)
	}

	return data, nil
}

func getPresentationSubmissionCredentials(pres *presentproof.Presentation, definitions *presexch.PresentationDefinition,
	vdriReg vdrapi.Registry, docLoader ld.DocumentLoader) (map[string]*verifiable.Credential, error) {
	if len(pres.PresentationsAttach) == 0 {
		return nil, fmt.Errorf("no presentation attachments")
	}

	attachment := pres.PresentationsAttach[0]

	vpBytes, err := attachment.Data.Fetch()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch contents of attachment with id %s : %w", attachment.ID, err)
	}

	vp, err := verifiable.ParsePresentation(
		vpBytes,
		verifiable.WithPresPublicKeyFetcher(verifiable.NewVDRKeyResolver(vdriReg).PublicKeyFetcher()),
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(docLoader),
	)
	if err != nil {
		return nil,
			fmt.Errorf("%w: failed to parse verifiable presentation %s: %s", errInvalidCredential, vpBytes, err.Error())
	}

	matched, err := definitions.Match(
		vp, docLoader,
		presexch.WithCredentialOptions(
			verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(vdriReg).PublicKeyFetcher()),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(docLoader),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid presentation submission: %w", err)
	}

	// return data
	return matched, nil
}

func evaluateAuthorizationCredential(c *verifiable.Credential) error {
	authZ, err := vc.AuthZSubject(c)
	if err != nil {
		return fmt.Errorf("unable to decode authorization credential: %w", err)
	}

	if authZ.IssuerDIDDoc == nil || authZ.IssuerDIDDoc.Doc == nil {
		return errors.New("authorization credential missing issuer did doc") // nolint:wrapcheck // false positive
	}

	return nil
}
