/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/edge-adapter/pkg/internal/common/adapterutil"
	adaptervc "github.com/trustbloc/edge-adapter/pkg/vc"
)

const (
	// VerifiableCredential vc type.
	VerifiableCredential = "VerifiableCredential"

	// VerifiablePresentation vp type.
	VerifiablePresentation = "VerifiablePresentation"

	// ManifestCredentialType vc type.
	ManifestCredentialType = "IssuerManifestCredential"

	// DIDConnectCredentialType vc type.
	DIDConnectCredentialType = "DIDConnection"

	// jsonld contexts
	// TODO - should be configurable
	issuerManifestContext       = "https://trustbloc.github.io/context/vc/issuer-manifest-credential-v1.jsonld"
	consentCredentialContext    = "https://trustbloc.github.io/context/vc/consent-credential-v1.jsonld"
	verifiableCredentialContext = "https://www.w3.org/2018/credentials/v1"
)

// CreateManifestCredential creates issuer manifest credential.
func CreateManifestCredential(issuerName string, supportedContexts []string) ([]byte, error) {
	issued := time.Now()

	customFields := make(map[string]interface{})

	customFields["name"] = issuerName

	vc := &verifiable.Credential{
		Context: []string{
			verifiableCredentialContext,
			issuerManifestContext,
		},
		ID: uuid.New().URN(),
		Types: []string{
			VerifiableCredential,
			ManifestCredentialType,
		},
		Subject: &ManifestCredentialSubject{
			ID:       uuid.New().String(),
			Contexts: supportedContexts,
		},
		Issuer: verifiable.Issuer{
			ID: uuid.New().URN(),
		},
		Issued:       util.NewTime(issued),
		CustomFields: customFields,
	}

	return vc.MarshalJSON()
}

// ParseWalletResponse parses VP received from the wallet and returns the DIDConnect response.
func ParseWalletResponse(vpBytes []byte) (*DIDConnectCredentialSubject, error) {
	// TODO https://github.com/trustbloc/edge-adapter/issues/87 validate the signature
	pres, err := verifiable.ParsePresentation(vpBytes, verifiable.WithDisabledPresentationProofCheck())
	if err != nil {
		return nil, fmt.Errorf("invalid presentation: %s", err.Error())
	}

	rawCredentials, err := pres.MarshalledCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to parse the credential: %s", err.Error())
	}

	if len(rawCredentials) != 1 {
		return nil, errors.New("there should be only one credential")
	}

	// TODO https://github.com/trustbloc/edge-adapter/issues/87 validate the signature
	cred, err := verifiable.ParseCredential(rawCredentials[0], verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential : %s", err.Error())
	}

	if !adapterutil.StringsContains(DIDConnectCredentialType, cred.Types) {
		return nil, fmt.Errorf("vc doesn't contain %s type", DIDConnectCredentialType)
	}

	didConnectVC := &DIDConnectCredential{}

	err = adapterutil.DecodeJSONMarshaller(cred, didConnectVC)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential : %s", err.Error())
	}

	return didConnectVC.Subject, nil
}

// CreateConsentCredential creates consent credential.
func CreateConsentCredential(did string, docJSON []byte, rpDIDDoc *adaptervc.DIDDoc,
	userDID string) *verifiable.Credential {
	issued := time.Now()

	vc := &verifiable.Credential{
		Context: []string{
			verifiableCredentialContext,
			consentCredentialContext,
		},
		ID: uuid.New().URN(),
		Types: []string{
			VerifiableCredential,
			adaptervc.ConsentCredentialType,
		},
		Subject: &adaptervc.ConsentCredentialSubject{
			ID: uuid.New().String(),
			IssuerDIDDoc: &adaptervc.DIDDoc{
				ID:  did,
				Doc: docJSON,
			},
			RPDIDDoc: rpDIDDoc,
			UserDID:  userDID,
		},
		Issuer: verifiable.Issuer{
			ID: uuid.New().URN(),
		},
		Issued: util.NewTime(issued),
	}

	return vc
}

// CreatePresentation creates presentation to be sent to the rp.
func CreatePresentation(vc *verifiable.Credential) (*verifiable.Presentation, error) {
	return vc.Presentation()
}
