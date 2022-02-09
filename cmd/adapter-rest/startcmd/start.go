/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	arieslog "github.com/hyperledger/aries-framework-go/pkg/common/log"
	ldrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	ariesld "github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	ldsvc "github.com/hyperledger/aries-framework-go/pkg/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/edge-adapter/pkg/did"
	"github.com/trustbloc/edge-adapter/pkg/hydra"
	"github.com/trustbloc/edge-adapter/pkg/ld"
	"github.com/trustbloc/edge-adapter/pkg/presentationex"
	"github.com/trustbloc/edge-adapter/pkg/restapi/healthcheck"
	"github.com/trustbloc/edge-adapter/pkg/restapi/issuer"
	issuerops "github.com/trustbloc/edge-adapter/pkg/restapi/issuer/operation"
	"github.com/trustbloc/edge-adapter/pkg/restapi/rp"
	rpops "github.com/trustbloc/edge-adapter/pkg/restapi/rp/operation"
)

var logger = log.New("edge-adapter")

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the adapter-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "ADAPTER_REST_HOST_URL"

	externalURLFlagName  = "external-url"
	externalURLEnvKey    = "ADAPTER_REST_EXTERNAL_URL"
	externalURLFlagUsage = "URL that the adapter-rest instance is exposed on. " +
		" Alternatively, this can be set with the following environment variable: " + externalURLEnvKey

	datasourceNameFlagName  = "dsn"
	datasourceNameFlagUsage = "Datasource Name with credentials if required." +
		" Format must be <driver>:[//]<driver-specific-dsn>." +
		" Examples: 'mysql://root:secret@tcp(localhost:3306)/adapter', 'mem://test'," +
		" 'mongodb://mongodb.example.com:27017'. Supported drivers are [mem, mysql, mongodb]." +
		" Alternatively, this can be set with the following environment variable: " + datasourceNameEnvKey
	datasourceNameEnvKey = "ADAPTER_REST_DSN"

	datasourceTimeoutFlagName  = "dsn-timeout"
	datasourceTimeoutFlagUsage = "Total time in seconds to wait until the datasource is available before giving up." +
		" Default: " + string(rune(datasourceTimeoutDefault)) + " seconds." +
		" Alternatively, this can be set with the following environment variable: " + datasourceTimeoutEnvKey
	datasourceTimeoutEnvKey  = "ADAPTER_REST_DSN_TIMEOUT"
	datasourceTimeoutDefault = 30

	oidcProviderURLFlagName  = "op-url"
	oidcProviderURLFlagUsage = "URL for the OIDC provider." +
		"Alternatively, this can be set with the following environment variable: " + oidcProviderEnvKey
	oidcProviderEnvKey = "ADAPTER_REST_OP_URL"

	staticFilesPathFlagName  = "static-path"
	staticFilesPathFlagUsage = "Path to the folder where the static files are to be hosted under " + uiEndpoint + "." +
		"Alternatively, this can be set with the following environment variable: " + staticFilesPathEnvKey
	staticFilesPathEnvKey = "ADAPTER_REST_STATIC_FILES"

	cmOutputDescriptorsFilePathFlagName  = "output-descriptors-path"
	cmOutputDescriptorsFilePathFlagUsage = "Path to the output descriptors file of credential manifests " +
		"supported by the adapter'" + "Alternatively, this can be set with the following " +
		"environment variable: " + cmOutputDescriptorsFilePathEnvKey
	cmOutputDescriptorsFilePathEnvKey = "ADAPTER_REST_CM_DESCRIPTORS_FILE"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "ADAPTER_REST_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "ADAPTER_REST_TLS_CACERTS"

	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "Path to the server certificate to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = "ADAPTER_REST_TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "Path to the private key to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = "ADAPTER_REST_TLS_SERVE_KEY"

	presentationDefinitionsFlagName  = "presentation-definitions-file"
	presentationDefinitionsFlagUsage = "Path to presentation definitions file with input_descriptors."
	presentationDefinitionsEnvKey    = "ADAPTER_REST_PRESENTATION_DEFINITIONS_FILE"

	hydraURLFlagName  = "hydra-url"
	hydraURLFlagUsage = "Base URL to the hydra service." +
		"Alternatively, this can be set with the following environment variable: " + hydraURLEnvKey
	hydraURLEnvKey = "ADAPTER_REST_HYDRA_URL"

	modeFlagName  = "mode"
	modeFlagUsage = "Mode in which the edge-adapter service will run. Possible values: " +
		"['issuer', 'rp']."
	modeEnvKey = "ADAPTER_REST_MODE"

	// AES256GCM symmetric key file for encrypting data in the oidc client store
	issuerOIDCClientStoreKeyFlagName  = "oidc-store-key"
	issuerOIDCClientStoreKeyEnvKey    = "OIDC_STORE_KEY"
	issuerOIDCClientStoreKeyFlagUsage = "Symmetric key file for encrypting data " +
		"in the issuer adapter's oidc client store. " +
		"Alternatively, this can be set with the following environment variable: " + issuerOIDCClientStoreKeyEnvKey

	// inbound host url flag
	didCommInboundHostFlagName  = "didcomm-inbound-host"
	didCommInboundHostEnvKey    = "ADAPTER_REST_DIDCOMM_INBOUND_HOST"
	didCommInboundHostFlagUsage = "Inbound Host Name:Port. This is used internally to start the didcomm server." +
		" Alternatively, this can be set with the following environment variable: " + didCommInboundHostEnvKey

	// inbound host external url flag
	didCommInboundHostExternalFlagName  = "didcomm-inbound-host-external"
	didCommInboundHostExternalEnvKey    = "ADAPTER_REST_DIDCOMM_INBOUND_HOST_EXTERNAL"
	didCommInboundHostExternalFlagUsage = "Inbound Host External Name:Port." +
		" This is the URL for the inbound server as seen externally." +
		" If not provided, then the internal inbound host will be used here." +
		" Alternatively, this can be set with the following environment variable: " + didCommInboundHostExternalEnvKey

	trustblocDomainFlagName  = "dids-trustbloc-domain"
	trustblocDomainEnvKey    = "ADAPTER_REST_TRUSTBLOC_DOMAIN"
	trustblocDomainFlagUsage = "URL to the did:trustbloc consortium's domain." +
		" Alternatively, this can be set with the following environment variable: " + trustblocDomainEnvKey

	universalResolverURLFlagName      = "universal-resolver-url"
	universalResolverURLFlagShorthand = "r"
	universalResolverURLFlagUsage     = "Universal Resolver instance is running on. Format: HostName:Port."
	universalResolverURLEnvKey        = "ADAPTER_REST_UNIVERSAL_RESOLVER_URL"

	logLevelFlagName  = "log-level"
	logLevelFlagUsage = "Sets the logging level." +
		" Possible values are [DEBUG, INFO, WARNING, ERROR, CRITICAL] (default is INFO)." +
		" Alternatively, this can be set with the following environment variable: " + logLevelEnvKey
	logLevelEnvKey = "ADAPTER_REST_LOGLEVEL"

	requestTokensFlagName  = "request-tokens"
	requestTokensEnvKey    = "ADAPTER_REST_REQUEST_TOKENS" // nolint: gosec
	requestTokensFlagUsage = "Tokens used for http request " +
		" Alternatively, this can be set with the following environment variable: " + requestTokensEnvKey

	walletAppURLFlagName  = "wallet-app-url"
	walletAppURLFlagUsage = "A deep link pointing to wallet application(s) which will be " +
		"used by this adapter to send credential request to remote wallets ." +
		" Alternatively, this can be set with the following environment variable: " + walletAppURLEnvKey
	walletAppURLEnvKey = "ADAPTER_REST_WALLET_APP_URL"

	didAnchorOriginFlagName  = "did-anchor-origin"
	didAnchorOriginEnvKey    = "ADAPTER_REST_DID_ANCHOR_ORIGIN"
	didAnchorOriginFlagUsage = "DID anchor origin." +
		" Alternatively, this can be set with the following environment variable: " + didAnchorOriginEnvKey

	// remote JSON-LD context provider url flag.
	contextProviderFlagName  = "context-provider-url"
	contextProviderEnvKey    = "ADAPTER_REST_CONTEXT_PROVIDER_URL"
	contextProviderFlagUsage = "Remote context provider URL to get JSON-LD contexts from." +
		" This flag can be repeated, allowing setting up multiple context providers." +
		" Alternatively, this can be set with the following environment variable (in CSV format): " +
		contextProviderEnvKey

	// default verification key type flag.
	keyTypeFlagName  = "key-type"
	keyTypeEnvKey    = "ADAPTER_REST_KEY_TYPE"
	keyTypeFlagUsage = "Default key type for adapter." +
		" This flag sets the verification (and for DIDComm V1 encryption as well) key type used for key creation " +
		"in the adapter. Alternatively, this can be set with the following environment variable: " +
		keyTypeEnvKey

	// default key agreement type flag.
	keyAgreementTypeFlagName  = "key-agreement-type"
	keyAgreementTypeEnvKey    = "ADAPTER_REST_KEY_AGREEMENT_TYPE"
	keyAgreementTypeFlagUsage = "Default key agreement type for adapter." +
		" Default encryption (used in DIDComm V2) key type used for key agreement creation in the adapter." +
		" Alternatively, this can be set with the following environment variable: " +
		keyAgreementTypeEnvKey

	// default key agreement type flag.
	mediaTypeProfileFlagName  = "media-type-profiles"
	mediaTypeProfileEnvKey    = "ADAPTER_REST_MEDIA_TYPE_PROFILES"
	mediaTypeProfileFlagUsage = "Media type profiles for adapter." +
		" Alternatively, this can be set with the following environment variable: " +
		mediaTypeProfileEnvKey
)

// Database types
const (
	databaseTypeMemOption     = "mem"
	databaseTypeMySQLOption   = "mysql"
	databaseTypeMongoDBOption = "mongodb"
)

// API endpoints.
const (
	uiEndpoint = "/ui"

	// modes
	issuerMode = "issuer"
	rpMode     = "rp"
)

const (
	rpAdapterPersistentStorePrefix = "rpadapter"
	rpAdapterTransientStorePrefix  = "rpadapter_txn"
	issuerAdapterStorePrefix       = "issueradapter"
	tokenLength                    = 2
	sleep                          = 1 * time.Second
)

const (
	confErrMsg = "configuration failed: %w"
)

// nolint:gochecknoglobals
var supportedStorageProviders = map[string]func(string, string) (storage.Provider, error){
	databaseTypeMySQLOption: func(dsn, prefix string) (storage.Provider, error) {
		return mysql.NewProvider(dsn, mysql.WithDBPrefix(prefix)) // nolint:wrapcheck // reduce cyclo
	},
	databaseTypeMemOption: func(_, _ string) (storage.Provider, error) { // nolint:unparam
		return mem.NewProvider(), nil
	},
	databaseTypeMongoDBOption: func(dsn, prefix string) (storage.Provider, error) {
		return mongodb.NewProvider(dsn, mongodb.WithDBPrefix(prefix)) // nolint:wrapcheck // reduce cyclo
	},
}

type tlsParameters struct {
	systemCertPool bool
	caCerts        []string
	serveCertPath  string
	serveKeyPath   string
}

type didCommParameters struct {
	inboundHostInternal string
	inboundHostExternal string
	keyType             string
	keyAgreementType    string
	mediaTypeProfiles   []string
}

type dsnParams struct {
	dsn     string
	timeout uint64
}

type adapterRestParameters struct {
	hostURL                     string
	tlsParams                   *tlsParameters
	dsnParams                   *dsnParams
	oidcProviderURL             string
	staticFiles                 string
	presentationDefinitionsFile string
	// TODO assuming same base path for all hydra endpoints for now
	hydraURL                    string
	mode                        string
	didCommParameters           *didCommParameters // didcomm
	trustblocDomain             string
	universalResolverURL        string
	requestTokens               map[string]string
	walletAppURL                string
	oidcClientDBKeyPath         string
	externalURL                 string
	didAnchorOrigin             string
	contextProviderURLs         []string
	cmOutputDescriptorsFilePath string
}

type server interface {
	ListenAndServe(host, certFile, keyFile string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	if certFile == "" || keyFile == "" {
		return http.ListenAndServe(host, router) // nolint:wrapcheck // reduce cyclo
	}

	return http.ListenAndServeTLS(host, certFile, keyFile, router) // nolint:wrapcheck // reduce cyclo
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start adapter-rest",
		Long:  "Start adapter-rest inside the edge-adapter",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getAdapterRestParameters(cmd)
			if err != nil {
				return fmt.Errorf("failed to configure adapter: %w", err)
			}

			return startAdapterService(parameters, srv)
		},
	}
}

//nolint:funlen,gocyclo,cyclop
func getAdapterRestParameters(cmd *cobra.Command) (*adapterRestParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	tlsParams, err := getTLS(cmd)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	dsnParams, err := getDsnParams(cmd)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	externalURL, err := cmdutils.GetUserSetVarFromString(cmd, externalURLFlagName, externalURLEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	oidcURL, err := cmdutils.GetUserSetVarFromString(cmd, oidcProviderURLFlagName, oidcProviderEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	staticFiles, err := cmdutils.GetUserSetVarFromString(cmd, staticFilesPathFlagName, staticFilesPathEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	outputDescriptorsFilePath, err := cmdutils.GetUserSetVarFromString(cmd, cmOutputDescriptorsFilePathFlagName,
		cmOutputDescriptorsFilePathEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	mode, err := cmdutils.GetUserSetVarFromString(cmd, modeFlagName, modeEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	presentationDefinitionsFile, err := cmdutils.GetUserSetVarFromString(cmd, presentationDefinitionsFlagName,
		presentationDefinitionsEnvKey, mode != rpMode)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	hydraURL, err := cmdutils.GetUserSetVarFromString(cmd, hydraURLFlagName, hydraURLEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	issuerOIDCKeyPath, err := cmdutils.GetUserSetVarFromString(cmd, issuerOIDCClientStoreKeyFlagName,
		issuerOIDCClientStoreKeyEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	// didcomm
	didCommParameters := getDIDCommParams(cmd)

	trustblocDomain, err := cmdutils.GetUserSetVarFromString(cmd, trustblocDomainFlagName, trustblocDomainEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	universalResolverURL, err := cmdutils.GetUserSetVarFromString(cmd, universalResolverURLFlagName,
		universalResolverURLEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	logLevel, err := cmdutils.GetUserSetVarFromString(cmd, logLevelFlagName, logLevelEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	requestTokens, err := getRequestTokens(cmd)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	err = setLogLevel(logLevel)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	walletAppURL, err := cmdutils.GetUserSetVarFromString(cmd, walletAppURLFlagName, walletAppURLEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	didAnchorOrigin := cmdutils.GetUserSetOptionalVarFromString(cmd, didAnchorOriginFlagName, didAnchorOriginEnvKey)

	logger.Infof("logger level set to %s", logLevel)

	contextProviderURLs, err := cmdutils.GetUserSetVarFromArrayString(cmd, contextProviderFlagName,
		contextProviderEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	return &adapterRestParameters{
		hostURL:                     hostURL,
		tlsParams:                   tlsParams,
		dsnParams:                   dsnParams,
		oidcProviderURL:             oidcURL,
		staticFiles:                 staticFiles,
		presentationDefinitionsFile: presentationDefinitionsFile,
		hydraURL:                    hydraURL,
		mode:                        mode,
		didCommParameters:           didCommParameters,
		trustblocDomain:             trustblocDomain,
		universalResolverURL:        universalResolverURL,
		requestTokens:               requestTokens,
		walletAppURL:                walletAppURL,
		oidcClientDBKeyPath:         issuerOIDCKeyPath,
		externalURL:                 externalURL,
		didAnchorOrigin:             didAnchorOrigin,
		contextProviderURLs:         contextProviderURLs,
		cmOutputDescriptorsFilePath: outputDescriptorsFilePath,
	}, nil
}

func getRequestTokens(cmd *cobra.Command) (map[string]string, error) {
	requestTokens, err := cmdutils.GetUserSetVarFromArrayString(cmd, requestTokensFlagName,
		requestTokensEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	tokens := make(map[string]string)

	for _, token := range requestTokens {
		split := strings.Split(token, "=")
		switch len(split) {
		case tokenLength:
			tokens[split[0]] = split[1]
		default:
			logger.Warnf("invalid token '%s'", token)
		}
	}

	return tokens, nil
}

func setLogLevel(logLevel string) error {
	if logLevel == "" {
		logLevel = "INFO"
	}

	err := setEdgeCoreLogLevel(logLevel)
	if err != nil {
		return fmt.Errorf(confErrMsg, err)
	}

	return setAriesFrameworkLogLevel(logLevel)
}

func setEdgeCoreLogLevel(logLevel string) error {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		return fmt.Errorf("failed to parse log level '%s' : %w", logLevel, err)
	}

	log.SetLevel("", level)

	return nil
}

func setAriesFrameworkLogLevel(logLevel string) error {
	level, err := arieslog.ParseLevel(logLevel)
	if err != nil {
		return fmt.Errorf("failed to parse log level '%s' : %w", logLevel, err)
	}

	arieslog.SetLevel("", level)

	return nil
}

func getDsnParams(cmd *cobra.Command) (*dsnParams, error) {
	params := &dsnParams{}

	var err error

	params.dsn, err = cmdutils.GetUserSetVarFromString(cmd, datasourceNameFlagName, datasourceNameEnvKey, false)
	if err != nil {
		return nil, fmt.Errorf("failed to configure dsn: %w", err)
	}

	// TODO GetUserSetVarFromString logic should be revised: https://github.com/trustbloc/edge-core/issues/50
	timeout, err := cmdutils.GetUserSetVarFromString(cmd, datasourceTimeoutFlagName, datasourceTimeoutEnvKey, true)
	if err != nil && !strings.Contains(err.Error(), "value is empty") {
		return nil, fmt.Errorf("failed to configure dsn timeout: %w", err)
	}

	if timeout == "" {
		timeout = string(rune(datasourceTimeoutDefault))
	}

	t, err := strconv.Atoi(timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dsn timeout %s: %w", timeout, err)
	}

	params.timeout = uint64(t)

	return params, nil
}

func getDIDCommParams(cmd *cobra.Command) *didCommParameters {
	inboundHostInternal := cmdutils.GetUserSetOptionalVarFromString(cmd, didCommInboundHostFlagName,
		didCommInboundHostEnvKey)

	inboundHostExternal := cmdutils.GetUserSetOptionalVarFromString(cmd, didCommInboundHostExternalFlagName,
		didCommInboundHostExternalEnvKey)

	keyType := cmdutils.GetUserSetOptionalVarFromString(cmd, keyTypeFlagName, keyTypeEnvKey)

	keyAgreementType := cmdutils.GetUserSetOptionalVarFromString(cmd, keyAgreementTypeFlagName,
		keyAgreementTypeEnvKey)

	mediaTypeProfiles := cmdutils.GetUserSetOptionalVarFromArrayString(cmd,
		mediaTypeProfileFlagName, mediaTypeProfileEnvKey)

	return &didCommParameters{
		inboundHostInternal: inboundHostInternal,
		inboundHostExternal: inboundHostExternal,
		keyType:             keyType,
		keyAgreementType:    keyAgreementType,
		mediaTypeProfiles:   mediaTypeProfiles,
	}
}

func getTLS(cmd *cobra.Command) (*tlsParameters, error) {
	tlsSystemCertPoolString, err := cmdutils.GetUserSetVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf(confErrMsg, err)
	}

	tlsSystemCertPool := false
	if tlsSystemCertPoolString != "" {
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return nil, fmt.Errorf(confErrMsg, err)
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey)

	tlsServeCertPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsServeCertPathFlagName, tlsServeCertPathEnvKey)

	tlsServeKeyPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsServeKeyPathFlagName, tlsServeKeyPathFlagEnvKey)

	return &tlsParameters{
		systemCertPool: tlsSystemCertPool,
		caCerts:        tlsCACerts,
		serveCertPath:  tlsServeCertPath,
		serveKeyPath:   tlsServeKeyPath,
	}, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	startCmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)
	startCmd.Flags().StringP(oidcProviderURLFlagName, "", "", oidcProviderURLFlagUsage)
	startCmd.Flags().StringP(datasourceNameFlagName, "", "", datasourceNameFlagUsage)
	startCmd.Flags().StringP(datasourceTimeoutFlagName, "", "", datasourceTimeoutFlagUsage)
	startCmd.Flags().StringP(staticFilesPathFlagName, "", "", staticFilesPathFlagUsage)
	startCmd.Flags().StringP(cmOutputDescriptorsFilePathFlagName, "", "", cmOutputDescriptorsFilePathFlagUsage)
	startCmd.Flags().StringP(presentationDefinitionsFlagName, "", "", presentationDefinitionsFlagUsage)
	startCmd.Flags().StringP(hydraURLFlagName, "", "", hydraURLFlagUsage)
	startCmd.Flags().StringP(modeFlagName, "", "", modeFlagUsage)
	startCmd.Flags().StringArrayP(requestTokensFlagName, "", []string{}, requestTokensFlagUsage)

	// didcomm
	startCmd.Flags().StringP(didCommInboundHostFlagName, "", "", didCommInboundHostFlagUsage)
	startCmd.Flags().StringP(didCommInboundHostExternalFlagName, "", "", didCommInboundHostExternalFlagUsage)
	startCmd.Flags().StringP(keyTypeFlagName, "", "", keyTypeFlagUsage)
	startCmd.Flags().StringP(keyAgreementTypeFlagName, "", "", keyAgreementTypeFlagUsage)
	startCmd.Flags().StringSliceP(mediaTypeProfileFlagName, "", []string{}, mediaTypeProfileFlagUsage)

	startCmd.Flags().StringP(trustblocDomainFlagName, "", "", trustblocDomainFlagUsage)
	startCmd.Flags().StringP(universalResolverURLFlagName, universalResolverURLFlagShorthand, "",
		universalResolverURLFlagUsage)
	startCmd.Flags().StringP(logLevelFlagName, "", "INFO", logLevelFlagUsage)
	startCmd.Flags().StringP(walletAppURLFlagName, "", "", walletAppURLFlagUsage)
	startCmd.Flags().StringP(issuerOIDCClientStoreKeyFlagName, "", "", issuerOIDCClientStoreKeyFlagUsage)
	startCmd.Flags().StringP(externalURLFlagName, "", "", externalURLFlagUsage)
	startCmd.Flags().StringP(didAnchorOriginFlagName, "", "", didAnchorOriginFlagUsage)
	startCmd.Flags().StringArrayP(contextProviderFlagName, "", []string{}, contextProviderFlagUsage)
}

func startAdapterService(parameters *adapterRestParameters, srv server) error {
	rootCAs, err := tlsutils.GetCertPool(parameters.tlsParams.systemCertPool, parameters.tlsParams.caCerts)
	if err != nil {
		return fmt.Errorf(confErrMsg, err)
	}

	router := mux.NewRouter()

	// add health check endpoint
	healthCheckService := healthcheck.New()

	healthCheckHandlers := healthCheckService.GetOperations()
	for _, handler := range healthCheckHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	msgRegistrar := msghandler.NewRegistrar()

	// add endpoints
	switch parameters.mode {
	case rpMode:
		framework, err := createAriesAgent(
			parameters,
			&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
			rpAdapterPersistentStorePrefix, msgRegistrar)
		if err != nil {
			return fmt.Errorf("failed to create rp aries agent: %w", err)
		}

		err = addRPHandlers(parameters, framework, router, rootCAs, msgRegistrar)
		if err != nil {
			return fmt.Errorf("failed to add rp-adapter handlers : %w", err)
		}
	case issuerMode:
		framework, err := createAriesAgent(parameters, &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
			issuerAdapterStorePrefix, msgRegistrar)
		if err != nil {
			return fmt.Errorf("failed to create issuer aries agent: %w", err)
		}

		err = addIssuerHandlers(parameters, framework, router, rootCAs, msgRegistrar)
		if err != nil {
			return fmt.Errorf("failed to add issuer-adapter handlers : %w", err)
		}

	default:
		return fmt.Errorf("invalid mode : %s", parameters.mode)
	}

	logger.Infof("starting %s adapter rest server on host %s", parameters.mode, parameters.hostURL)

	return srv.ListenAndServe( // nolint:wrapcheck // reduce cyclo
		parameters.hostURL,
		parameters.tlsParams.serveCertPath,
		parameters.tlsParams.serveKeyPath,
		constructCORSHandler(router))
}

// nolint:funlen,gocyclo,cyclop
func addRPHandlers(parameters *adapterRestParameters, framework *aries.Aries, router *mux.Router,
	rootCAs *x509.CertPool, msgRegistrar *msghandler.Registrar) error {
	presentationExProvider, err := getPresentationExchangeProvider(parameters.presentationDefinitionsFile)
	if err != nil {
		return fmt.Errorf("failed to create pres-exch provider: %w", err)
	}

	hydraURL, err := url.Parse(parameters.hydraURL)
	if err != nil {
		return fmt.Errorf("failed to parse hydra url: %w", err)
	}

	ctx, err := framework.Context()
	if err != nil {
		return fmt.Errorf("aries-framework - failed to get aries context : %w", err)
	}

	oobClient, err := outofband.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize outofband client : %w", err)
	}

	oobV2Client, err := outofbandv2.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize outofband v2 client: %w", err)
	}

	didClient, err := didexchange.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialized didexchange client : %w", err)
	}

	presentProofClient, err := presentproof.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to create presentproof client: %w", err)
	}

	store, tStore, err := initStores(parameters.dsnParams.dsn, parameters.dsnParams.timeout,
		"", rpAdapterPersistentStorePrefix, rpAdapterTransientStorePrefix)
	if err != nil {
		return fmt.Errorf("failed to init edge storage: %w", err)
	}

	// TODO init OIDC stuff in iteration 2 - https://github.com/trustbloc/edge-adapter/issues/24

	didCreator, err := did.NewTrustblocDIDCreator(
		parameters.trustblocDomain,
		parameters.didAnchorOrigin,
		parameters.didCommParameters.inboundHostExternal,
		ctx.KMS(),
		rootCAs,
		parameters.requestTokens["sidetreeToken"],
		ctx.KeyType(),
		ctx.KeyAgreementType(),
	)
	if err != nil {
		return fmt.Errorf("failed to create trustbloc did creator: %w", err)
	}

	// add rp endpoints
	rpService, err := rp.New(&rpops.Config{
		PresentationExProvider: presentationExProvider,
		Hydra:                  hydra.NewClient(hydraURL, rootCAs),
		UIEndpoint:             uiEndpoint,
		OOBClient:              oobClient,
		OOBV2Client:            oobV2Client,
		DIDExchClient:          didClient,
		Storage:                &rpops.Storage{Persistent: store, Transient: tStore},
		PublicDIDCreator:       didCreator,
		AriesContextProvider:   ctx,
		AriesMessenger:         framework.Messenger(),
		MsgRegistrar:           msgRegistrar,
		PresentProofClient:     presentProofClient,
		WalletBridgeAppURL:     parameters.walletAppURL,
		JSONLDDocumentLoader:   ctx.JSONLDDocumentLoader(),
		DidDomain:              parameters.trustblocDomain,
		ExternalURL:            parameters.externalURL,
	})
	if err != nil {
		return fmt.Errorf("failed to init rp operations: %w", err)
	}

	rpHandlers := rpService.GetOperations()
	for _, handler := range rpHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// handlers for JSON-LD context operations
	for _, handler := range ldrest.New(ldsvc.New(ctx)).GetRESTHandlers() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// static frontend
	router.PathPrefix(uiEndpoint).
		Subrouter().
		Methods(http.MethodGet).
		HandlerFunc(uiHandler(parameters.staticFiles, http.ServeFile))

	return nil
}

// nolint:funlen
func addIssuerHandlers(parameters *adapterRestParameters, framework *aries.Aries, router *mux.Router,
	rootCAs *x509.CertPool, msgRegistrar *msghandler.Registrar) error {
	store, err := initStore(parameters.dsnParams.dsn, parameters.dsnParams.timeout, issuerAdapterStorePrefix)
	if err != nil {
		return fmt.Errorf("failed to init storage provider : %w", err)
	}

	ariesCtx, err := framework.Context()
	if err != nil {
		return fmt.Errorf("aries-framework - failed to get aries context : %w", err)
	}

	cmDescriptors, err := readCMOutputDescriptorFile(parameters.cmOutputDescriptorsFilePath)
	if err != nil {
		return fmt.Errorf("failed to read and validate manifest output descriptors : %w", err)
	}

	clientStoreKey, err := getIssuerOIDCClientStoreKey(parameters.oidcClientDBKeyPath)
	if err != nil {
		return fmt.Errorf("failed to fetch OIDC client store key: %w", err)
	}

	didCreator, err := did.NewTrustblocDIDCreator(
		parameters.trustblocDomain,
		parameters.didAnchorOrigin,
		parameters.didCommParameters.inboundHostExternal,
		ariesCtx.KMS(),
		rootCAs,
		parameters.requestTokens["sidetreeToken"],
		ariesCtx.KeyType(),
		ariesCtx.KeyAgreementType(),
	)
	if err != nil {
		return fmt.Errorf("failed to init trustbloc did creator: %w", err)
	}
	// TODO #579 Persist the manifest output descriptor in local file based or in-memory cache.
	// add issuer endpoints
	issuerService, err := issuer.New(&issuerops.Config{
		AriesCtx:             ariesCtx,
		AriesMessenger:       framework.Messenger(),
		MsgRegistrar:         msgRegistrar,
		UIEndpoint:           uiEndpoint,
		StoreProvider:        store,
		PublicDIDCreator:     didCreator,
		TLSConfig:            &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
		OIDCClientStoreKey:   clientStoreKey,
		ExternalURL:          parameters.externalURL,
		DidDomain:            parameters.trustblocDomain,
		JSONLDDocumentLoader: ariesCtx.JSONLDDocumentLoader(),
		CMDescriptors:        cmDescriptors,
	})
	if err != nil {
		return fmt.Errorf("failed to init issuer ops: %w", err)
	}

	rpHandlers := issuerService.GetOperations()
	for _, handler := range rpHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// handlers for JSON-LD context operations
	for _, handler := range ldrest.New(ldsvc.New(ariesCtx)).GetRESTHandlers() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// static frontend
	router.PathPrefix(uiEndpoint).
		Subrouter().
		Methods(http.MethodGet).
		HandlerFunc(uiHandler(parameters.staticFiles, http.ServeFile))

	return nil
}

func getIssuerOIDCClientStoreKey(keyPath string) ([]byte, error) {
	bytes, errRead := ioutil.ReadFile(path.Clean(keyPath))
	if errRead != nil {
		return nil, fmt.Errorf("failed to read key '%s': %w", keyPath, errRead)
	}

	return bytes, nil
}

func uiHandler(
	basePath string,
	fileServer func(http.ResponseWriter, *http.Request, string)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == uiEndpoint {
			fileServer(w, r, strings.ReplaceAll(basePath+"/index.html", "//", "/"))
			return
		}

		fileServer(w, r, strings.ReplaceAll(basePath+"/"+r.URL.Path[len(uiEndpoint):], "//", "/"))
	}
}

func constructCORSHandler(handler http.Handler) http.Handler {
	return cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost},
			AllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "Authorization"},
		},
	).Handler(handler)
}

func getDBParams(dbURL string) (driver, dsn string, err error) {
	const (
		urlParts = 2
	)

	parsed := strings.SplitN(dbURL, ":", urlParts)

	if len(parsed) != urlParts {
		return "", "", fmt.Errorf("invalid dbURL %s", dbURL)
	}

	driver = parsed[0]

	if driver == "mongodb" {
		// The MongoDB storage provider needs the full connection string (including the driver as part of it).
		return driver, dbURL, nil
	}

	dsn = strings.TrimPrefix(parsed[1], "//")

	return driver, dsn, nil
}

func retry(fn func() error, timeout uint64) error {
	numRetries := uint64(datasourceTimeoutDefault)

	if timeout != 0 {
		numRetries = timeout
	}

	return backoff.RetryNotify( // nolint:wrapcheck // reduce cyclo
		fn,
		backoff.WithMaxRetries(backoff.NewConstantBackOff(sleep), numRetries),
		func(retryErr error, t time.Duration) {
			logger.Warnf(
				"failed to connect to storage, will sleep for %s before trying again : %s\n",
				t, retryErr)
		},
	)
}

func initStore(dbURL string, timeout uint64, prefix string) (storage.Provider, error) {
	driver, dsn, err := getDBParams(dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to init store [%s]: %w", dbURL, err)
	}

	providerFunc, supported := supportedStorageProviders[driver]
	if !supported {
		return nil, fmt.Errorf("unsupported storage driver: %s", driver)
	}

	var store storage.Provider

	err = retry(func() error {
		var openErr error
		store, openErr = providerFunc(dsn, prefix)
		return openErr
	}, timeout)
	if err != nil {
		return nil, fmt.Errorf("store init - failed to connect to storage at %s : %w", dsn, err)
	}

	return store, nil
}

func initStores(dbURL string, timeout uint64, dbPrefix, persistentUsagePrefix, transientUsagePrefix string) (persistent,
	transient storage.Provider, err error) {
	persistent, err = initStore(dbURL, timeout, dbPrefix+persistentUsagePrefix)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init persistent storage: %w", err)
	}

	transient, err = initStore(dbURL, timeout, dbPrefix+transientUsagePrefix)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init transient state storage: %w", err)
	}

	return persistent, transient, nil
}

func acceptsDID(method string) bool {
	// TODO list of allowed DIDs should be configurable
	return method == "orb"
}

var (
	//nolint:gochecknoglobals
	keyTypes = map[string]kms.KeyType{
		"ed25519":           kms.ED25519Type,
		"ecdsap256ieee1363": kms.ECDSAP256TypeIEEEP1363,
		"ecdsap256der":      kms.ECDSAP256TypeDER,
		"ecdsap384ieee1363": kms.ECDSAP384TypeIEEEP1363,
		"ecdsap384der":      kms.ECDSAP384TypeDER,
		"ecdsap521ieee1363": kms.ECDSAP521TypeIEEEP1363,
		"ecdsap521der":      kms.ECDSAP521TypeDER,
	}

	//nolint:gochecknoglobals
	keyAgreementTypes = map[string]kms.KeyType{
		"x25519kw": kms.X25519ECDHKWType,
		"p256kw":   kms.NISTP256ECDHKWType,
		"p384kw":   kms.NISTP384ECDHKWType,
		"p521kw":   kms.NISTP521ECDHKWType,
	}
)

//nolint:funlen
func createAriesAgent( // nolint:gocyclo,cyclop
	parameters *adapterRestParameters,
	tlsConfig *tls.Config,
	dbPrefix string,
	msgRegistrar api.MessageServiceProvider,
) (*aries.Aries, error) {
	var opts []aries.Option

	if parameters.didCommParameters.inboundHostInternal == "" {
		return nil, errors.New("didcomm inbound host is mandatory")
	}

	// TODO - enable TLS on aries inbound transports: https://github.com/trustbloc/edge-adapter/issues/303
	inboundTransportOpt := defaults.WithInboundHTTPAddr(
		parameters.didCommParameters.inboundHostInternal,
		parameters.didCommParameters.inboundHostExternal,
		"",
		"",
	)

	outbound, err := arieshttp.NewOutbound(arieshttp.WithOutboundTLSConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("aries-framework - failed to create outbound tranpsort opts : %w", err)
	}

	if parameters.universalResolverURL != "" {
		universalResolverVDRI, resErr := httpbinding.New(parameters.universalResolverURL,
			httpbinding.WithAccept(acceptsDID), httpbinding.WithHTTPClient(
				&http.Client{
					Transport: &http.Transport{
						TLSClientConfig: tlsConfig,
					},
				},
			))
		if resErr != nil {
			return nil, fmt.Errorf("failed to create new universal resolver vdri: %w", resErr)
		}

		opts = append(opts, aries.WithVDR(universalResolverVDRI))
	}

	store, tStore, err := initStores(parameters.dsnParams.dsn, parameters.dsnParams.timeout, dbPrefix,
		"_aries", "_ariesps")
	if err != nil {
		return nil, fmt.Errorf("failed to init edge storage: %w", err)
	}

	ldStore, err := ld.NewStoreProvider(store)
	if err != nil {
		return nil, fmt.Errorf("failed to init LD store provider: %w", err)
	}

	loader, err := createJSONLDDocumentLoader(ldStore, tlsConfig, parameters.contextProviderURLs)
	if err != nil {
		return nil, fmt.Errorf("failed to create document loader: %w", err)
	}

	if kt, ok := keyTypes[parameters.didCommParameters.keyType]; ok {
		opts = append(opts, aries.WithKeyType(kt))
	}

	if kat, ok := keyAgreementTypes[parameters.didCommParameters.keyAgreementType]; ok {
		opts = append(opts, aries.WithKeyAgreementType(kat))
	}

	if len(parameters.didCommParameters.mediaTypeProfiles) != 0 {
		opts = append(opts, aries.WithMediaTypeProfiles(parameters.didCommParameters.mediaTypeProfiles))
	}

	opts = append(opts,
		inboundTransportOpt,
		aries.WithOutboundTransports(outbound),
		aries.WithStoreProvider(store),
		aries.WithProtocolStateStoreProvider(tStore),
		aries.WithMessageServiceProvider(msgRegistrar),
		aries.WithJSONLDDocumentLoader(loader),
		aries.WithJSONLDContextStore(ldStore.JSONLDContextStore()),
		aries.WithJSONLDRemoteProviderStore(ldStore.JSONLDRemoteProviderStore()),
	)

	framework, err := aries.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("aries-framework - failed to initialize framework : %w", err)
	}

	return framework, nil
}

func createJSONLDDocumentLoader(ldStore *ld.StoreProvider, tlsConfig *tls.Config,
	providerURLs []string) (jsonld.DocumentLoader, error) {
	var loaderOpts []ariesld.DocumentLoaderOpts

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	for _, u := range providerURLs {
		loaderOpts = append(loaderOpts,
			ariesld.WithRemoteProvider(
				remote.NewProvider(u, remote.WithHTTPClient(httpClient)),
			),
		)
	}

	loader, err := ld.NewDocumentLoader(ldStore, loaderOpts...)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	return loader, nil
}

func getPresentationExchangeProvider(configFile string) (*presentationex.Provider, error) {
	reader, err := os.Open(filepath.Clean(configFile))
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", configFile, err)
	}

	defer func() {
		closeErr := reader.Close()
		if closeErr != nil {
			logger.Warnf("failed to close %s: %w", configFile, closeErr)
		}
	}()

	p, err := presentationex.New(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to init presentation-exchange provider: %w", err)
	}

	return p, nil
}

func readCMOutputDescriptorFile(cmDescriptorsFile string) (cmDescriptor map[string]*issuerops.CMAttachmentDescriptors,
	err error) {
	if cmDescriptorsFile == "" {
		return make(map[string]*issuerops.CMAttachmentDescriptors), nil
	}

	credentialDescriptorsBytes, err := ioutil.ReadFile(filepath.Clean(cmDescriptorsFile))
	if err != nil {
		return nil, fmt.Errorf("read credential manifest descriptors file : %w", err)
	}

	err = json.Unmarshal(credentialDescriptorsBytes, &cmDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential manifest descriptors file: %w", err)
	}

	for _, descriptors := range cmDescriptor {
		err := cm.ValidateOutputDescriptors(descriptors.OutputDesc)
		if err != nil {
			return nil, fmt.Errorf("aries-framework - failed to validate output descriptors: %w", err)
		}
	}
	// TODO Issue#563 validate input descriptor if exists

	return cmDescriptor, nil
}
