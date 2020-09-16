/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	arieslog "github.com/hyperledger/aries-framework-go/pkg/common/log"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	ariesctx "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	ariesmem "github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	ariesmysql "github.com/hyperledger/aries-framework-go/pkg/storage/mysql"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/httpbinding"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	"github.com/trustbloc/edge-core/pkg/storage/mysql"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	ariespai "github.com/trustbloc/edge-adapter/pkg/aries"
	"github.com/trustbloc/edge-adapter/pkg/did"
	"github.com/trustbloc/edge-adapter/pkg/governance"
	"github.com/trustbloc/edge-adapter/pkg/hydra"
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

	datasourceNameFlagName  = "dsn"
	datasourceNameFlagUsage = "Datasource Name with credentials if required." +
		" Format must be <driver>:[//]<driver-specific-dsn>." +
		" Examples: 'mysql://root:secret@tcp(localhost:3306)/adapter', 'mem://test'." +
		" Supported drivers are [mem, mysql]." +
		" Alternatively, this can be set with the following environment variable: " + datasourceNameEnvKey
	datasourceNameEnvKey = "ADAPTER_REST_DSN"

	datasourceTimeoutFlagName  = "dsn-timeout"
	datasourceTimeoutFlagUsage = "Total time in seconds to wait until the datasource is available before giving up." +
		" Default: " + string(datasourceTimeoutDefault) + " seconds." +
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

	// db path
	didCommDBPathFlagName  = "didcomm-db-path"
	didCommDBPathEnvKey    = "ADAPTER_REST_DIDCOMM_DB_PATH"
	didCommDBPathFlagUsage = "Path to database." +
		" Alternatively, this can be set with the following environment variable: " + didCommDBPathEnvKey

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

	governanceVCSURLFlagName  = "governance-vcs-url"
	governanceVCSURLFlagUsage = "Governance VCS instance is running on. Format: HostName:Port."
	governanceVCSURLEnvKey    = "ADAPTER_REST_GOVERNANCE_VCS_URL"

	requestTokensFlagName  = "request-tokens"
	requestTokensEnvKey    = "ADAPTER_REST_REQUEST_TOKENS" //nolint: gosec
	requestTokensFlagUsage = "Tokens used for http request " +
		" Alternatively, this can be set with the following environment variable: " + requestTokensEnvKey
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

// nolint:gochecknoglobals
var supportedEdgeStorageProviders = map[string]func(string, string) (storage.Provider, error){
	"mysql": func(dsn, prefix string) (storage.Provider, error) {
		return mysql.NewProvider(dsn, mysql.WithDBPrefix(prefix))
	},
	"mem": func(_, _ string) (storage.Provider, error) { // nolint:unparam
		return memstore.NewProvider(), nil
	},
}

// nolint:gochecknoglobals
var supportedAriesStorageProviders = map[string]func(string, string) (ariesstorage.Provider, error){
	"mysql": func(dsn, prefix string) (ariesstorage.Provider, error) {
		return ariesmysql.NewProvider(dsn, ariesmysql.WithDBPrefix(prefix))
	},
	"mem": func(_, _ string) (ariesstorage.Provider, error) { // nolint:unparam
		return ariesmem.NewProvider(), nil
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
	dbPath              string
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
	hydraURL             string
	mode                 string
	didCommParameters    *didCommParameters // didcomm
	trustblocDomain      string
	universalResolverURL string
	governanceVCSURL     string
	requestTokens        map[string]string
}

// governanceProvider governance provider.
type governanceProvider interface {
	IssueCredential(didID, profileID string) ([]byte, error)
	GetCredential(profileID string) ([]byte, error)
}

type server interface {
	ListenAndServe(host string, router http.Handler) error
	ListenAndServeTLS(host, certFile, keyFile string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler) error {
	return http.ListenAndServe(host, router)
}

// ListenAndServeTLS starts the server using the standard Go HTTPS implementation.
func (s *HTTPServer) ListenAndServeTLS(host, certFile, keyFile string, router http.Handler) error {
	return http.ListenAndServeTLS(host, certFile, keyFile, router)
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
				return err
			}

			return startAdapterService(parameters, srv)
		},
	}
}

//nolint:funlen,gocyclo
func getAdapterRestParameters(cmd *cobra.Command) (*adapterRestParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsParams, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	dsnParams, err := getDsnParams(cmd)
	if err != nil {
		return nil, err
	}

	oidcURL, err := cmdutils.GetUserSetVarFromString(cmd, oidcProviderURLFlagName, oidcProviderEnvKey, true)
	if err != nil {
		return nil, err
	}

	staticFiles, err := cmdutils.GetUserSetVarFromString(cmd, staticFilesPathFlagName, staticFilesPathEnvKey, true)
	if err != nil {
		return nil, err
	}

	mode, err := cmdutils.GetUserSetVarFromString(cmd, modeFlagName, modeEnvKey, true)
	if err != nil {
		return nil, err
	}

	presentationDefinitionsFile, err := cmdutils.GetUserSetVarFromString(cmd, presentationDefinitionsFlagName,
		presentationDefinitionsEnvKey, mode != rpMode)
	if err != nil {
		return nil, err
	}

	hydraURL, err := cmdutils.GetUserSetVarFromString(cmd, hydraURLFlagName, hydraURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	// didcomm
	didCommParameters, err := getDIDCommParams(cmd)
	if err != nil {
		return nil, err
	}

	trustblocDomain, err := cmdutils.GetUserSetVarFromString(cmd, trustblocDomainFlagName, trustblocDomainEnvKey, true)
	if err != nil {
		return nil, err
	}

	universalResolverURL, err := cmdutils.GetUserSetVarFromString(cmd, universalResolverURLFlagName,
		universalResolverURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	logLevel, err := cmdutils.GetUserSetVarFromString(cmd, logLevelFlagName, logLevelEnvKey, true)
	if err != nil {
		return nil, err
	}

	governanceVCSURL, err := cmdutils.GetUserSetVarFromString(cmd, governanceVCSURLFlagName,
		governanceVCSURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	requestTokens, err := getRequestTokens(cmd)
	if err != nil {
		return nil, err
	}

	err = setLogLevel(logLevel)
	if err != nil {
		return nil, err
	}

	logger.Infof("logger level set to %s", logLevel)

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
		governanceVCSURL:            governanceVCSURL,
		requestTokens:               requestTokens,
	}, nil
}

func getRequestTokens(cmd *cobra.Command) (map[string]string, error) {
	requestTokens, err := cmdutils.GetUserSetVarFromArrayString(cmd, requestTokensFlagName,
		requestTokensEnvKey, true)
	if err != nil {
		return nil, err
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
		return err
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
		timeout = string(datasourceTimeoutDefault)
	}

	t, err := strconv.Atoi(timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dsn timeout %s: %w", timeout, err)
	}

	params.timeout = uint64(t)

	return params, nil
}

func getDIDCommParams(cmd *cobra.Command) (*didCommParameters, error) {
	inboundHostInternal, err := cmdutils.GetUserSetVarFromString(cmd, didCommInboundHostFlagName,
		didCommInboundHostEnvKey, true)
	if err != nil {
		return nil, err
	}

	inboundHostExternal, err := cmdutils.GetUserSetVarFromString(cmd, didCommInboundHostExternalFlagName,
		didCommInboundHostExternalEnvKey, true)
	if err != nil {
		return nil, err
	}

	dbPath, err := cmdutils.GetUserSetVarFromString(cmd, didCommDBPathFlagName, didCommDBPathEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &didCommParameters{
		inboundHostInternal: inboundHostInternal,
		inboundHostExternal: inboundHostExternal,
		dbPath:              dbPath,
	}, nil
}

func getTLS(cmd *cobra.Command) (*tlsParameters, error) {
	tlsSystemCertPoolString, err := cmdutils.GetUserSetVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsSystemCertPool := false
	if tlsSystemCertPoolString != "" {
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return nil, err
		}
	}

	tlsCACerts, err := cmdutils.GetUserSetVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsServeCertPath, err := cmdutils.GetUserSetVarFromString(cmd, tlsServeCertPathFlagName, tlsServeCertPathEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsServeKeyPath, err := cmdutils.GetUserSetVarFromString(cmd, tlsServeKeyPathFlagName, tlsServeKeyPathFlagEnvKey, true)
	if err != nil {
		return nil, err
	}

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
	startCmd.Flags().StringP(presentationDefinitionsFlagName, "", "", presentationDefinitionsFlagUsage)
	startCmd.Flags().StringP(hydraURLFlagName, "", "", hydraURLFlagUsage)
	startCmd.Flags().StringP(modeFlagName, "", "", modeFlagUsage)
	startCmd.Flags().StringP(governanceVCSURLFlagName, "", "", governanceVCSURLFlagUsage)
	startCmd.Flags().StringArrayP(requestTokensFlagName, "", []string{}, requestTokensFlagUsage)

	// didcomm
	startCmd.Flags().StringP(didCommInboundHostFlagName, "", "", didCommInboundHostFlagUsage)
	startCmd.Flags().StringP(didCommInboundHostExternalFlagName, "", "", didCommInboundHostExternalFlagUsage)
	startCmd.Flags().StringP(didCommDBPathFlagName, "", "", didCommDBPathFlagUsage)

	startCmd.Flags().StringP(trustblocDomainFlagName, "", "", trustblocDomainFlagUsage)
	startCmd.Flags().StringP(universalResolverURLFlagName, universalResolverURLFlagShorthand, "",
		universalResolverURLFlagUsage)
	startCmd.Flags().StringP(logLevelFlagName, "", "INFO", logLevelFlagUsage)
}

func startAdapterService(parameters *adapterRestParameters, srv server) error {
	rootCAs, err := tlsutils.GetCertPool(parameters.tlsParams.systemCertPool, parameters.tlsParams.caCerts)
	if err != nil {
		return err
	}

	router := mux.NewRouter()

	// add health check endpoint
	healthCheckService := healthcheck.New()

	healthCheckHandlers := healthCheckService.GetOperations()
	for _, handler := range healthCheckHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// add endpoints
	switch parameters.mode {
	case rpMode:
		ariesCtx, err := createAriesAgent(parameters, &tls.Config{RootCAs: rootCAs}, rpAdapterPersistentStorePrefix)
		if err != nil {
			return err
		}

		err = addRPHandlers(parameters, ariesCtx, router, rootCAs)
		if err != nil {
			return fmt.Errorf("failed to add rp-adapter handlers : %w", err)
		}
	case issuerMode:
		ariesCtx, err := createAriesAgent(parameters, &tls.Config{RootCAs: rootCAs}, issuerAdapterStorePrefix)
		if err != nil {
			return err
		}

		err = addIssuerHandlers(parameters, ariesCtx, router, rootCAs)
		if err != nil {
			return fmt.Errorf("failed to add issuer-adapter handlers : %w", err)
		}
	default:
		return fmt.Errorf("invalid mode : %s", parameters.mode)
	}

	logger.Infof("starting %s adapter rest server on host %s", parameters.mode, parameters.hostURL)

	return srv.ListenAndServeTLS(
		parameters.hostURL,
		parameters.tlsParams.serveCertPath,
		parameters.tlsParams.serveKeyPath,
		constructCORSHandler(router))
}

// nolint:funlen,gocyclo
func addRPHandlers(
	parameters *adapterRestParameters, ctx ariespai.CtxProvider, router *mux.Router, rootCAs *x509.CertPool) error {
	presentationExProvider, err := getPresentationExchangeProvider(parameters.presentationDefinitionsFile)
	if err != nil {
		return err
	}

	hydraURL, err := url.Parse(parameters.hydraURL)
	if err != nil {
		return err
	}

	oobClient, err := outofband.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize outofband client : %w", err)
	}

	didClient, err := didexchange.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialized didexchange client : %w", err)
	}

	presentProofClient, err := presentproof.New(ctx)
	if err != nil {
		return err
	}

	store, tStore, err := initRPAdapterEdgeStores(parameters.dsnParams.dsn, parameters.dsnParams.timeout)
	if err != nil {
		return fmt.Errorf("failed to init edge storage: %w", err)
	}

	var governanceProv governanceProvider

	if parameters.governanceVCSURL != "" {
		var errNew error

		governanceProv, errNew = newGovernanceProvider(parameters.governanceVCSURL, rootCAs, store,
			parameters.requestTokens)
		if errNew != nil {
			return errNew
		}
	}

	// TODO init OIDC stuff in iteration 2 - https://github.com/trustbloc/edge-adapter/issues/24

	// add rp endpoints
	rpService, err := rp.New(&rpops.Config{
		PresentationExProvider: presentationExProvider,
		Hydra:                  hydra.NewClient(hydraURL, rootCAs),
		UIEndpoint:             uiEndpoint,
		OOBClient:              oobClient,
		DIDExchClient:          didClient,
		Storage:                &rpops.Storage{Persistent: store, Transient: tStore},
		PublicDIDCreator: did.NewTrustblocDIDCreator(
			parameters.trustblocDomain,
			parameters.didCommParameters.inboundHostExternal,
			ctx.KMS(),
			rootCAs),
		AriesContextProvider: ctx,
		GovernanceProvider:   governanceProv,
		PresentProofClient:   presentProofClient,
	})
	if err != nil {
		return err
	}

	rpHandlers := rpService.GetOperations()
	for _, handler := range rpHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// static frontend
	router.PathPrefix(uiEndpoint).
		Subrouter().
		Methods(http.MethodGet).
		HandlerFunc(uiHandler(parameters.staticFiles, http.ServeFile))

	return nil
}

func addIssuerHandlers(parameters *adapterRestParameters, ariesCtx ariespai.CtxProvider, router *mux.Router,
	rootCAs *x509.CertPool) error {
	store, err := initEdgeStore(parameters.dsnParams.dsn, parameters.dsnParams.timeout, issuerAdapterStorePrefix)
	if err != nil {
		return fmt.Errorf("failed to init storage provider : %w", err)
	}

	var governanceProv governanceProvider

	if parameters.governanceVCSURL != "" {
		var errNew error

		governanceProv, errNew = newGovernanceProvider(parameters.governanceVCSURL, rootCAs, store,
			parameters.requestTokens)
		if errNew != nil {
			return errNew
		}
	}

	// add issuer endpoints
	issuerService, err := issuer.New(&issuerops.Config{
		AriesCtx:      ariesCtx,
		UIEndpoint:    uiEndpoint,
		StoreProvider: store,
		PublicDIDCreator: did.NewTrustblocDIDCreator(
			parameters.trustblocDomain,
			parameters.didCommParameters.inboundHostExternal,
			ariesCtx.KMS(),
			rootCAs,
		),
		TLSConfig:          &tls.Config{RootCAs: rootCAs},
		GovernanceProvider: governanceProv,
	})

	if err != nil {
		return err
	}

	rpHandlers := issuerService.GetOperations()
	for _, handler := range rpHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// static frontend
	router.PathPrefix(uiEndpoint).
		Subrouter().
		Methods(http.MethodGet).
		HandlerFunc(uiHandler(parameters.staticFiles, http.ServeFile))

	return nil
}

func newGovernanceProvider(governanceVCSURL string, rootCAs *x509.CertPool,
	store storage.Provider, requestTokens map[string]string) (*governance.Provider, error) {
	return governance.New(governanceVCSURL, &tls.Config{RootCAs: rootCAs}, store,
		requestTokens)
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

func initRPAdapterEdgeStores(dbURL string, timeout uint64) (persistent, transient storage.Provider, err error) {
	persistent, err = initEdgeStore(dbURL, timeout, rpAdapterPersistentStorePrefix)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init edge persistent storage: %w", err)
	}

	transient, err = initEdgeStore(dbURL, timeout, rpAdapterTransientStorePrefix)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init edge transient storage: %w", err)
	}

	return persistent, transient, nil
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
	dsn = strings.TrimPrefix(parsed[1], "//")

	return driver, dsn, nil
}

func retry(fn func() error, timeout uint64) error {
	numRetries := uint64(datasourceTimeoutDefault)

	if timeout != 0 {
		numRetries = timeout
	}

	return backoff.RetryNotify(
		fn,
		backoff.WithMaxRetries(backoff.NewConstantBackOff(sleep), numRetries),
		func(retryErr error, t time.Duration) {
			logger.Warnf(
				"failed to connect to storage, will sleep for %s before trying again : %s\n",
				t, retryErr)
		},
	)
}

// nolint: dupl
func initAriesStore(dbURL string, timeout uint64, prefix string) (ariesstorage.Provider, error) {
	driver, dsn, err := getDBParams(dbURL)
	if err != nil {
		return nil, err
	}

	providerFunc, supported := supportedAriesStorageProviders[driver]
	if !supported {
		return nil, fmt.Errorf("unsupported storage driver: %s", driver)
	}

	var store ariesstorage.Provider

	err = retry(func() error {
		var openErr error
		store, openErr = providerFunc(dsn, prefix)
		return openErr
	}, timeout)
	if err != nil {
		return nil, fmt.Errorf("ariesstore init - failed to connect to storage at %s : %w", dsn, err)
	}

	return store, nil
}

// nolint: dupl
func initEdgeStore(dbURL string, timeout uint64, prefix string) (storage.Provider, error) {
	driver, dsn, err := getDBParams(dbURL)
	if err != nil {
		return nil, err
	}

	providerFunc, supported := supportedEdgeStorageProviders[driver]
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
		return nil, fmt.Errorf("edgestore init - failed to connect to storage at %s : %w", dsn, err)
	}

	return store, nil
}

func initAriesStores(dbURL string, timeout uint64, dbPrefix string) (persistent,
	protocolStateStore ariesstorage.Provider, err error) {
	persistent, err = initAriesStore(dbURL, timeout, dbPrefix+"_aries")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init aries persistent storage: %w", err)
	}

	protocolStateStore, err = initAriesStore(dbURL, timeout, dbPrefix+"_ariesps")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init aries protocol state storage: %w", err)
	}

	return persistent, protocolStateStore, nil
}

func acceptsDID(method string) bool {
	// TODO list of allowed DIDs should be configurable
	return method == "trustbloc"
}

func createAriesAgent(parameters *adapterRestParameters, tlsConfig *tls.Config, dbPrefix string) (*ariesctx.Provider, error) { // nolint:lll
	var opts []aries.Option

	if parameters.didCommParameters.inboundHostInternal == "" {
		return nil, errors.New("didcomm inbound host is mandatory")
	}

	if parameters.didCommParameters.dbPath != "" {
		opts = append(opts, defaults.WithStorePath(parameters.didCommParameters.dbPath))
	}

	// TODO - enable TLS on aries inbound transports: https://github.com/trustbloc/edge-adapter/issues/303
	inboundTransportOpt := defaults.WithInboundHTTPAddr(
		parameters.didCommParameters.inboundHostInternal,
		parameters.didCommParameters.inboundHostExternal,
		"",
		"",
	)

	opts = append(opts, inboundTransportOpt)

	outbound, err := arieshttp.NewOutbound(arieshttp.WithOutboundTLSConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("aries-framework - failed to create outbound tranpsort opts : %w", err)
	}

	opts = append(opts, aries.WithOutboundTransports(outbound))

	if parameters.universalResolverURL != "" {
		universalResolverVDRI, resErr := httpbinding.New(parameters.universalResolverURL,
			httpbinding.WithAccept(acceptsDID), httpbinding.WithTLSConfig(tlsConfig))
		if resErr != nil {
			return nil, fmt.Errorf("failed to create new universal resolver vdri: %w", resErr)
		}

		opts = append(opts, aries.WithVDRI(universalResolverVDRI))
	}

	store, tStore, err := initAriesStores(parameters.dsnParams.dsn, parameters.dsnParams.timeout, dbPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to init edge storage: %w", err)
	}

	opts = append(opts, aries.WithStoreProvider(store), aries.WithProtocolStateStoreProvider(tStore))

	framework, err := aries.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("aries-framework - failed to initialize framework : %w", err)
	}

	ctx, err := framework.Context()
	if err != nil {
		return nil, fmt.Errorf("aries-framework - failed to get aries context : %w", err)
	}

	return ctx, nil
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
