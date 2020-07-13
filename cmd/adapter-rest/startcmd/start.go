/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	ariesctx "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/httpbinding"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"github.com/xo/dburl"

	ariespai "github.com/trustbloc/edge-adapter/pkg/aries"
	"github.com/trustbloc/edge-adapter/pkg/did"
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
	datasourceNameFlagUsage = "Datasource Name with credentials if required," +
		" eg. mysql://root:secret@localhost:3306/adapter" +
		"Alternatively, this can be set with the following environment variable: " + datasourceNameEnvKey
	datasourceNameEnvKey = "ADAPTER_REST_DSN"

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
	universalResolverURLEnvKey        = "ADAPTER_UNIVERSAL_RESOLVER_URL"
)

// API endpoints.
const (
	uiEndpoint = "/ui"

	// modes
	issuerMode = "issuer"
	rpMode     = "rp"
)

type didCommParameters struct {
	inboundHostInternal string
	inboundHostExternal string
	dbPath              string
}

type adapterRestParameters struct {
	hostURL                     string
	tlsSystemCertPool           bool
	tlsCACerts                  []string
	dsn                         string
	oidcProviderURL             string
	staticFiles                 string
	presentationDefinitionsFile string
	// TODO assuming same base path for all hydra endpoints for now
	hydraURL             string
	mode                 string
	didCommParameters    *didCommParameters // didcomm
	trustblocDomain      string
	universalResolverURL string
}

type server interface {
	ListenAndServe(host string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler) error {
	return http.ListenAndServe(host, router)
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

	tlsSystemCertPool, tlsCACerts, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	dsn, err := cmdutils.GetUserSetVarFromString(cmd, datasourceNameFlagName, datasourceNameEnvKey, true)
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

	return &adapterRestParameters{
		hostURL:                     hostURL,
		tlsSystemCertPool:           tlsSystemCertPool,
		tlsCACerts:                  tlsCACerts,
		dsn:                         dsn,
		oidcProviderURL:             oidcURL,
		staticFiles:                 staticFiles,
		presentationDefinitionsFile: presentationDefinitionsFile,
		hydraURL:                    hydraURL,
		mode:                        mode,
		didCommParameters:           didCommParameters,
		trustblocDomain:             trustblocDomain,
		universalResolverURL:        universalResolverURL,
	}, nil
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

func getTLS(cmd *cobra.Command) (bool, []string, error) {
	tlsSystemCertPoolString, err := cmdutils.GetUserSetVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey, true)
	if err != nil {
		return false, nil, err
	}

	tlsSystemCertPool := false
	if tlsSystemCertPoolString != "" {
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return false, nil, err
		}
	}

	tlsCACerts, err := cmdutils.GetUserSetVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey, true)
	if err != nil {
		return false, nil, err
	}

	return tlsSystemCertPool, tlsCACerts, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(oidcProviderURLFlagName, "", "", oidcProviderURLFlagUsage)
	startCmd.Flags().StringP(datasourceNameFlagName, "", "", datasourceNameFlagUsage)
	startCmd.Flags().StringP(staticFilesPathFlagName, "", "", staticFilesPathFlagUsage)
	startCmd.Flags().StringP(presentationDefinitionsFlagName, "", "", presentationDefinitionsFlagUsage)
	startCmd.Flags().StringP(hydraURLFlagName, "", "", hydraURLFlagUsage)
	startCmd.Flags().StringP(modeFlagName, "", "", modeFlagUsage)

	// didcomm
	startCmd.Flags().StringP(didCommInboundHostFlagName, "", "", didCommInboundHostFlagUsage)
	startCmd.Flags().StringP(didCommInboundHostExternalFlagName, "", "", didCommInboundHostExternalFlagUsage)
	startCmd.Flags().StringP(didCommDBPathFlagName, "", "", didCommDBPathFlagUsage)

	startCmd.Flags().StringP(trustblocDomainFlagName, "", "", trustblocDomainFlagUsage)
	startCmd.Flags().StringP(universalResolverURLFlagName, universalResolverURLFlagShorthand, "",
		universalResolverURLFlagUsage)
}

func startAdapterService(parameters *adapterRestParameters, srv server) error {
	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	logger.Debugf("root ca's %v", rootCAs)

	router := mux.NewRouter()

	// add health check endpoint
	healthCheckService := healthcheck.New()

	healthCheckHandlers := healthCheckService.GetOperations()
	for _, handler := range healthCheckHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	ariesCtx, err := createAriesAgent(parameters, &tls.Config{RootCAs: rootCAs})
	if err != nil {
		return err
	}

	// add endpoints
	switch parameters.mode {
	case rpMode:
		err = addRPHandlers(parameters, ariesCtx, router, rootCAs)
		if err != nil {
			return nil
		}
	case issuerMode:
		err = addIssuerHandlers(parameters, ariesCtx, router, rootCAs)
		if err != nil {
			return nil
		}
	default:
		return fmt.Errorf("invalid mode : %s", parameters.mode)
	}

	logger.Infof("starting %s adapter rest server on host %s", parameters.mode, parameters.hostURL)

	return srv.ListenAndServe(parameters.hostURL, constructCORSHandler(router))
}

func addRPHandlers(
	parameters *adapterRestParameters, ctx ariespai.CtxProvider, router *mux.Router, rootCAs *x509.CertPool) error {
	presentationExProvider, err := presentationex.New(parameters.presentationDefinitionsFile)
	if err != nil {
		return err
	}

	hydraURL, err := url.Parse(parameters.hydraURL)
	if err != nil {
		return err
	}

	didClient, err := didexchange.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialized didexchange client : %w", err)
	}

	presentProofClient, err := presentproof.New(ctx)
	if err != nil {
		return err
	}

	// TODO init OIDC stuff in iteration 2 - https://github.com/trustbloc/edge-adapter/issues/24

	// add rp endpoints
	rpService, err := rp.New(&rpops.Config{
		PresentationExProvider: presentationExProvider,
		Hydra:                  hydra.NewClient(hydraURL, rootCAs),
		UIEndpoint:             uiEndpoint,
		DIDExchClient:          didClient,
		Store:                  memstore.NewProvider(),
		PublicDIDCreator: did.NewTrustblocDIDCreator(
			parameters.trustblocDomain,
			parameters.didCommParameters.inboundHostExternal,
			ctx.KMS(),
			rootCAs),
		AriesStorageProvider: ctx,
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
	// add issuer endpoints
	issuerService, err := issuer.New(&issuerops.Config{
		AriesCtx:   ariesCtx,
		UIEndpoint: uiEndpoint,
		// TODO https://github.com/trustbloc/edge-adapter/issues/42 use sql store
		StoreProvider: memstore.NewProvider(),
		PublicDIDCreator: did.NewTrustblocDIDCreator(
			parameters.trustblocDomain,
			parameters.didCommParameters.inboundHostExternal,
			ariesCtx.KMS(),
			rootCAs,
		),
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

//nolint:deadcode,unused
func initDB(dsn string) (*sql.DB, error) {
	const (
		sleep      = 1 * time.Second
		numRetries = 30
	)

	var dbms *sql.DB

	err := backoff.RetryNotify(
		func() error {
			var openErr error
			dbms, openErr = dburl.Open(dsn)
			return openErr
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(sleep), numRetries),
		func(retryErr error, t time.Duration) {
			logger.Warnf(
				"failed to connect to database, will sleep for %d before trying again : %s\n",
				t, retryErr)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database at %s : %w", dsn, err)
	}

	return dbms, nil
}

func acceptsDID(method string) bool {
	// TODO list of allowed DIDs should be configurable
	return method == "trustbloc"
}

func createAriesAgent(parameters *adapterRestParameters, tlsConfig *tls.Config) (*ariesctx.Provider, error) {
	var opts []aries.Option

	if parameters.didCommParameters.inboundHostInternal == "" {
		return nil, errors.New("didcomm inbound host is mandatory")
	}

	if parameters.didCommParameters.dbPath != "" {
		opts = append(opts, defaults.WithStorePath(parameters.didCommParameters.dbPath))
	}

	inboundTransportOpt := defaults.WithInboundHTTPAddr(parameters.didCommParameters.inboundHostInternal,
		parameters.didCommParameters.inboundHostExternal)

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
