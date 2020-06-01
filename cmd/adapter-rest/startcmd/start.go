/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"

	"github.com/gorilla/mux"
	"github.com/ory/hydra-client-go/client"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/edge-adapter/pkg/db"
	"github.com/trustbloc/edge-adapter/pkg/presentationex"
	"github.com/trustbloc/edge-adapter/pkg/restapi/healthcheck"
	"github.com/trustbloc/edge-adapter/pkg/restapi/rp"
	"github.com/trustbloc/edge-adapter/pkg/restapi/rp/operation"

	// mysql db driver
	_ "github.com/go-sql-driver/mysql"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the adapter-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "ADAPTER_REST_HOST_URL"

	mysqlDatasourceFlagName  = "mysql-url"
	mysqlDatasourceFlagUsage = "MySQL datasource URL with credentials if required," +
		" eg. mysql://user:password@tcp(127.0.0.1:3306)/adapter." +
		"Alternatively, this can be set with the following environment variable: " + mysqlDatasourceEnvKey
	mysqlDatasourceEnvKey = "ADAPTER_REST_MYSQL_DATASOURCE"

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
)

// API endpoints.
const (
	uiEndpoint = "/ui"

	// modes
	issuerMode = "issuer"
	rpMode     = "rp"
)

type adapterRestParameters struct {
	hostURL                     string
	tlsSystemCertPool           bool
	tlsCACerts                  []string
	dsn                         string
	oidcProviderURL             string
	staticFiles                 string
	presentationDefinitionsFile string
	// TODO assuming same base path for all hydra endpoints for now
	hydraURL string
	mode     string
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

func getAdapterRestParameters(cmd *cobra.Command) (*adapterRestParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsSystemCertPool, tlsCACerts, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	dbURL, err := cmdutils.GetUserSetVarFromString(cmd, mysqlDatasourceFlagName, mysqlDatasourceEnvKey, true)
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

	return &adapterRestParameters{
		hostURL:                     hostURL,
		tlsSystemCertPool:           tlsSystemCertPool,
		tlsCACerts:                  tlsCACerts,
		dsn:                         dbURL,
		oidcProviderURL:             oidcURL,
		staticFiles:                 staticFiles,
		presentationDefinitionsFile: presentationDefinitionsFile,
		hydraURL:                    hydraURL,
		mode:                        mode,
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
	startCmd.Flags().StringP(mysqlDatasourceFlagName, "", "", mysqlDatasourceFlagUsage)
	startCmd.Flags().StringP(staticFilesPathFlagName, "", "", staticFilesPathFlagUsage)
	startCmd.Flags().StringP(presentationDefinitionsFlagName, "", "", presentationDefinitionsFlagUsage)
	startCmd.Flags().StringP(hydraURLFlagName, "", "", hydraURLFlagUsage)
	startCmd.Flags().StringP(modeFlagName, "", "", modeFlagUsage)
}

func startAdapterService(parameters *adapterRestParameters, srv server) error {
	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	log.Debugf("root ca's %v", rootCAs)

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
		err := addRPHandlers(parameters, router)
		if err != nil {
			return nil
		}
	case issuerMode:
		addIssuerHandlers(parameters, router)
	default:
		return fmt.Errorf("invalid mode : %s", parameters.mode)
	}

	log.Infof("starting %s adapter rest server on host %s", parameters.mode, parameters.hostURL)

	return srv.ListenAndServe(parameters.hostURL, constructCORSHandler(router))
}

func addRPHandlers(parameters *adapterRestParameters, router *mux.Router) error {
	presentationExProvider, err := presentationex.New(parameters.presentationDefinitionsFile)
	if err != nil {
		return err
	}

	hydraURL, err := url.Parse(parameters.hydraURL)
	if err != nil {
		return err
	}

	datasource, err := initDB(parameters.dsn)
	if err != nil {
		return err
	}

	// TODO init OIDC stuff in iteration 2 - https://github.com/trustbloc/edge-adapter/issues/24

	// add rp endpoints
	rpService, err := rp.New(&operation.Config{
		PresentationExProvider: presentationExProvider,
		Hydra:                  newHydraClient(hydraURL).Admin,
		TrxProvider:            newTrxProvider(datasource),
		UsersDAO:               db.NewEndUsers(datasource),
		OIDCRequestsDAO:        db.NewOIDCRequests(datasource),
		UIEndpoint:             uiEndpoint,
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

func addIssuerHandlers(parameters *adapterRestParameters, router *mux.Router) {
	// static frontend
	router.PathPrefix(uiEndpoint).
		Subrouter().
		Methods(http.MethodGet).
		HandlerFunc(uiHandler(parameters.staticFiles, http.ServeFile))
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

func newHydraClient(hydraURL *url.URL) *client.OryHydra {
	return client.NewHTTPClientWithConfig(
		nil,
		&client.TransportConfig{
			Schemes:  []string{hydraURL.Scheme},
			Host:     hydraURL.Host,
			BasePath: hydraURL.Path,
		},
	)
}

func initDB(dsn string) (*sql.DB, error) {
	const (
		sleep      = 1 * time.Second
		numRetries = 30
	)

	var dbms *sql.DB

	// TODO support parsing the driverName from the DSN
	//  https://github.com/trustbloc/edge-adapter/issues/23
	err := backoff.RetryNotify(
		func() error {
			var openErr error
			dbms, openErr = sql.Open("mysql", dsn)
			return openErr
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(sleep), numRetries),
		func(retryErr error, t time.Duration) {
			fmt.Printf(
				"warning - failed to connect to database, will sleep for %d before trying again : %s\n",
				t, retryErr)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database at %s : %w", dsn, err)
	}

	return dbms, nil
}

func newTrxProvider(dbms *sql.DB) func(ctx context.Context, opts *sql.TxOptions) (operation.Trx, error) {
	return func(ctx context.Context, opts *sql.TxOptions) (operation.Trx, error) {
		trx, err := dbms.BeginTx(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to open db transaction : %w", err)
		}

		return trx, nil
	}
}
