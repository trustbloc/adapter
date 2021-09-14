/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// nolint: gochecknoglobals
var inputDescriptors = `{
  "CreditCardStatement": {
    "schema": [{
      "uri": "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld"
    }]
  }
}`

type mockServer struct{}

func (s *mockServer) ListenAndServe(host, certPath, keyPath string, handler http.Handler) error {
	return nil
}

func TestListenAndServe(t *testing.T) { // nolint:paralleltest // shared environment variables
	var w HTTPServer
	err := w.ListenAndServe("wronghost", "", "", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "address wronghost: missing port in address")
}

func TestStartCmdContents(t *testing.T) { // nolint:paralleltest // shared environment variables
	startCmd := GetStartCmd(&mockServer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start adapter-rest", startCmd.Short)
	require.Equal(t, "Start adapter-rest inside the edge-adapter", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithBlankArg(t *testing.T) { // nolint:paralleltest // shared environment variables
	t.Run("test blank host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "host-url value is empty")
	})
}

func TestStartCmdWithMissingArg(t *testing.T) { // nolint:paralleltest // shared environment variables
	t.Run("test missing host url arg", func(t *testing.T) { // nolint:paralleltest // shared environment variables
		startCmd := GetStartCmd(&mockServer{})

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(),
			"Neither host-url (command line flag) nor ADAPTER_REST_HOST_URL (environment variable) have been set.")
	})

	t.Run("test missing presentation definition file arg (rpMode)", func(t *testing.T) { // nolint:paralleltest,lll // shared environment variables
		startCmd := GetStartCmd(&mockServer{})

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(inputDescriptors)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		args := []string{
			"--" + modeFlagName, rpMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + datasourceNameFlagName, "mem://tests",
			"--" + datasourceTimeoutFlagName, "30",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"Neither presentation-definitions-file (command line flag) nor "+
				"ADAPTER_REST_PRESENTATION_DEFINITIONS_FILE (environment variable) have been set.")
	})

	t.Run("missing presentation-exchange arg", func(t *testing.T) { // nolint:paralleltest // shared environment variables
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + modeFlagName, rpMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + datasourceNameFlagName, "mem://tests",
			"--" + datasourceTimeoutFlagName, "30",
			"--" + didCommInboundHostFlagName, randomURL(),
			"--" + trustblocDomainFlagName, "http://example.trustbloc.com",
			"--" + universalResolverURLFlagName, "http://uniresolver.trustbloc.com",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
	})

	t.Run("malformed presentation-exchange config file", func(t *testing.T) { // nolint:paralleltest,lll // shared environment variables
		startCmd := GetStartCmd(&mockServer{})

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		args := []string{
			"--" + modeFlagName, rpMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + presentationDefinitionsFlagName, file.Name(),
			"--" + datasourceNameFlagName, "mem://tests",
			"--" + datasourceTimeoutFlagName, "30",
			"--" + didCommInboundHostFlagName, randomURL(),
			"--" + trustblocDomainFlagName, "http://example.trustbloc.com",
			"--" + universalResolverURLFlagName, "http://uniresolver.trustbloc.com",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed unmarshal to input descriptors")
	})

	t.Run("nonexistent presentation-exchange config file", func(t *testing.T) { // nolint:paralleltest,lll // shared environment variables
		startCmd := GetStartCmd(&mockServer{})

		file := strings.ReplaceAll(uuid.New().String(), "-", "")

		args := []string{
			"--" + modeFlagName, rpMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + presentationDefinitionsFlagName, file,
			"--" + datasourceNameFlagName, "mem://tests",
			"--" + datasourceTimeoutFlagName, "30",
			"--" + didCommInboundHostFlagName, randomURL(),
			"--" + trustblocDomainFlagName, "http://example.trustbloc.com",
			"--" + universalResolverURLFlagName, "http://uniresolver.trustbloc.com",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "no such file or directory")
	})
}

func TestStartCmdWithBlankEnvVar(t *testing.T) { // nolint:paralleltest // shared environment variables
	t.Run("test blank host env var", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := os.Setenv(hostURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "ADAPTER_REST_HOST_URL value is empty")
	})
}

func TestStartCmdValidArgs(t *testing.T) { // nolint:paralleltest // shared environment variables
	startCmd := GetStartCmd(&mockServer{})

	file, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = file.WriteString(inputDescriptors)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(file.Name())) }()

	args := []string{
		"--" + modeFlagName, rpMode,
		"--" + hostURLFlagName, "localhost:8080",
		"--" + presentationDefinitionsFlagName, file.Name(),
		"--" + datasourceNameFlagName, "mem://tests",
		"--" + datasourceTimeoutFlagName, "30",
		"--" + didCommInboundHostFlagName, randomURL(),
		"--" + trustblocDomainFlagName, "http://example.trustbloc.com",
		"--" + universalResolverURLFlagName, "http://uniresolver.trustbloc.com",
		"--" + requestTokensFlagName, "token1=tk1",
		"--" + requestTokensFlagName, "token2=tk2=tk2",
		"--" + walletAppURLFlagName, "http://demoapp",
	}
	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.NoError(t, err)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) { // nolint:paralleltest // shared environment variables
	file, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = file.WriteString(inputDescriptors)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(file.Name())) }()

	startCmd := GetStartCmd(&mockServer{})
	args := []string{
		"--" + modeFlagName, "rp",
		"--" + didCommInboundHostFlagName, randomURL(),
		"--" + datasourceNameFlagName, "mem://test",
		"--" + datasourceTimeoutFlagName, "30",
	}
	startCmd.SetArgs(args)

	setEnvVars(t, file.Name())

	defer unsetEnvVars(t)

	err = startCmd.Execute()
	require.NoError(t, err)
}

func TestStartCmdDatasourceURL(t *testing.T) { // nolint:paralleltest // shared environment variables
	t.Run("unsupported driver", func(t *testing.T) { // nolint:paralleltest // shared environment variables
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(inputDescriptors)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		startCmd := GetStartCmd(&mockServer{})
		args := []string{
			"--" + modeFlagName, "rp",
			"--" + didCommInboundHostFlagName, randomURL(),
			"--" + datasourceNameFlagName, "unsupported://test",
		}
		startCmd.SetArgs(args)

		setEnvVars(t, file.Name())

		defer unsetEnvVars(t)

		err = startCmd.Execute()
		require.Error(t, err)
	})

	t.Run("invalid db url format", func(t *testing.T) { // nolint:paralleltest // shared environment variables
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(inputDescriptors)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		startCmd := GetStartCmd(&mockServer{})
		args := []string{
			"--" + modeFlagName, "rp",
			"--" + didCommInboundHostFlagName, randomURL(),
			"--" + datasourceNameFlagName, "invalid",
			"--" + datasourceTimeoutFlagName, "30",
		}
		startCmd.SetArgs(args)

		setEnvVars(t, file.Name())

		defer unsetEnvVars(t)

		err = startCmd.Execute()
		require.Error(t, err)
	})

	t.Run("missing db timeout flag", func(t *testing.T) { // nolint:paralleltest // shared environment variables
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(inputDescriptors)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		startCmd := GetStartCmd(&mockServer{})
		args := []string{
			"--" + modeFlagName, "rp",
			"--" + didCommInboundHostFlagName, randomURL(),
			"--" + datasourceNameFlagName, "mem://test",
		}
		startCmd.SetArgs(args)

		setEnvVars(t, file.Name())

		defer unsetEnvVars(t)

		err = startCmd.Execute()
		require.Error(t, err)
	})
}

func TestStartCmdDIDComm(t *testing.T) { // nolint:paralleltest // shared environment variables
	t.Run("test start didcomm - success", func(t *testing.T) { // nolint:paralleltest // shared environment variables
		startCmd := GetStartCmd(&mockServer{})

		file, err := ioutil.TempFile("", "*.key")
		require.NoError(t, err)

		key := make([]byte, 32)
		_, err = rand.Read(key)
		require.NoError(t, err)

		_, err = file.Write(key)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		args := []string{
			"--" + modeFlagName, issuerMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + didCommInboundHostFlagName, randomURL(),
			"--" + datasourceNameFlagName, "mem://test",
			"--" + datasourceTimeoutFlagName, "30",
			"--" + issuerOIDCClientStoreKeyFlagName, file.Name(),
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("test start didcomm - empty inbound host", func(t *testing.T) { // nolint:paralleltest,lll // shared environment variables
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + modeFlagName, issuerMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + datasourceNameFlagName, "mem://test",
			"--" + datasourceTimeoutFlagName, "30",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "didcomm inbound host is mandatory")
	})
}

func TestAdapterModes(t *testing.T) { // nolint:paralleltest // shared environment variables
	t.Run("test adapter mode - rp", func(t *testing.T) { // nolint:paralleltest // shared environment variables
		startCmd := GetStartCmd(&mockServer{})

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(inputDescriptors)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		args := []string{
			"--" + modeFlagName, rpMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + presentationDefinitionsFlagName, file.Name(),
			"--" + didCommInboundHostFlagName, randomURL(),
			"--" + datasourceNameFlagName, "mem://test",
			"--" + datasourceTimeoutFlagName, "30",
			"--" + governanceVCSURLFlagName, "http://example.vcs.com",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("test adapter mode - issuer", func(t *testing.T) { // nolint:paralleltest // shared environment variables
		startCmd := GetStartCmd(&mockServer{})

		testInboundHostURL := randomURL()

		file, err := ioutil.TempFile("", "*.key")
		require.NoError(t, err)

		key := make([]byte, 32)
		_, err = rand.Read(key)
		require.NoError(t, err)

		_, err = file.Write(key)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		args := []string{
			"--" + modeFlagName, issuerMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + didCommInboundHostFlagName, testInboundHostURL,
			"--" + datasourceNameFlagName, "mem://test",
			"--" + datasourceTimeoutFlagName, "30",
			"--" + governanceVCSURLFlagName, "http://example.vcs.com",
			"--" + issuerOIDCClientStoreKeyFlagName, file.Name(),
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("test adapter mode - unsupported mode", func(t *testing.T) { // nolint:paralleltest,lll // shared environment variables
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + modeFlagName, "invalidMode",
			"--" + hostURLFlagName, "localhost:8080",
			"--" + didCommInboundHostFlagName, randomURL(),
			"--" + datasourceNameFlagName, "mem://test",
			"--" + datasourceTimeoutFlagName, "30",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid mode : invalidMode")
	})

	t.Run("test adapter mode - invalid driver type", // nolint:paralleltest // shared environment variables
		func(t *testing.T) {
			parameters := &adapterRestParameters{
				dsnParams: &dsnParams{},
			}

			err := addIssuerHandlers(parameters, nil, nil, nil, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to init storage provider")

			_, err = initStore("invaldidb://test", 10, "")
			require.Error(t, err)
			require.Contains(t, err.Error(), "unsupported storage driver: invaldidb")
		})

	t.Run("test adapter mode - invalid MySQL dsn", // nolint:paralleltest // shared environment variables
		func(t *testing.T) {
			parameters := &adapterRestParameters{
				dsnParams: &dsnParams{},
			}

			err := addIssuerHandlers(parameters, nil, nil, nil, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to init storage provider")

			_, err = initStore("mysql://", 1, "")
			require.EqualError(t, err, "store init - failed to connect to storage at  : "+
				"DB URL for new mySQL DB provider can't be blank")
		})

	t.Run("test adapter mode - invalid MongoDB dsn", // nolint:paralleltest // shared environment variables
		func(t *testing.T) {
			parameters := &adapterRestParameters{
				dsnParams: &dsnParams{},
			}

			err := addIssuerHandlers(parameters, nil, nil, nil, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to init storage provider")

			_, err = initStore("mongodb://", 1, "")
			require.EqualError(t, err, "store init - failed to connect to storage at mongodb:// : "+
				"failed to create a new MongoDB client: error parsing uri: must have at least 1 host")
		})

	t.Run("test adapter mode - issuer client store key error", func(t *testing.T) { // nolint:paralleltest,lll // shared environment variables
		startCmd := GetStartCmd(&mockServer{})

		testInboundHostURL := randomURL()

		file, err := ioutil.TempFile("", "*.key")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		args := []string{
			"--" + modeFlagName, issuerMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + didCommInboundHostFlagName, testInboundHostURL,
			"--" + datasourceNameFlagName, "mem://test",
			"--" + datasourceTimeoutFlagName, "30",
			"--" + governanceVCSURLFlagName, "http://example.vcs.com",
			"--" + issuerOIDCClientStoreKeyFlagName, file.Name() + "-nonexistent",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read key")
	})

	t.Run("test adapter mode - wallet handler errors", func(t *testing.T) { // nolint:paralleltest,lll // shared environment variables
		file, err := ioutil.TempFile("", "*.key")
		require.NoError(t, err)

		key := make([]byte, 32)
		_, err = rand.Read(key)
		require.NoError(t, err)

		_, err = file.Write(key)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		parameters := &adapterRestParameters{
			dsnParams: &dsnParams{
				dsn: "mem://test",
			},
			didCommParameters:   &didCommParameters{},
			oidcClientDBKeyPath: file.Name(),
		}

		issuerAries, err := aries.New(aries.WithStoreProvider(&storage.MockStoreProvider{
			FailNamespace: "walletappprofile",
			Store:         &storage.MockStore{Store: make(map[string]storage.DBEntry)},
		}))
		require.NoError(t, err)

		defer func() {
			e := issuerAries.Close()
			logger.Warnf("failed to destroy issuer aries: %w", e)
		}()

		err = addIssuerHandlers(parameters, issuerAries, &mux.Router{}, nil, &msghandler.Registrar{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to initialize wallet bridge")

		rpAries, err := aries.New(aries.WithStoreProvider(&storage.MockStoreProvider{
			FailNamespace: "walletappprofile",
			Store:         &storage.MockStore{Store: make(map[string]storage.DBEntry)},
		}))
		require.NoError(t, err)

		defer func() {
			e := rpAries.Close()
			logger.Warnf("failed to destroy rp aries: %w", e)
		}()

		parameters.presentationDefinitionsFile = "./testdata/pres-def-mock.json"
		err = addRPHandlers(parameters, rpAries, &mux.Router{}, nil, &msghandler.Registrar{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to initialize wallet bridge")
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) { // nolint:paralleltest // shared environment variables
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t, "")

	defer unsetEnvVars(t)
	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func TestUIHandler(t *testing.T) { // nolint:paralleltest // shared environment variables
	t.Run("handle base path", func(t *testing.T) { // nolint:paralleltest // shared environment variables
		handled := false
		uiHandler(uiEndpoint, func(_ http.ResponseWriter, _ *http.Request, path string) {
			handled = true
			require.Equal(t, uiEndpoint+"/index.html", path)
		})(nil, &http.Request{URL: &url.URL{Path: uiEndpoint}})
		require.True(t, handled)
	})
	t.Run("handle subpaths", func(t *testing.T) { // nolint:paralleltest // shared environment variables
		const expected = uiEndpoint + "/css/abc123.css"
		handled := false
		uiHandler(uiEndpoint, func(_ http.ResponseWriter, _ *http.Request, path string) {
			handled = true
			require.Equal(t, expected, path)
		})(nil, &http.Request{URL: &url.URL{Path: expected}})
		require.True(t, handled)
	})
}

func setEnvVars(t *testing.T, fileName string) {
	t.Helper()

	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)

	err = os.Setenv(presentationDefinitionsEnvKey, fileName)
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	t.Helper()

	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(presentationDefinitionsEnvKey)
	require.NoError(t, err)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	t.Helper()

	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}

func randomURL() string {
	return fmt.Sprintf("localhost:%d", mustGetRandomPort(3))
}

func mustGetRandomPort(n int) int {
	for ; n > 0; n-- {
		port, err := getRandomPort()
		if err != nil {
			continue
		}

		return port
	}
	panic("cannot acquire the random port")
}

func getRandomPort() (int, error) {
	const network = "tcp"

	addr, err := net.ResolveTCPAddr(network, "localhost:0")
	if err != nil {
		return 0, fmt.Errorf("failed to resolve tcp address: %w", err)
	}

	listener, err := net.ListenTCP(network, addr)
	if err != nil {
		return 0, fmt.Errorf("failed to listen on tcp address %s: %w", addr, err)
	}

	err = listener.Close()
	if err != nil {
		return 0, fmt.Errorf("failed to close listener: %w", err)
	}

	return listener.Addr().(*net.TCPAddr).Port, nil
}
