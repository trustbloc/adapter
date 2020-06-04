/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"

	"github.com/google/uuid"
	"github.com/phayes/freeport"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	_ "github.com/go-sql-driver/mysql"
)

// nolint: gochecknoglobals
var inputDescriptors = `{
 "input_descriptors": [
  {
    "id": "banking_input_1",
    "group": ["A"],
    "schema": {
      "uri": "https://bank-standards.com/customer.json",
      "name": "Bank Account Information",
      "purpose": "We need your bank and account information."
    },
    "constraints": {
      "fields": [
        {
          "path": ["$.issuer", "$.vc.issuer", "$.iss"],
          "purpose": "The credential must be from one of the specified issuers",
          "filter": {
            "type": "string",
            "pattern": "did:example:123|did:example:456"
          }
        },
        { 
          "path": ["$.credentialSubject.account[*].id", "$.vc.credentialSubject.account[*].id"],
          "purpose": "We need your bank account number for processing purposes",
          "filter": {
            "type": "string",
            "minLength": 10,
            "maxLength": 12
          }
        },
        {
          "path": ["$.credentialSubject.account[*].route", "$.vc.credentialSubject.account[*].route"],
          "purpose": "You must have an account with a German, US, or Japanese bank account",
          "filter": {
            "type": "string",
            "pattern": "^DE|^US|^JP"
          }
        }
      ]
    }
  }
]
}`

//nolint:gochecknoglobals
var containerName = "edgeadapter_start_tests_" + strings.ReplaceAll(uuid.New().String(), "-", "")

//nolint:gochecknoglobals
var containerPort int

func startMySQL() error {
	var err error

	containerPort, err = freeport.GetFreePort()
	if err != nil {
		return fmt.Errorf("failed to obtain a port from the os : %w", err)
	}

	//nolint:gosec
	err = exec.Command("docker", "run",
		"--name", containerName,
		"-e", "MYSQL_ROOT_PASSWORD=secret",
		"-e", "MYSQL_DATABASE=edgeadapter",
		"-d",
		"-p", fmt.Sprintf("%d:3306", containerPort),
		"mysql:8.0.20").Run()
	if err != nil {
		return fmt.Errorf("failed to start mysql : %w", err)
	}

	db, err := sql.Open("mysql", fmt.Sprintf("root:secret@tcp(localhost:%d)/edgeadapter", containerPort))
	if err != nil {
		return fmt.Errorf("failed to start mysql : %w", err)
	}

	err = backoff.Retry(
		db.Ping,
		backoff.WithMaxRetries(backoff.NewConstantBackOff(500*time.Millisecond), 40),
	)
	if err != nil {
		return fmt.Errorf("failed to ping mysql : %w", err)
	}

	return nil
}

func stopMySQL() error {
	//nolint:gosec
	err := exec.Command("docker", "stop", containerName).Run()
	if err != nil {
		return fmt.Errorf("failed to stop mysql : %w", err)
	}

	return nil
}

func TestMain(m *testing.M) {
	err := startMySQL()
	if err != nil {
		panic(err)
	}

	code := m.Run()

	err = stopMySQL()
	if err != nil {
		panic(fmt.Errorf("failed to stop mysql : %w", err))
	}

	os.Exit(code)
}

type mockServer struct{}

func (s *mockServer) ListenAndServe(host string, handler http.Handler) error {
	return nil
}

func TestListenAndServe(t *testing.T) {
	var w HTTPServer
	err := w.ListenAndServe("wronghost", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "address wronghost: missing port in address")
}

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start adapter-rest", startCmd.Short)
	require.Equal(t, "Start adapter-rest inside the edge-adapter", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithBlankArg(t *testing.T) {
	t.Run("test blank host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "host-url value is empty", err.Error())
	})
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither host-url (command line flag) nor ADAPTER_REST_HOST_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing presentation definition file arg (rpMode)", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(inputDescriptors)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		args := []string{
			"--" + modeFlagName, rpMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + datasourceNameFlagName, fmt.Sprintf("mysql://root:secret@localhost:%d/edgeadapter", containerPort),
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t,
			"Neither presentation-definitions-file (command line flag) nor "+
				"ADAPTER_REST_PRESENTATION_DEFINITIONS_FILE (environment variable) have been set.",
			err.Error())
	})
}

func TestStartCmdWithBlankEnvVar(t *testing.T) {
	t.Run("test blank host env var", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := os.Setenv(hostURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "ADAPTER_REST_HOST_URL value is empty", err.Error())
	})
}

func TestStartCmdValidArgs(t *testing.T) {
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
		"--" + datasourceNameFlagName, fmt.Sprintf("mysql://root:secret@localhost:%d/edgeadapter", containerPort),
	}
	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.NoError(t, err)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	file, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = file.WriteString(inputDescriptors)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(file.Name())) }()

	startCmd := GetStartCmd(&mockServer{})
	args := []string{
		"--" + modeFlagName, "rp",
	}
	startCmd.SetArgs(args)

	setEnvVars(t, file.Name())

	defer unsetEnvVars(t)

	err = startCmd.Execute()
	require.NoError(t, err)
}

func TestStartCmdDIDComm(t *testing.T) {
	t.Run("test start didcomm - success", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()

		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + modeFlagName, issuerMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + didCommInboundHostFlagName, randomURL(),
			"--" + didCommDBPathFlagName, path,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("test start didcomm - empty inbound host", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()

		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + modeFlagName, issuerMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + didCommDBPathFlagName, path,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "didcomm inbound host is mandatory")
	})

	t.Run("test start didcomm - empty inbound host", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + modeFlagName, issuerMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + didCommInboundHostFlagName, randomURL(),
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "aries-framework - failed to initialize framework")
	})
}

func TestAdapterModes(t *testing.T) {
	t.Run("test adapter mode - rp", func(t *testing.T) {
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
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("test adapter mode - issuer", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()

		startCmd := GetStartCmd(&mockServer{})

		testInboundHostURL := randomURL()

		args := []string{
			"--" + modeFlagName, issuerMode,
			"--" + hostURLFlagName, "localhost:8080",
			"--" + didCommInboundHostFlagName, testInboundHostURL,
			"--" + didCommDBPathFlagName, path,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("test adapter mode - unsupported mode", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + modeFlagName, "invalidMode",
			"--" + hostURLFlagName, "localhost:8080",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid mode : invalidMode")
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t, "")

	defer unsetEnvVars(t)
	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func TestUIHandler(t *testing.T) {
	t.Run("handle base path", func(t *testing.T) {
		handled := false
		uiHandler(uiEndpoint, func(_ http.ResponseWriter, _ *http.Request, path string) {
			handled = true
			require.Equal(t, uiEndpoint+"/index.html", path)
		})(nil, &http.Request{URL: &url.URL{Path: uiEndpoint}})
		require.True(t, handled)
	})
	t.Run("handle subpaths", func(t *testing.T) {
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
	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)

	err = os.Setenv(presentationDefinitionsEnvKey, fileName)
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(presentationDefinitionsEnvKey)
	require.NoError(t, err)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
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
		return 0, err
	}

	listener, err := net.ListenTCP(network, addr)
	if err != nil {
		return 0, err
	}

	err = listener.Close()
	if err != nil {
		return 0, err
	}

	return listener.Addr().(*net.TCPAddr).Port, nil
}

func generateTempDir(t testing.TB) (string, func()) {
	path, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}

	return path, func() {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clear leveldb directory: %s", err)
		}
	}
}
