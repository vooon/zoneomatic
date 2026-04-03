//go:build e2e

package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const e2eAPIKey = "e2e-secret"

var (
	buildOnce  sync.Once
	binaryPath string
	buildErr   error
)

type runningServer struct {
	baseURL  string
	zonePath string
	cmd      *exec.Cmd
	logs     *bytes.Buffer
}

type pdnsServer struct {
	ID         string `json:"id"`
	DaemonType string `json:"daemon_type"`
	Version    string `json:"version"`
}

type pdnsRecord struct {
	Content string `json:"content"`
}

type pdnsRRSet struct {
	Name    string       `json:"name"`
	Type    string       `json:"type"`
	TTL     int          `json:"ttl"`
	Records []pdnsRecord `json:"records"`
}

type pdnsZone struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	RRsets []pdnsRRSet `json:"rrsets"`
}

func TestZoneomaticPDNSE2E(t *testing.T) {
	srv := startZoneomatic(t)
	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("server discovery", func(t *testing.T) {
		server := httpJSON[pdnsServer](t, client, http.MethodGet, srv.baseURL+"/api/v1/servers/localhost", nil)
		assert.Equal(t, "localhost", server.ID)
		assert.Equal(t, "authoritative", server.DaemonType)
		assert.Equal(t, "zoneomatic", server.Version)
	})

	t.Run("zone patch and read", func(t *testing.T) {
		payload := strings.NewReader(`{"rrsets":[{"name":"e2e.at.example.com.","type":"A","ttl":120,"changetype":"REPLACE","records":[{"content":"192.0.2.55","disabled":false}]}]}`)
		resp := httpDo(t, client, http.MethodPatch, srv.baseURL+"/api/v1/servers/localhost/zones/at.example.com.", payload)
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		zoneResp := httpJSON[pdnsZone](t, client, http.MethodGet, srv.baseURL+"/api/v1/servers/localhost/zones/at.example.com.", nil)
		assert.Equal(t, "at.example.com.", zoneResp.ID)

		rrset := findRRSet(t, zoneResp.RRsets, "e2e.at.example.com.", "A")
		assert.Equal(t, 120, rrset.TTL)
		assert.Equal(t, []pdnsRecord{{Content: "192.0.2.55"}}, rrset.Records)

		zoneBuf, err := os.ReadFile(srv.zonePath)
		require.NoError(t, err)
		assert.Contains(t, string(zoneBuf), "e2e")
		assert.Contains(t, string(zoneBuf), "192.0.2.55")
	})

	t.Run("unsupported zone create", func(t *testing.T) {
		resp := httpDo(t, client, http.MethodPost, srv.baseURL+"/api/v1/servers/localhost/zones", nil)
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error":"create zone is not implemented"}`, string(body))
	})

	t.Run("unauthorized without api key", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.baseURL+"/api/v1/servers/localhost", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close() // nolint:errcheck

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func startZoneomatic(t *testing.T) *runningServer {
	t.Helper()

	repoRoot := repositoryRoot(t)
	zonePath := copyFixture(t, filepath.Join(repoRoot, "internal", "zone", "testdata", "at.example.com.zone"))
	htpasswdPath := writeHTPasswd(t)
	listenAddr := freeListenAddr(t)
	baseURL := "http://" + listenAddr

	logs := bytes.NewBuffer(nil)
	cmd := exec.Command(zoneomaticBinary(t),
		"--htpasswd", htpasswdPath,
		"--zone", zonePath,
		"--listen", listenAddr,
		"--debug",
	)
	cmd.Dir = repoRoot
	cmd.Stdout = logs
	cmd.Stderr = logs

	require.NoError(t, cmd.Start())

	srv := &runningServer{
		baseURL:  baseURL,
		zonePath: zonePath,
		cmd:      cmd,
		logs:     logs,
	}

	t.Cleanup(func() {
		stopServer(t, srv)
		if t.Failed() {
			t.Logf("zoneomatic logs:\n%s", srv.logs.String())
		}
	})

	require.Eventually(t, func() bool {
		resp, err := http.Get(baseURL + "/health")
		if err != nil {
			return false
		}
		defer resp.Body.Close() // nolint:errcheck

		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 100*time.Millisecond, "zoneomatic did not become ready\n%s", srv.logs.String())

	return srv
}

func stopServer(t *testing.T, srv *runningServer) {
	t.Helper()

	if srv.cmd.Process == nil || (srv.cmd.ProcessState != nil && srv.cmd.ProcessState.Exited()) {
		return
	}

	_ = srv.cmd.Process.Signal(syscall.SIGTERM)

	done := make(chan error, 1)
	go func() {
		done <- srv.cmd.Wait()
	}()

	select {
	case <-time.After(5 * time.Second):
		_ = srv.cmd.Process.Kill()
		<-done
	case <-done:
	}
}

func zoneomaticBinary(t *testing.T) string {
	t.Helper()

	buildOnce.Do(func() {
		repoRoot := repositoryRoot(t)
		buildDir, err := os.MkdirTemp("", "zoneomatic-e2e-build-")
		if err != nil {
			buildErr = err
			return
		}

		binaryPath = filepath.Join(buildDir, "zoneomatic")

		cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/zoneomatic")
		cmd.Dir = repoRoot
		output, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("go build failed: %w\n%s", err, output)
		}
	})

	require.NoError(t, buildErr)
	return binaryPath
}

func repositoryRoot(t *testing.T) string {
	t.Helper()

	_, fileName, _, ok := runtime.Caller(0)
	require.True(t, ok)

	return filepath.Clean(filepath.Join(filepath.Dir(fileName), "..", ".."))
}

func copyFixture(t *testing.T, src string) string {
	t.Helper()

	dst := filepath.Join(t.TempDir(), filepath.Base(src))
	buf, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, buf, 0600))

	return dst
}

func writeHTPasswd(t *testing.T) string {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(e2eAPIKey), bcrypt.DefaultCost)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "test.htpasswd")
	require.NoError(t, os.WriteFile(path, []byte("e2e:"+string(hash)+"\n"), 0600))

	return path
}

func freeListenAddr(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close() // nolint:errcheck

	return listener.Addr().String()
}

func httpDo(t *testing.T, client *http.Client, method, url string, body io.Reader) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, url, body)
	require.NoError(t, err)
	req.Header.Set("X-API-Key", e2eAPIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		resp.Body.Close() // nolint:errcheck
	})

	return resp
}

func httpJSON[T any](t *testing.T, client *http.Client, method, url string, body io.Reader) T {
	t.Helper()

	resp := httpDo(t, client, method, url, body)
	defer resp.Body.Close() // nolint:errcheck

	buf, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Less(t, resp.StatusCode, 400, string(buf))

	var ret T
	require.NoError(t, json.Unmarshal(buf, &ret))
	return ret
}

func findRRSet(t *testing.T, rrsets []pdnsRRSet, name, typ string) pdnsRRSet {
	t.Helper()

	for _, rrset := range rrsets {
		if rrset.Name == name && rrset.Type == typ {
			return rrset
		}
	}

	t.Fatalf("rrset not found: %s %s", name, typ)
	return pdnsRRSet{}
}
