//go:build e2e

package e2e_test

import (
	"bytes"
	"encoding/base64"
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

	"github.com/miekg/dns"
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

func TestZoneomaticRFC2136E2E(t *testing.T) {
	tsigPath := filepath.Join(t.TempDir(), "tsig.conf")
	require.NoError(t, os.WriteFile(tsigPath, []byte(`
key "certmanager.example.com" {
	algorithm hmac-sha256;
	secret "YlZQY3QDIVu4vaD+7ZXhCQJ0NOn35EIvPrR52PP14kQ=";
};
`), 0600))

	dnsAddr := freeListenAddr(t)

	srv := startZoneomaticWithArgs(t,
		"--rfc2136-acme-listen", dnsAddr,
		"--rfc2136-acme-tsig-file", tsigPath,
		"--rfc2136-acme-allow", "127.0.0.0/8",
	)

	client := &dns.Client{
		Net:        "udp",
		TsigSecret: map[string]string{"certmanager.example.com.": "YlZQY3QDIVu4vaD+7ZXhCQJ0NOn35EIvPrR52PP14kQ="},
	}

	tok := "e2e-token-abcdefghijklmnopqrstuvwxyz012345678"
	m := new(dns.Msg)
	m.SetUpdate("at.example.com.")
	m.Insert([]dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: "_acme-challenge.e2e.at.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{tok},
	}})
	m.SetTsig("certmanager.example.com.", dns.HmacSHA256, 300, time.Now().Unix())

	resp, _, err := client.Exchange(m, dnsAddr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "rcode=%s", dns.RcodeToString[resp.Rcode])

	require.Eventually(t, func() bool {
		buf, err := os.ReadFile(srv.zonePath)
		if err != nil {
			return false
		}
		return strings.Contains(string(buf), tok)
	}, 10*time.Second, 100*time.Millisecond, "zone file was not updated")

	// Unsigned update must be rejected.
	unsigned := new(dns.Msg)
	unsigned.SetUpdate("at.example.com.")
	unsigned.Insert([]dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: "_acme-challenge.evil.at.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{"evil"},
	}})

	resp, _, err = (&dns.Client{Net: "udp"}).Exchange(unsigned, dnsAddr)
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeNotAuth, resp.Rcode)
}

func TestZoneomaticRFC2136NsupdateE2E(t *testing.T) {
	// Cross-implementation check against BIND's nsupdate, which must be
	// installed. It exercises the same protocol as cert-manager's solver but
	// with a completely independent implementation.
	nsupdate, err := exec.LookPath("nsupdate")
	if err != nil {
		t.Skip("nsupdate not installed")
	}

	tsigPath := filepath.Join(t.TempDir(), "tsig.conf")
	secret := "YlZQY3QDIVu4vaD+7ZXhCQJ0NOn35EIvPrR52PP14kQ="
	require.NoError(t, os.WriteFile(tsigPath, []byte(
		"key \"certmanager.example.com\" {\n\talgorithm hmac-sha256;\n\tsecret \""+secret+"\";\n};\n"), 0600))

	dnsAddr := freeListenAddr(t)
	host, port, err := net.SplitHostPort(dnsAddr)
	require.NoError(t, err)

	srv := startZoneomaticWithArgs(t,
		"--rfc2136-acme-listen", dnsAddr,
		"--rfc2136-acme-tsig-file", tsigPath,
		"--rfc2136-acme-allow", "127.0.0.0/8",
	)

	run := func(t *testing.T, script string) {
		t.Helper()
		cmd := exec.Command(nsupdate, "-k", tsigPath)
		cmd.Stdin = strings.NewReader(script)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "nsupdate failed: %s", out)
	}

	tok := "nsupdate-token-abcdefghijklmnopqrstuvwxyz012345"
	run(t, fmt.Sprintf("server %s %s\nzone at.example.com\nupdate add _acme-challenge.nsupdate.at.example.com 60 TXT \"%s\"\nsend\n", host, port, tok))

	require.Eventually(t, func() bool {
		buf, err := os.ReadFile(srv.zonePath)
		return err == nil && strings.Contains(string(buf), tok)
	}, 10*time.Second, 100*time.Millisecond, "zone file was not updated by nsupdate")

	// nsupdate must also be able to remove the value again.
	run(t, fmt.Sprintf("server %s %s\nzone at.example.com\nupdate delete _acme-challenge.nsupdate.at.example.com TXT \"%s\"\nsend\n", host, port, tok))

	require.Eventually(t, func() bool {
		buf, err := os.ReadFile(srv.zonePath)
		return err == nil && !strings.Contains(string(buf), tok)
	}, 10*time.Second, 100*time.Millisecond, "zone file was not cleaned up by nsupdate")
}

func TestZoneomaticRFC2136KnsupdateE2E(t *testing.T) {
	// Cross-implementation check against Knot DNS's knsupdate.
	knsupdate, err := exec.LookPath("knsupdate")
	if err != nil {
		t.Skip("knsupdate not installed")
	}

	const keyName = "certmanager.example.com"
	const secret = "YlZQY3QDIVu4vaD+7ZXhCQJ0NOn35EIvPrR52PP14kQ="

	tsigPath := filepath.Join(t.TempDir(), "tsig.conf")
	require.NoError(t, os.WriteFile(tsigPath, []byte(
		"key \""+keyName+"\" {\n\talgorithm hmac-sha256;\n\tsecret \""+secret+"\";\n};\n"), 0600))

	dnsAddr := freeListenAddr(t)
	host, port, err := net.SplitHostPort(dnsAddr)
	require.NoError(t, err)

	srv := startZoneomaticWithArgs(t,
		"--rfc2136-acme-listen", dnsAddr,
		"--rfc2136-acme-tsig-file", tsigPath,
		"--rfc2136-acme-allow", "127.0.0.0/8",
	)

	tok := "knot-token-abcdefghijklmnopqrstuvwxyz0123456789"
	script := fmt.Sprintf("server %s %s\nzone at.example.com\nupdate add _acme-challenge.knot.at.example.com 60 TXT \"%s\"\nsend\n", host, port, tok)

	cmd := exec.Command(knsupdate, "-y", "hmac-sha256:"+keyName+":"+secret)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "knsupdate failed: %s", out)

	require.Eventually(t, func() bool {
		buf, err := os.ReadFile(srv.zonePath)
		return err == nil && strings.Contains(string(buf), tok)
	}, 10*time.Second, 100*time.Millisecond, "zone file was not updated by knsupdate")
}

func TestZoneomaticRFC2136UpdateListenerE2E(t *testing.T) {
	nsupdate, err := exec.LookPath("nsupdate")
	if err != nil {
		t.Skip("nsupdate not installed")
	}

	tsigPath := filepath.Join(t.TempDir(), "tsig.conf")
	secret := "YlZQY3QDIVu4vaD+7ZXhCQJ0NOn35EIvPrR52PP14kQ="
	require.NoError(t, os.WriteFile(tsigPath, []byte(
		"key \"certmanager.example.com\" {\n\talgorithm hmac-sha256;\n\tsecret \""+secret+"\";\n};\n"), 0600))

	dnsAddr := freeListenAddr(t)
	host, port, err := net.SplitHostPort(dnsAddr)
	require.NoError(t, err)

	srv := startZoneomaticWithArgs(t,
		"--rfc2136-update-listen", dnsAddr,
		"--rfc2136-update-tsig-file", tsigPath,
		"--rfc2136-update-max-ttl", "30",
	)

	// Packet TTL 300 must be capped to the configured 30.
	cmd := exec.Command(nsupdate, "-k", tsigPath)
	cmd.Stdin = strings.NewReader(fmt.Sprintf(
		"server %s %s\nzone at.example.com\nupdate add www.at.example.com 300 A 192.0.2.10\nsend\n", host, port))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "nsupdate failed: %s", out)

	require.Eventually(t, func() bool {
		buf, err := os.ReadFile(srv.zonePath)
		if err != nil {
			return false
		}
		return strings.Contains(string(buf), "www") && strings.Contains(string(buf), "192.0.2.10")
	}, 10*time.Second, 100*time.Millisecond, "zone file was not updated")

	buf, err := os.ReadFile(srv.zonePath)
	require.NoError(t, err)
	assert.Regexp(t, `www\s+30\s+IN\s+A\s+192\.0\.2\.10`, string(buf), "expected TTL to be capped to 30")
}

func TestZoneomaticRFC2136DisabledByDefault(t *testing.T) {
	srv := startZoneomatic(t)

	// No DNS listener should be present; the HTTP server is up.
	resp, err := http.Get(srv.baseURL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close() // nolint:errcheck
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func startZoneomatic(t *testing.T) *runningServer {
	t.Helper()
	return startZoneomaticWithArgs(t)
}

func startZoneomaticWithArgs(t *testing.T, extraArgs ...string) *runningServer {
	t.Helper()
	return startZoneomaticConfigured(t, nil, extraArgs...)
}

func startZoneomaticConfigured(t *testing.T, extraEnv []string, extraArgs ...string) *runningServer {
	t.Helper()

	repoRoot := repositoryRoot(t)
	zonePath := copyFixture(t, filepath.Join(repoRoot, "internal", "zone", "testdata", "at.example.com.zone"))
	htpasswdPath := writeHTPasswd(t)
	listenAddr := freeListenAddr(t)
	baseURL := "http://" + listenAddr

	args := []string{
		"--htpasswd", htpasswdPath,
		"--zone", zonePath,
		"--listen", listenAddr,
		"--debug",
	}
	args = append(args, extraArgs...)

	logs := bytes.NewBuffer(nil)
	cmd := exec.Command(zoneomaticBinary(t), args...)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), extraEnv...)
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
	req.Header.Set("X-API-Key", pdnsAPIKey("e2e", e2eAPIKey))
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

func pdnsAPIKey(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}
