//go:build k3d

// Package k3d_test issues a real certificate with cert-manager's rfc2136
// solver against zoneomatic, inside a throwaway k3d (k3s) cluster:
//
//	cert-manager --RFC2136/TSIG--> zoneomatic --zone file--> CoreDNS <--dns-01-- Pebble
//
// Requires docker (or a compatible runtime), k3d, kubectl and helm. Set
// ZM_K3D_KEEP=1 to keep the cluster after the test for debugging.
package k3d_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	certManagerVersion = "v1.21.2"
	pebbleImage        = "ghcr.io/letsencrypt/pebble:2.10.1"
	coreDNSImage       = "docker.io/coredns/coredns:1.12.4"
	busyboxImage       = "docker.io/library/busybox:1.37"
	zoneomaticImage    = "localhost/zoneomatic:k3d-e2e"

	namespace   = "zoneomatic"
	zoneName    = "at.example.com"
	tsigKeyName = "cert-manager.example.com"
)

type env struct {
	t          *testing.T
	cluster    string
	kubeconfig string
	root       string
}

func TestCertManagerRFC2136(t *testing.T) {
	for _, tool := range []string{"docker", "k3d", "kubectl", "helm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}

	e := &env{t: t, cluster: fmt.Sprintf("zm-e2e-%d", os.Getpid()), root: repositoryRoot(t)}
	e.kubeconfig = filepath.Join(t.TempDir(), "kubeconfig")

	image := e.buildImage()
	e.createCluster(image)

	tsigSecret := randomSecret(t)
	vars := map[string]any{
		"Namespace":       namespace,
		"ZoneName":        zoneName,
		"TSIGKeyName":     tsigKeyName,
		"TSIGSecret":      tsigSecret,
		"HTPasswd":        htpasswdLine(t),
		"Zone":            e.readFile("internal/zone/testdata/at.example.com.zone"),
		"ZoneomaticImage": zoneomaticImage,
		"CoreDNSImage":    coreDNSImage,
		"BusyboxImage":    busyboxImage,
		"PebbleImage":     pebbleImage,
	}

	e.apply("zoneomatic.yaml.tmpl", vars)
	e.kubectl("-n", namespace, "rollout", "status", "deployment/zoneomatic", "--timeout=3m")

	svcIP := strings.TrimSpace(e.kubectl("-n", namespace, "get", "service", "zoneomatic", "-o", "jsonpath={.spec.clusterIP}"))
	require.NotEmpty(t, svcIP)
	dnsServer := svcIP + ":53"
	vars["DNSServer"] = dnsServer
	vars["RFC2136Server"] = svcIP + ":5353"

	e.apply("pebble.yaml.tmpl", vars)

	// cert-manager must look up the zone and check propagation against the
	// server that serves zoneomatic's zone file, not the public DNS.
	e.run("helm", "install", "cert-manager", "cert-manager",
		"--kubeconfig", e.kubeconfig,
		"--repo", "https://charts.jetstack.io",
		"--version", certManagerVersion,
		"--namespace", "cert-manager", "--create-namespace",
		"--set", "crds.enabled=true",
		"--set-json", fmt.Sprintf(`extraArgs=["--dns01-recursive-nameservers-only","--dns01-recursive-nameservers=%s","--dns01-check-retry-period=2s"]`, dnsServer),
		"--wait", "--timeout", "5m",
	)
	e.kubectl("-n", namespace, "rollout", "status", "deployment/pebble", "--timeout=3m")

	e.apply("issuer.yaml.tmpl", vars)

	if _, err := e.kubectlErr("-n", namespace, "wait", "certificate/zoneomatic-test", "--for=condition=Ready", "--timeout=5m"); err != nil {
		e.dumpState()
		t.Fatalf("certificate did not become ready: %v", err)
	}

	// Ready is set once the certificate is issued; the challenges are cleaned
	// up afterwards. Wait for that, so the CleanUp path is covered as well.
	ok := eventually(3*time.Minute, func() bool {
		out, err := e.kubectlErr("-n", namespace, "get", "challenges.acme.cert-manager.io", "-o", "name")
		return err == nil && strings.TrimSpace(out) == ""
	})
	if !ok {
		e.dumpState()
		t.Fatal("ACME challenges were not cleaned up")
	}

	zone := e.zoneFile()
	t.Logf("final zone file:\n%s", zone)

	challenges := 0
	zp := dns.NewZoneParser(strings.NewReader(zone), zoneName+".", "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		txt, isTXT := rr.(*dns.TXT)
		if !isTXT || !strings.EqualFold(txt.Hdr.Name, "_acme-challenge."+zoneName+".") {
			continue
		}
		challenges++
		require.Equal(t, []string{"placeholder"}, txt.Txt, "challenge token left in zone: %s", txt)
	}
	require.NoError(t, zp.Err())
	require.NotZero(t, challenges, "no _acme-challenge entry in zone; present never reached zoneomatic")

	zmLogs := e.kubectl("-n", namespace, "logs", "deployment/zoneomatic", "-c", "zoneomatic")
	require.NotContains(t, zmLogs, "RFC2136 update failed", "zoneomatic logs:\n%s", zmLogs)
	require.Contains(t, zmLogs, "class=NONE", "no cleanup (class NONE) update was received:\n%s", zmLogs)

	cmLogs := e.kubectl("-n", "cert-manager", "logs", "deployment/cert-manager")
	require.NotContains(t, cmLogs, "DNS update failed", "cert-manager logs:\n%s", cmLogs)
}

// buildImage builds the zoneomatic image from the release Dockerfile.
func (e *env) buildImage() string {
	ctxDir := e.t.TempDir()
	platform := "linux/" + runtime.GOARCH

	bin := filepath.Join(ctxDir, platform, "zoneomatic")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/zoneomatic")
	cmd.Dir = e.root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	out, err := cmd.CombinedOutput()
	require.NoError(e.t, err, "go build failed: %s", out)

	e.run("docker", "build",
		"-f", filepath.Join(e.root, "Dockerfile"),
		"--build-arg", "TARGETPLATFORM="+platform,
		"-t", zoneomaticImage,
		ctxDir,
	)
	return zoneomaticImage
}

func (e *env) createCluster(image string) {
	e.run("k3d", "cluster", "create", e.cluster,
		"--no-lb",
		"--k3s-arg", "--disable=traefik@server:0",
		"--kubeconfig-update-default=false",
		"--kubeconfig-switch-context=false",
		"--wait", "--timeout", "3m",
	)
	e.t.Cleanup(func() {
		if os.Getenv("ZM_K3D_KEEP") != "" {
			e.t.Logf("keeping cluster %s (kubeconfig: k3d kubeconfig get %s)", e.cluster, e.cluster)
			return
		}
		_, _ = exec.Command("k3d", "cluster", "delete", e.cluster).CombinedOutput()
	})

	kc := e.run("k3d", "kubeconfig", "get", e.cluster)
	require.NoError(e.t, os.WriteFile(e.kubeconfig, []byte(kc), 0600))

	e.run("k3d", "image", "import", "--cluster", e.cluster, image)
}

func (e *env) apply(name string, vars map[string]any) {
	cmd := exec.Command("kubectl", "--kubeconfig", e.kubeconfig, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(e.render(name, vars))
	out, err := cmd.CombinedOutput()
	require.NoError(e.t, err, "kubectl apply %s failed: %s", name, out)
}

func (e *env) render(name string, vars map[string]any) string {
	tmpl := template.Must(template.New(name).Funcs(template.FuncMap{
		"indent": func(n int, s string) string {
			pad := strings.Repeat(" ", n)
			return pad + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n"+pad)
		},
	}).ParseFiles(filepath.Join(e.root, "tests/k3d/testdata", name)))

	var buf bytes.Buffer
	require.NoError(e.t, tmpl.Execute(&buf, vars))
	return buf.String()
}

func (e *env) zoneFile() string {
	return e.kubectl("-n", namespace, "exec", "deployment/zoneomatic", "-c", "tools", "--",
		"cat", "/zones/"+zoneName+".zone")
}

func (e *env) dumpState() {
	for _, args := range [][]string{
		{"-n", namespace, "describe", "certificates,certificaterequests,orders,challenges"},
		{"-n", namespace, "logs", "deployment/zoneomatic", "-c", "zoneomatic"},
		{"-n", namespace, "logs", "deployment/zoneomatic", "-c", "coredns"},
		{"-n", namespace, "logs", "deployment/pebble"},
		{"-n", "cert-manager", "logs", "deployment/cert-manager"},
		{"-n", namespace, "exec", "deployment/zoneomatic", "-c", "tools", "--", "cat", "/zones/" + zoneName + ".zone"},
	} {
		out, _ := e.kubectlErr(args...)
		e.t.Logf("$ kubectl %s\n%s", strings.Join(args, " "), out)
	}
}

func (e *env) kubectl(args ...string) string {
	e.t.Helper()
	out, err := e.kubectlErr(args...)
	require.NoError(e.t, err, "kubectl %s: %s", strings.Join(args, " "), out)
	return out
}

func (e *env) kubectlErr(args ...string) (string, error) {
	out, err := exec.Command("kubectl", append([]string{"--kubeconfig", e.kubeconfig}, args...)...).CombinedOutput()
	return string(out), err
}

func (e *env) run(name string, args ...string) string {
	e.t.Helper()
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	require.NoError(e.t, err, "%s %s failed:\n%s%s", name, strings.Join(args, " "), stdout.String(), stderr.String())
	return stdout.String()
}

func (e *env) readFile(rel string) string {
	b, err := os.ReadFile(filepath.Join(e.root, rel))
	require.NoError(e.t, err)
	return string(b)
}

func eventually(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

func randomSecret(t *testing.T) string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(b)
}

func htpasswdLine(t *testing.T) string {
	hash, err := bcrypt.GenerateFromPassword([]byte("unused"), bcrypt.MinCost)
	require.NoError(t, err)
	return "k3d:" + string(hash)
}

func repositoryRoot(t *testing.T) string {
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
