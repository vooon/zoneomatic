//go:build k3d

// Package k3d_test checks that cert-manager's rfc2136 solver can issue
// certificates through zoneomatic's ACME-only RFC2136 listener:
//
//	cert-manager --RFC2136/TSIG--> zoneomatic --zone file--> CoreDNS <--dns-01-- Pebble
//
// The stack is deployed by `make k3d-cluster k3d-build k3d-deploy` (or just
// `make k3d`); this test only creates Certificates and checks the outcome, so
// it can be re-run against the same cluster.
package k3d_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	namespace = "zoneomatic-e2e"
	zoneName  = "at.example.com."
	zonePath  = "/zones/at.example.com.zone"
	issuer    = "zoneomatic-pebble"
)

// dnsNames covers the apex and wildcard sharing _acme-challenge, plus a name
// that has no entry in the zone at all.
var dnsNames = []string{"at.example.com", "*.at.example.com", "s3.at.example.com"}

var challengeNames = []string{"_acme-challenge.at.example.com.", "_acme-challenge.s3.at.example.com."}

func TestCertManagerRFC2136(t *testing.T) {
	// Never fall back to the default kubectl context.
	if os.Getenv("KUBECONFIG") == "" {
		t.Skip("KUBECONFIG not set; run via `make k3d-test`")
	}

	// Two rounds: the second one starts from the placeholders left by the
	// first cleanup.
	for round := 1; round <= 2; round++ {
		t.Run(fmt.Sprintf("round-%d", round), func(t *testing.T) {
			issueCertificate(t, fmt.Sprintf("zm-test-%d-%d", time.Now().Unix(), round))
		})
	}
}

func issueCertificate(t *testing.T, name string) {
	since := time.Now().UTC().Format(time.RFC3339)

	kubectlApply(t, fmt.Sprintf(`apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  secretName: %[1]s-tls
  dnsNames: ["%[3]s"]
  issuerRef:
    kind: ClusterIssuer
    name: %[4]s
`, name, namespace, strings.Join(dnsNames, `", "`), issuer))
	t.Cleanup(func() {
		_, _ = kubectlNoFail("-n", namespace, "delete", "certificate", name, "--ignore-not-found")
		_, _ = kubectlNoFail("-n", namespace, "delete", "secret", name+"-tls", "--ignore-not-found")
	})

	if out, err := kubectlNoFail("-n", namespace, "wait", "certificate/"+name, "--for=condition=Ready", "--timeout=5m"); err != nil {
		dumpState(t)
		t.Fatalf("certificate %s did not become ready: %v\n%s", name, err, out)
	}

	// Ready is set once the certificate is issued; challenges are cleaned up
	// afterwards. Wait for that so the CleanUp path is covered as well.
	if !eventually(3*time.Minute, func() bool {
		out, err := kubectlNoFail("-n", namespace, "get", "challenges.acme.cert-manager.io", "-o", "name")
		return err == nil && strings.TrimSpace(out) == ""
	}) {
		dumpState(t)
		t.Fatal("ACME challenges were not cleaned up")
	}

	zone := kubectl(t, "-n", namespace, "exec", "deployment/zoneomatic", "-c", "zoneomatic", "--", "cat", zonePath)
	t.Logf("zone file after cleanup:\n%s", zone)

	txt := map[string][]string{}
	zp := dns.NewZoneParser(strings.NewReader(zone), zoneName, "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if r, isTXT := rr.(*dns.TXT); isTXT {
			n := strings.ToLower(r.Hdr.Name)
			txt[n] = append(txt[n], strings.Join(r.Txt, ""))
		}
	}
	require.NoError(t, zp.Err())
	for _, n := range challengeNames {
		assert.Equal(t, []string{"placeholder"}, txt[n], "TXT records of %s", n)
	}

	zmLogs := kubectl(t, "-n", namespace, "logs", "deployment/zoneomatic", "-c", "zoneomatic", "--since-time="+since)
	assert.NotContains(t, zmLogs, "RFC2136 update failed")
	assert.Contains(t, zmLogs, "class=NONE", "no cleanup (class NONE) update was received")

	cmLogs := kubectl(t, "-n", "cert-manager", "logs", "deployment/cert-manager", "--since-time="+since)
	assert.NotContains(t, cmLogs, "DNS update failed")

	if t.Failed() {
		t.Logf("zoneomatic logs:\n%s", zmLogs)
	}
}

func dumpState(t *testing.T) {
	t.Helper()
	for _, args := range [][]string{
		{"-n", namespace, "describe", "certificates,certificaterequests,orders,challenges"},
		{"-n", namespace, "logs", "deployment/zoneomatic", "-c", "zoneomatic", "--tail=200"},
		{"-n", namespace, "logs", "deployment/zoneomatic", "-c", "coredns", "--tail=100"},
		{"-n", namespace, "logs", "deployment/pebble", "--tail=100"},
		{"-n", "cert-manager", "logs", "deployment/cert-manager", "--tail=200"},
		{"-n", namespace, "exec", "deployment/zoneomatic", "-c", "zoneomatic", "--", "cat", zonePath},
	} {
		out, _ := kubectlNoFail(args...)
		t.Logf("$ kubectl %s\n%s", strings.Join(args, " "), out)
	}
}

func kubectlApply(t *testing.T, manifest string) {
	t.Helper()
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "kubectl apply failed: %s", out)
}

func kubectl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := kubectlNoFail(args...)
	require.NoError(t, err, "kubectl %s: %s", strings.Join(args, " "), out)
	return out
}

func kubectlNoFail(args ...string) (string, error) {
	out, err := exec.Command("kubectl", args...).CombinedOutput()
	return string(out), err
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
