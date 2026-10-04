package zone

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const commentsBase = "$ORIGIN c.example.com.\n$TTL 60\n@ IN SOA ns1.example.com. hostmaster.example.com. 1763822925 1H 600 1W 1D\n@ IN NS ns1.example.com.\n"

// commentCases have a comment in every position a zone file allows.
var commentCases = map[string]string{
	"header":        "; header comment\n" + commentsBase,
	"origin-trail":  strings.Replace(commentsBase, "$ORIGIN c.example.com.", "$ORIGIN c.example.com. ; after origin", 1),
	"ttl-trail":     strings.Replace(commentsBase, "$TTL 60", "$TTL 60 ; after ttl", 1),
	"soa-multiline": "$ORIGIN c.example.com.\n$TTL 60\n@ IN SOA ns1.example.com. hostmaster.example.com. ( ; paren\n 1763822925 ; bump on every change\n 1H ; refresh note\n 600 ; retry note\n 1W ; expire note\n 1D ) ; minimum note\n@ IN NS ns1.example.com.\n",
	"rec-trail":     commentsBase + "www IN A 192.0.2.1 ; trailing A\n",
	"cont-trail":    commentsBase + "www IN A 192.0.2.1\n    IN AAAA 2001:db8::1 ; trailing AAAA\n",
	"double-semi":   commentsBase + ";; double\nwww IN A 192.0.2.1\n",
	"txt-multiline": commentsBase + "txt IN TXT ( \"one\" ; inside\n  \"two\" ) ; after\n",
	"indented":      commentsBase + "   ; indented comment\nwww IN A 192.0.2.1\n",
	"acme-trail":    commentsBase + "_acme-challenge IN TXT \"placeholder\" ; acme note\n",
	"eof-comment":   commentsBase + "; at end\n",
}

func commentTexts(src string) []string {
	var ret []string
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, ";"); i >= 0 {
			if c := strings.TrimSpace(strings.TrimLeft(line[i:], "; ")); c != "" {
				ret = append(ret, c)
			}
		}
	}
	return ret
}

func writeZone(t *testing.T, src string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.example.com.zone")
	require.NoError(t, os.WriteFile(p, []byte(src), 0o644))
	return p
}

func TestComments_KeptOnUpdate(t *testing.T) {
	for name, src := range commentCases {
		t.Run(name, func(t *testing.T) {
			p := writeZone(t, src)
			ctrl, err := New(p)
			require.NoError(t, err)

			// An unrelated update rewrites the whole file.
			require.NoError(t, ctrl.UpdateACMEChallenge(context.TODO(), "_acme-challenge.other.c.example.com.", "tok", EmptyPlaceholder))

			out, err := os.ReadFile(p)
			require.NoError(t, err)
			for _, c := range commentTexts(src) {
				assert.Contains(t, string(out), c, "comment lost:\n%s", out)
			}
		})
	}
}

func TestComments_CarriedOnReplace(t *testing.T) {
	ctx := context.TODO()

	t.Run("acme-placeholder", func(t *testing.T) {
		p := writeZone(t, commentCases["acme-trail"])
		ctrl, err := New(p)
		require.NoError(t, err)

		name := "_acme-challenge.c.example.com."
		require.NoError(t, ctrl.UpdateACMEChallenge(ctx, name, "tok-a", EmptyPlaceholder))
		require.NoError(t, ctrl.UpdateACMEChallenge(ctx, name, "tok-b", EmptyPlaceholder))
		require.NoError(t, ctrl.UpdateACMEChallenge(ctx, name, "", "tok-a"))
		require.NoError(t, ctrl.UpdateACMEChallenge(ctx, name, "", "tok-b"))

		out, err := os.ReadFile(p)
		require.NoError(t, err)
		assert.Equal(t, 1, strings.Count(string(out), "acme note"), "%s", out)
		assert.Equal(t, 1, strings.Count(string(out), `"placeholder"`), "%s", out)
	})

	t.Run("ddns-address", func(t *testing.T) {
		p := writeZone(t, commentCases["rec-trail"])
		ctrl, err := New(p)
		require.NoError(t, err)

		require.NoError(t, ctrl.UpdateDDNSAddress(ctx, "www.c.example.com.", []netip.Addr{netip.MustParseAddr("192.0.2.99")}))

		out, err := os.ReadFile(p)
		require.NoError(t, err)
		assert.Contains(t, string(out), "192.0.2.99")
		assert.NotContains(t, string(out), "192.0.2.1 ")
		assert.Contains(t, string(out), "trailing A", "%s", out)
	})
}

func TestComments_SerialDateKept(t *testing.T) {
	p := writeZone(t, commentCases["soa-multiline"])
	ctrl, err := New(p)
	require.NoError(t, err)

	for range 2 {
		require.NoError(t, ctrl.UpdateACMEChallenge(context.TODO(), "_acme-challenge.c.example.com.", "tok", EmptyPlaceholder))
		require.NoError(t, ctrl.UpdateACMEChallenge(context.TODO(), "_acme-challenge.c.example.com.", "", "tok"))
	}

	out, err := os.ReadFile(p)
	require.NoError(t, err)
	// One generated date, followed by the user's note, not accumulating.
	assert.Equal(t, 1, strings.Count(string(out), "; serial  "), "%s", out)
	assert.Equal(t, 1, strings.Count(string(out), "bump on every change"), "%s", out)
	assert.Contains(t, string(out), "refresh note")
}
