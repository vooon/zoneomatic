package zone

import (
	"bytes"
	"context"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/vooon/go-masterfile"
)

// FuzzZoneSave runs an unrelated update over arbitrary zone files. The
// update may fail, but must not panic, and a written file must keep every
// record and comment of the original, as read by miekg/dns.
func FuzzZoneSave(f *testing.F) {
	for _, src := range commentCases {
		f.Add([]byte(src))
	}
	for _, name := range []string{"at.example.com.zone", "mx.example.com.zone", "acme-apex-at.zone", "3.2.1.in-addr.arpa.zone"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, src []byte) {
		p := filepath.Join(t.TempDir(), "fuzz.zone")
		if err := os.WriteFile(p, src, 0o644); err != nil {
			t.Fatal(err)
		}
		ctrl, err := New(p)
		if err != nil {
			return
		}
		zones, err := ctrl.ListZones(context.TODO())
		if err != nil || len(zones) != 1 {
			return
		}
		origin := zones[0].Name

		// Only zones that the reference parser accepts are interesting.
		// zoneomatic reads $ORIGIN as absolute and writes it that way.
		before, err := masterfile.Records(origin, absoluteOrigins(src))
		if err != nil {
			return
		}
		// Only the user-written parts count: the serial's generated date
		// changes with every bump.
		rawComments, err := masterfile.Comments(src)
		if err != nil {
			return
		}
		var comments []string
		for _, c := range rawComments {
			if user := strings.TrimSpace(masterfile.UserComment(c)); user != "" {
				comments = append(comments, user)
			}
		}
		// Skip inputs the two parsers read differently (e.g. miekg/dns
		// rejects or merges fields of a multi-line SOA that starts with
		// "(name"): that is a disagreement about the input, not a save bug.
		z, err := ctrl.(*DomainCtrl).files[0].load()
		if err != nil {
			return
		}
		plain := bytes.NewBuffer(nil)
		if err := z.WritePlain(plain); err != nil {
			t.Fatal(err)
		}
		if ours, err := masterfile.Records(origin, plain.Bytes()); err != nil || !maps.Equal(ours, before) {
			return
		}

		if err := ctrl.UpdateACMEChallenge(context.TODO(), "_acme-challenge.zz-fuzz."+origin, "tok", EmptyPlaceholder); err != nil {
			return
		}

		out, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		after, err := masterfile.Records(origin, out)
		if err != nil {
			t.Fatalf("written zone does not parse: %v\n--- input\n%s\n--- output\n%s", err, src, out)
		}
		for rr, n := range before {
			if after[rr] < n {
				t.Fatalf("record lost: %s\n--- input\n%s\n--- output\n%s", rr, src, out)
			}
		}
		outComments, _ := masterfile.Comments(out)
		all := ""
		for _, c := range outComments {
			all += c + "\n"
		}
		for _, c := range comments {
			if !contains(all, c) {
				t.Fatalf("comment lost: %q\n--- input\n%s\n--- output\n%s", c, src, out)
			}
		}
	})
}

// originRE finds $ORIGIN values, split like the zonefile lexer does (on
// space, tab, CR, LF and ';').
var originRE = regexp.MustCompile(`(?m)^(\$ORIGIN[ \t]+)([^ \t\r\n;]+)`)

// absoluteOrigins makes $ORIGIN values fully qualified, as zoneomatic reads
// and writes them.
func absoluteOrigins(src []byte) []byte {
	return originRE.ReplaceAllFunc(src, func(m []byte) []byte {
		sub := originRE.FindSubmatch(m)
		return append(sub[1], dns.Fqdn(string(sub[2]))...)
	})
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
