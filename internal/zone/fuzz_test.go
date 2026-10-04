package zone

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"
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
		before, err := zoneRecords(origin, absoluteOrigins(src))
		if err != nil {
			return
		}
		comments, err := zoneComments(src)
		if err != nil {
			return
		}

		if err := ctrl.UpdateACMEChallenge(context.TODO(), "_acme-challenge.zz-fuzz."+origin, "tok", EmptyPlaceholder); err != nil {
			return
		}

		out, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		after, err := zoneRecords(origin, out)
		if err != nil {
			t.Fatalf("written zone does not parse: %v\n--- input\n%s\n--- output\n%s", err, src, out)
		}
		for rr, n := range before {
			if after[rr] < n {
				t.Fatalf("record lost: %s\n--- input\n%s\n--- output\n%s", rr, src, out)
			}
		}
		outComments, _ := zoneComments(out)
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

var originRE = regexp.MustCompile(`(?m)^(\$ORIGIN[ \t]+[^\s;]*[^\s;.])([ \t;]|$)`)

func absoluteOrigins(src []byte) []byte {
	return originRE.ReplaceAll(src, []byte("$1.$2"))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
