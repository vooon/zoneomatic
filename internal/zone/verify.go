package zone

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/vooon/zoneomatic/pkg/dnsfmt"
	"github.com/vooon/zoneomatic/pkg/zonefile"
)

// ErrUnsafeWrite is returned when a reformatted zone file would differ from
// the intended content, so it is not written.
var ErrUnsafeWrite = errors.New("refusing to write zone file")

// verifyReformat checks that formatted, the output of dnsfmt, holds exactly
// the same records as plain (the unformatted text it was produced from) and
// keeps all of its comments. miekg/dns is the reference parser. The SOA
// serial is ignored: reformatting bumps it on purpose.
func verifyReformat(origin string, plain, formatted []byte) error {
	want, err := zoneRecords(origin, plain)
	if err != nil {
		return fmt.Errorf("%w: unformatted zone does not parse: %w", ErrUnsafeWrite, err)
	}
	got, err := zoneRecords(origin, formatted)
	if err != nil {
		return fmt.Errorf("%w: formatted zone does not parse: %w", ErrUnsafeWrite, err)
	}
	if !maps.Equal(want, got) {
		return fmt.Errorf("%w: records changed by formatting: %s", ErrUnsafeWrite, recordsDiff(want, got))
	}

	wantComments, err := zoneComments(plain)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeWrite, err)
	}
	gotComments, err := zoneComments(formatted)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeWrite, err)
	}
	all := strings.Join(gotComments, "\n")
	for _, c := range wantComments {
		if !strings.Contains(all, c) {
			return fmt.Errorf("%w: comment lost by formatting: %q", ErrUnsafeWrite, c)
		}
	}

	return nil
}

// zoneRecords parses a zone with miekg/dns and returns its records as a
// multiset of their text form, with the SOA serial zeroed.
func zoneRecords(origin string, data []byte) (map[string]int, error) {
	ret := map[string]int{}
	zp := dns.NewZoneParser(bytes.NewReader(data), dns.Fqdn(origin), "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if soa, isSOA := rr.(*dns.SOA); isSOA {
			soa.Serial = 0
		}
		ret[strings.ToLower(rr.String())]++
	}
	return ret, zp.Err()
}

// zoneComments returns the comment texts of a zone, without the parts
// dnsfmt generates itself.
func zoneComments(data []byte) ([]string, error) {
	zf, perr := zonefile.Load(data)
	if perr != nil {
		return nil, perr
	}

	var ret []string
	for _, e := range zf.Entries() {
		for _, c := range e.Comments() {
			if user := bytes.TrimSpace(dnsfmt.UserComment(c)); len(user) > 0 {
				ret = append(ret, string(user))
			}
		}
	}
	return ret, nil
}

func recordsDiff(want, got map[string]int) string {
	var diff []string
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if got[k] < want[k] {
			diff = append(diff, "-"+k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(got)) {
		if want[k] < got[k] {
			diff = append(diff, "+"+k)
		}
	}
	return strings.Join(diff, "; ")
}
