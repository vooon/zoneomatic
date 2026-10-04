package dnsfmt

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/miekg/dns"
	"github.com/vooon/zoneomatic/pkg/zonefile"
)

func Reformat(data, origin []byte, w io.Writer, incrementSerial bool) error {
	origin = zonefile.Fqdn(origin)

	zf, perr := zonefile.Load(data)
	if perr != nil {
		return fmt.Errorf("dnsfmt: parse error on line %d: %w", perr.LineNo, perr)
	}

	// 2 loops: finding and striping the  origin and some admin, and then actually reformatting.

	single := map[string]int{}
	longestname := 0
	prevname := []byte{}
	entries := zf.Entries()
	for i := range entries {
		e := &entries[i]
		if e.IsComment {
			continue
		}
		if e.IsControl {
			if bytes.Equal(e.Command(), []byte("$ORIGIN")) {
				origin = zonefile.Fqdn(e.Values()[0])
			}
			continue
		}

		if err := e.SetDomain(StripOrigin(origin, e.Domain())); err != nil {
			return fmt.Errorf("set domain: %w", err)
		}

		// count number of types per name, as we want to group singletons.
		if !bytes.Equal(prevname, e.Domain()) && len(prevname) > 0 {
			if len(e.Domain()) > 0 {
				single[string(e.Domain())] += 1
			} else {
				single[string(prevname)] += 1
			}
		}

		// Strip origin from selected records.
		values := e.Values()
		switch e.RRType() {
		case dns.TypeSOA:
			if len(values) < 3 {
				return fmt.Errorf("malformed SOA RR: %v", values)
			}
			if len(origin) == 0 { // $ORIGIN not set take from SOA
				origin = zonefile.Fqdn(e.Domain())
			}

			if err := e.SetValue(0, StripOrigin(origin, values[0])); err != nil {
				return fmt.Errorf("set SOA mname: %w", err)
			}
			if err := e.SetValue(1, StripOrigin(origin, values[1])); err != nil {
				return fmt.Errorf("set SOA rname: %w", err)
			}

		case dns.TypeSRV:
			if len(values) < 4 {
				return fmt.Errorf("malformed SRV RR: %v", values)
			}
			if err := e.SetValue(3, StripOrigin(origin, values[3])); err != nil {
				return fmt.Errorf("set SRV target: %w", err)
			}

		case dns.TypeRRSIG:
			if len(values) < 8 {
				return fmt.Errorf("malformed RRSIG RR: %v", values)
			}
			if err := e.SetValue(7, StripOrigin(origin, values[7])); err != nil {
				return fmt.Errorf("set RRSIG signer: %w", err)
			}

		case dns.TypeMX:
			if len(values) < 2 {
				return fmt.Errorf("malformed MX RR: %v", values)
			}
			if err := e.SetValue(1, StripOrigin(origin, values[1])); err != nil {
				return fmt.Errorf("set MX exchange: %w", err)
			}

		case dns.TypePTR:
			fallthrough
		case dns.TypeNS:
			fallthrough
		case dns.TypeCNAME:
			fallthrough
		case dns.TypeNSEC:
			if len(values) < 1 {
				return fmt.Errorf("malformed RR: %v", values)
			}
			if err := e.SetValue(0, StripOrigin(origin, values[0])); err != nil {
				return fmt.Errorf("set rr target: %w", err)
			}
		}

		if l := len(e.Domain()); l > longestname {
			longestname = l
		}
		if len(e.Domain()) > 0 {
			prevname = e.Domain()
		}
	}
	longestname += 2 // extra indent (we already take the origin into account)

	prevname = []byte{}
	prevtype := []byte{}
	prevttl := 0
	prevcom := false
	firstname := true
	for _, e := range zf.Entries() {
		if e.IsComment {
			if !prevcom && !firstname {
				fmt.Fprintln(w)
			}
			for _, c := range e.Comments() {
				fmt.Fprintf(w, "%s\n", c)
			}
			prevcom = true
			prevname = []byte{}
			prevtype = []byte{}
			continue
		}
		if e.IsControl {
			values := e.RawValues()
			if bytes.Equal(e.Command(), []byte("$ORIGIN")) && len(values) > 0 {
				// The origin is used as absolute; a missing trailing dot
				// would make other parsers read it relative to the zone.
				values = append([][]byte{zonefile.Fqdn(values[0])}, values[1:]...)
			}
			fmt.Fprintf(w, "%s %s%s\n", e.Command(), bytes.Join(values, []byte(" ")), trailing(e.Comments()))
			prevcom = false
			prevname = []byte{}
			prevtype = []byte{}
			continue
		}

		if !bytes.Equal(prevname, e.Domain()) {
			// keep comments near, don't add a newline when previous line was comment.
			// first record doesn't need a newline
			if len(e.Domain()) > 0 && !prevcom && !firstname {
				v, _ := single[string(prevname)]
				// names /w multiple types get a newline
				if v > 1 {
					fmt.Fprintln(w)
				}
				// single type names together, except when types differ
				if v == 1 && !bytes.Equal(prevtype, e.Type()) {
					fmt.Fprintln(w)
				}
			}
			fmt.Fprintf(w, "%-*s", longestname, e.Domain())
		} else {
			fmt.Fprintf(w, "%-*s", longestname, "")
		}

		prevcom = false
		firstname = false

		if ttl := e.TTL(); ttl != nil && *ttl != prevttl {
			prevttl = *ttl
			fmt.Fprintf(w, "%10s", TimeToHuman(ttl))
		} else {
			fmt.Fprintf(w, "%10s", " ")
		}

		if len(e.Class()) > 0 {
			fmt.Fprintf(w, "%5s", e.Class())
		} else {
			fmt.Fprintf(w, "%5s", "IN")
		}
		fmt.Fprintf(w, "   %-8s", e.Type())

		// Specicial handling for certain RR types. Comments are kept next to
		// the value they follow.
		values := e.Values()
		raw := e.RawValues()
		head, after := e.ValueComments()
		switch e.RRType() {
		case dns.TypeTXT, dns.TypeSPF:
			quoted := make([][]byte, len(values))
			for i, v := range values {
				quoted[i] = []byte(Quote(v))
			}
			writeValues(w, longestname, quoted, head, after, len(values) > 1)

		case dns.TypeCAA:
			rendered := make([][]byte, len(values))
			for i, v := range values {
				if i < 2 {
					rendered[i] = v
				} else {
					rendered[i] = []byte(Quote(v))
				}
			}
			writeValues(w, longestname, rendered, head, after, false)

		case dns.TypeSOA:
			if len(values) != 7 {
				return fmt.Errorf("malformed SOA RR: %v", values)
			}
			fmt.Fprintf(w, "%s%s (%s\n", Space3, bytes.Join(raw[:2], []byte(" ")), trailing(append(head, slices.Concat(after[:2]...)...)))
			for i, v := range values[2:] {
				comment := ""
				if len(after[i+2]) > 0 {
					comment = " " + string(bytes.Join(after[i+2], []byte(" ")))
				}
				if i == 0 {
					if incrementSerial {
						v = Increase(v)
					}
					// Always show the serial as a date; keep the user's own
					// comment after it.
					comment = " " + soacomment[0] + SerialToHuman(v)
					for _, c := range after[2] {
						if user := UserComment(c); len(user) > 0 {
							comment += " " + string(user)
						}
					}
				} else {
					v = bytes.ToUpper(TimeToHumanByte(v))
					if comment == "" || isGeneratedSOAComment(after[i+2], i) {
						comment = " " + soacomment[i]
					}
				}
				fmt.Fprintf(w, "%-*s%s%-12s%s\n", longestname+Indent, " ", Space3, v, comment)
			}
			closeBrace(w, longestname)

		case dns.TypeCDS, dns.TypeDS, dns.TypeCDNSKEY, dns.TypeDNSKEY, dns.TypeRRSIG:
			n := 3
			if e.RRType() == dns.TypeRRSIG {
				n = 8
			}
			if len(values) < n+1 {
				return fmt.Errorf("malformed RR: %v", values)
			}
			comments := trailing(append(head, slices.Concat(after...)...))
			pieces := Split(bytes.Join(values[n:], nil), 55)
			if len(pieces) == 1 && e.RRType() != dns.TypeRRSIG {
				fmt.Fprintf(w, "%s%s%s\n", Space3, bytes.Join(raw, []byte(" ")), comments)
				break
			}

			fmt.Fprintf(w, "%s%s (%s\n", Space3, bytes.Join(raw[:n], []byte(" ")), comments)
			for _, p := range pieces {
				fmt.Fprintf(w, "%-*s%s%-13s\n", longestname+Indent, " ", Space3, p)
			}
			closeBrace(w, longestname)

		default:
			writeValues(w, longestname, raw, head, after, false)
		}

		if len(e.Domain()) > 0 {
			prevname = e.Domain()
		}
		prevtype = e.Type()
	}
	return nil
}

const (
	Space3 = "   "
	Indent = 29
)

var soacomment = []string{"; serial", "; refresh", "; retry", "; expire", "; minimum"}

// isGeneratedSOAComment reports whether the comments of SOA field i are the
// label dnsfmt writes itself (and should regenerate), not the user's.
func isGeneratedSOAComment(comments [][]byte, i int) bool {
	return len(comments) == 1 && string(comments[0]) == soacomment[i]
}

// generatedSerialRE matches the serial comment dnsfmt writes: "; serial"
// optionally followed by the serial as a date.
var generatedSerialRE = regexp.MustCompile(`^;\s*serial(?:\s+[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} UTC)?`)

// UserComment returns the part of a comment that was not generated by dnsfmt:
// for the SOA serial comment, whatever follows "; serial <date>". Other
// comments are returned unchanged. The result may be empty.
func UserComment(c []byte) []byte {
	if loc := generatedSerialRE.FindIndex(c); loc != nil {
		return bytes.TrimSpace(c[loc[1]:])
	}
	return c
}

// trailing renders comments for the end of a line (joined, as only one
// comment fits on a line), or "" when there are none.
func trailing(comments [][]byte) string {
	if len(comments) == 0 {
		return ""
	}
	return "   " + string(bytes.Join(comments, []byte(" ")))
}

// writeValues writes record values after the type. They stay on one line
// unless multi is set or a comment precedes a value other than the last;
// then each value gets its own line inside ( ), followed by its comments.
func writeValues(w io.Writer, longestname int, values [][]byte, head [][]byte, after [][][]byte, multi bool) {
	for i := 0; i+1 < len(after); i++ {
		multi = multi || len(after[i]) > 0
	}
	multi = multi || len(head) > 0

	if !multi {
		var last [][]byte
		if len(after) > 0 {
			last = after[len(after)-1]
		}
		fmt.Fprintf(w, "%s%s%s\n", Space3, bytes.Join(values, []byte(" ")), trailing(last))
		return
	}

	fmt.Fprintf(w, "%s(%s\n", Space3, trailing(head))
	for i, v := range values {
		fmt.Fprintf(w, "%-*s%s%s%s\n", longestname+Indent, " ", Space3, v, trailing(after[i]))
	}
	closeBrace(w, longestname)
}

func closeBrace(w io.Writer, longestname int) {
	fmt.Fprintf(w, "%-*s)\n", longestname+Indent+3, " ")
}

func Split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf)
	}
	return chunks
}

// StripOrigin makes name relative to origin, or "@" for the origin itself.
// Names outside the origin are returned unchanged; the suffix must match on
// a label boundary (case-insensitively), so "myexample.com." is not taken
// as part of "example.com.".
func StripOrigin(origin, name []byte) []byte {
	if len(origin) == 0 || len(name) < len(origin) {
		return name
	}
	l := len(name) - len(origin)
	if !bytes.EqualFold(name[l:], origin) {
		return name
	}
	if l == 0 {
		return []byte("@")
	}
	if name[l-1] != '.' || (l >= 2 && name[l-2] == '\\') {
		return name
	}
	return name[:l-1]
}
