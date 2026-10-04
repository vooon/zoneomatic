package dnsfmt

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"

	"github.com/miekg/dns"
	"github.com/vooon/zoneomatic/pkg/zonefile"
)

const (
	// maxNameWidth caps the owner name column; longer names overflow it.
	maxNameWidth = 24
	// indent is used for the lines of a multi-line ( ... ) value.
	indent = "    "
)

// Reformat writes the zone file in data in a compact, aligned layout:
//
//   - owner names are made relative to $ORIGIN and aligned in a column
//     (capped at maxNameWidth); a repeated owner is left blank
//   - a TTL column only appears when records have explicit TTLs
//   - values are written as they are (no rewriting of names or times),
//     multi-line values are indented by four spaces
//   - all comments are kept next to the value they follow, blank lines are
//     kept as in the input (runs collapsed to one)
//
// With incrementSerial the SOA serial is bumped (see Increase).
func Reformat(data, origin []byte, w io.Writer, incrementSerial bool) error {
	origin = zonefile.Fqdn(origin)

	zf, perr := zonefile.Load(data)
	if perr != nil {
		return fmt.Errorf("dnsfmt: parse error on line %d: %w", perr.LineNo, perr)
	}

	// First pass: relative owner names and column widths.
	nameWidth, ttlWidth, typeWidth := 0, 0, 0
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
		if e.RRType() == dns.TypeSOA {
			if len(e.Values()) != 7 {
				return fmt.Errorf("malformed SOA RR: %q", e.Values())
			}
			if len(origin) <= 1 && len(e.Domain()) > 0 { // $ORIGIN not set, take it from the SOA
				origin = zonefile.Fqdn(e.Domain())
			}
		}

		if err := e.SetDomain(StripOrigin(origin, e.Domain())); err != nil {
			return fmt.Errorf("set domain: %w", err)
		}

		nameWidth = max(nameWidth, len(e.Domain()))
		if ttl := e.TTL(); ttl != nil {
			ttlWidth = max(ttlWidth, len(strconv.Itoa(*ttl)))
		}
		typeWidth = max(typeWidth, len(e.Type()))
	}
	nameWidth = min(nameWidth, maxNameWidth)

	f := formatter{w: w, nameWidth: nameWidth, ttlWidth: ttlWidth, typeWidth: typeWidth}

	// Second pass: write. Blank lines are only written between other lines.
	var prevname []byte
	blank, wrote := false, false
	for _, e := range entries {
		if e.IsBlank() {
			blank = wrote
			prevname = nil
			continue
		}
		if blank {
			fmt.Fprintln(w)
			blank = false
		}
		wrote = true

		switch {
		case e.IsComment:
			for _, c := range e.Comments() {
				fmt.Fprintf(w, "%s\n", c)
			}
			prevname = nil

		case e.IsControl:
			values := e.RawValues()
			if bytes.Equal(e.Command(), []byte("$ORIGIN")) {
				// The origin is used as absolute; a missing trailing dot
				// would make other parsers read it relative to the zone.
				values = append([][]byte{zonefile.Fqdn(values[0])}, values[1:]...)
			}
			fmt.Fprintf(w, "%s %s%s\n", e.Command(), bytes.Join(values, []byte(" ")), trailing(e.Comments()))
			prevname = nil

		default:
			// A record without owner inherits it and stays that way. A
			// repeated owner is left blank, unless a comment, blank line or
			// directive came in between.
			name := e.Domain()
			switch {
			case len(name) == 0:
			case prevname != nil && NameEqual(name, prevname):
				name = nil
			default:
				prevname = name
			}
			if err := f.record(e, name, incrementSerial); err != nil {
				return err
			}
		}
	}
	return nil
}

type formatter struct {
	w                              io.Writer
	nameWidth, ttlWidth, typeWidth int
}

// record writes one resource record entry.
func (f formatter) record(e zonefile.Entry, name []byte, incrementSerial bool) error {
	prefix := fmt.Sprintf("%-*s ", f.nameWidth, name)
	if f.ttlWidth > 0 {
		ttl := ""
		if t := e.TTL(); t != nil {
			ttl = strconv.Itoa(*t)
		}
		prefix += fmt.Sprintf("%*s ", f.ttlWidth, ttl)
	}
	class := e.Class()
	if len(class) == 0 {
		class = []byte("IN")
	}
	prefix += fmt.Sprintf("%s %-*s ", class, f.typeWidth, e.Type())

	values := e.Values()
	raw := e.RawValues()
	head, after := e.ValueComments()

	switch e.RRType() {
	case dns.TypeTXT, dns.TypeSPF:
		quoted := make([][]byte, len(values))
		for i, v := range values {
			quoted[i] = []byte(Quote(v))
		}
		f.values(prefix, quoted, head, after, len(values) > 1)

	case dns.TypeCAA:
		rendered := slices.Clone(raw)
		for i := 2; i < len(values); i++ {
			rendered[i] = []byte(Quote(values[i]))
		}
		f.values(prefix, rendered, head, after, false)

	case dns.TypeSOA:
		f.soa(prefix, values, raw, head, after, incrementSerial)

	case dns.TypeCDS, dns.TypeDS, dns.TypeCDNSKEY, dns.TypeDNSKEY, dns.TypeRRSIG:
		n := 3
		if e.RRType() == dns.TypeRRSIG {
			n = 8
		}
		if len(values) < n+1 {
			return fmt.Errorf("malformed %s RR: %q", e.Type(), values)
		}
		// Long base64 data is split over several lines; its comments go to
		// the first line.
		comments := trailing(append(head, slices.Concat(after...)...))
		pieces := Split(bytes.Join(values[n:], nil), 55)
		if len(pieces) == 1 {
			fmt.Fprintf(f.w, "%s%s%s\n", prefix, bytes.Join(raw, []byte(" ")), comments)
			break
		}
		fmt.Fprintf(f.w, "%s%s (%s\n", prefix, bytes.Join(raw[:n], []byte(" ")), comments)
		for _, p := range pieces {
			fmt.Fprintf(f.w, "%s%s\n", indent, p)
		}
		fmt.Fprintln(f.w, ")")

	default:
		f.values(prefix, raw, head, after, false)
	}
	return nil
}

// values writes record values after prefix. They stay on one line unless
// multi is set or a comment precedes a value other than the last; then each
// value gets its own indented line inside ( ), followed by its comments.
func (f formatter) values(prefix string, values [][]byte, head [][]byte, after [][][]byte, multi bool) {
	for i := 0; i+1 < len(after); i++ {
		multi = multi || len(after[i]) > 0
	}
	multi = multi || len(head) > 0

	if !multi {
		var last [][]byte
		if len(after) > 0 {
			last = after[len(after)-1]
		}
		line := prefix + string(bytes.Join(values, []byte(" ")))
		fmt.Fprintf(f.w, "%s%s\n", bytes.TrimRight([]byte(line), " "), trailing(last))
		return
	}

	fmt.Fprintf(f.w, "%s(%s\n", prefix, trailing(head))
	width := 0
	for i, v := range values {
		if len(after[i]) > 0 {
			width = max(width, len(v))
		}
	}
	for i, v := range values {
		line := fmt.Sprintf("%s%-*s", indent, width, v)
		fmt.Fprintf(f.w, "%s%s\n", bytes.TrimRight([]byte(line), " "), trailing(after[i]))
	}
	fmt.Fprintln(f.w, ")")
}

// soa writes the SOA record: mname and rname on the first line, then one
// field per line with its comment. The serial always gets its date.
func (f formatter) soa(prefix string, values, raw, head [][]byte, after [][][]byte, incrementSerial bool) {
	fmt.Fprintf(f.w, "%s%s (%s\n", prefix, bytes.Join(raw[:2], []byte(" ")), trailing(append(head, slices.Concat(after[:2]...)...)))

	fields := slices.Clone(raw[2:])
	if incrementSerial {
		fields[0] = Increase(values[2])
	}
	width := 0
	for _, v := range fields {
		width = max(width, len(v))
	}

	for i, v := range fields {
		var comment string
		if i == 0 {
			comment = soacomment[0] + SerialToHuman(v)
			for _, c := range after[2] {
				if user := UserComment(c); len(user) > 0 {
					comment += " " + string(user)
				}
			}
		} else if len(after[i+2]) == 0 || isGeneratedSOAComment(after[i+2], i) {
			comment = soacomment[i]
		} else {
			comment = string(bytes.Join(after[i+2], []byte(" ")))
		}
		fmt.Fprintf(f.w, "%s%-*s %s\n", indent, width, v, comment)
	}
	fmt.Fprintln(f.w, ")")
}

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
	return " " + string(bytes.Join(comments, []byte(" ")))
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
	if !NameEqual(name[l:], origin) {
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

// NameEqual compares DNS names case-insensitively for ASCII letters only
// (RFC 4343). Unicode folding would treat different non-ASCII bytes (all
// invalid UTF-8 decodes to U+FFFD) as equal.
func NameEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
