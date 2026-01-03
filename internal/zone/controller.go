package zone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/go-fuego/fuego"
	"github.com/miekg/dns"
	"github.com/miekg/dnsfmt/zonefile"
	"github.com/vooon/zoneomatic/pkg/dnsfmt"
)

// ErrSoaNotFound emited if zone file does not have SOA record, which is mandatory
var (
	ErrSoaNotFound    = errors.New("SOA not found")
	ErrRecordNotFound = errors.New("Record not found")
)

// EmptyPlaceholder will be used instead of empty ACME TXT because we cannot really set ""
const EmptyPlaceholder = "placeholder"

// Controller implements zone file modification methods
type Controller interface {
	// UpdateRecords replace records values
	// match record domain and type(s), then replace all of them with new values
	// UpdateRecords(ctx context.Context, domain string, types []uint16, values []zonefile.Entry, allowNew bool) (changed bool, err error)

	// UpdateDDNSAddress changes DDNS A/AAAA records
	UpdateDDNSAddress(ctx context.Context, domain string, addrs []netip.Addr) error
	// UpdateACMEChallenge changes ACME TXT record for DNS-01 challenge
	UpdateACMEChallenge(ctx context.Context, domain string, newToken, oldToken string) error
}

type File struct {
	origin string
	path   string
	lg     *slog.Logger
	mu     sync.Mutex
}

type DomainCtrl struct {
	files []*File
}

func New(zonefiles ...string) (Controller, error) {

	ret := make([]*File, 0, len(zonefiles))
	for _, fl := range zonefiles {
		fileName := path.Base(fl)
		f := &File{
			path: fl,
			lg:   slog.Default().With("zone_file", fileName),
		}

		_, _, err := f.load()
		if err != nil {
			return nil, fmt.Errorf("failed to load zone: %s: %w", fileName, err)
		}

		ret = append(ret, f)
	}

	return &DomainCtrl{files: ret}, nil
}

func (s *DomainCtrl) UpdateDDNSAddress(ctx context.Context, domain string, addrs []netip.Addr) error {

	lg := slog.Default().With("domain", domain)

	domainDot := domain
	if !strings.HasSuffix(domainDot, ".") {
		domainDot += "."
	}

	for _, fl := range s.files {
		lg.DebugContext(ctx, "Check file", "file_origin", fl.origin)
		if strings.HasSuffix(domainDot, fl.origin) {
			lg.InfoContext(ctx, "Zone file found", "zonefile", path.Base(fl.path))
			return fl.UpdateDDNSAddress(ctx, domainDot, addrs)
		}
	}

	return &fuego.HTTPError{
		Title:  "zone not found",
		Detail: fmt.Sprintf("zone not found for domain: %s", domain),
		Status: http.StatusNotFound,
	}
}

func (s *DomainCtrl) UpdateACMEChallenge(ctx context.Context, domain string, newToken, oldToken string) error {

	lg := slog.Default().With("domain", domain)

	domainDot := domain
	if !strings.HasSuffix(domainDot, ".") {
		domainDot += "."
	}

	if !strings.HasPrefix(domainDot, "_acme-challenge.") {
		domainDot = "_acme-challenge." + domainDot
	}

	for _, fl := range s.files {
		lg.DebugContext(ctx, "Check file", "file_origin", fl.origin)
		if strings.HasSuffix(domainDot, fl.origin) {
			lg.InfoContext(ctx, "Zone file found", "zonefile", path.Base(fl.path))
			return fl.UpdateACMEChallenge(ctx, domainDot, newToken, oldToken)
		}
	}

	return &fuego.HTTPError{
		Title:  "zone not found",
		Detail: fmt.Sprintf("zone not found for domain: %s", domain),
		Status: http.StatusNotFound,
	}
}

func (s *DomainCtrl) UpdateRecords(ctx context.Context, domain string, types []uint16, values []zonefile.Entry, allowNew bool) (changed bool, err error) {
	return false, nil
}

func (s *File) load() (zf *zonefile.Zonefile, soa *zonefile.Entry, err error) {
	buf, err := os.ReadFile(s.path)
	if err != nil {
		return nil, nil, err
	}

	var zfErr *zonefile.ParsingError
	zf, zfErr = zonefile.Load(buf)
	if zfErr != nil {
		return nil, nil, zfErr
	}

	ok := false
	origin := ""
	prevDomain := []byte{}
	for _, ent := range zf.Entries() {
		if ent.IsComment {
			continue
		}

		if ent.IsControl {
			if bytes.Equal(ent.Command(), []byte("$ORIGIN")) {
				origin = string(zonefile.Fqdn(ent.Values()[0]))
			}
			continue
		}

		dom := ent.Domain()
		if dom != nil {
			prevDomain = dom
		} else {
			dom = prevDomain
		}

		err = ent.SetDomain(dnsfmt.StripOrigin([]byte(s.origin), dom))
		if err != nil {
			return
		}

		if ent.RRType() == dns.TypeSOA {
			soa = &ent
			ok = true
		}
	}
	if !ok {
		return nil, nil, ErrSoaNotFound
	}

	if origin == "" {
		origin = string(soa.Domain())
	}

	if s.origin != origin && s.origin != "" {
		s.lg.Warn("Changed origin", "prev_origin", s.origin, "new_origin", origin)
	} else if s.origin != origin {
		s.lg.Info("Detected origin", "origin", origin)
	}
	s.origin = origin

	// PrintEntries(zf.Entries(), os.Stdout)

	return
}

func (s *File) updateRecords(ctx context.Context, domain string, rrTypes []uint16, values []zonefile.Entry, allowNew bool) (changed bool, err error) {
	lg := s.lg.With("domain", domain, "rr_types", rrTypes)

	zf, _, err := s.load()
	if err != nil {
		return
	}

	shortDomain := []byte(StripOrigin(domain, s.origin))

	// 1. Copy all non-matching elements, insert new values on the place of first element
	allEnt := zf.Entries()
	newEntries := make([]zonefile.Entry, 0, len(allEnt))
	found := false
	for idx, ent := range allEnt {
		if bytes.Equal(ent.Domain(), shortDomain) && slices.Contains(rrTypes, ent.RRType()) {
			if !found {
				lg.DebugContext(ctx, "First matching record found", "index", idx)
				newEntries = append(newEntries, values...)
				found = true
			}
			continue
		}

		newEntries = append(newEntries, ent)
	}

	// 2. If old record not found - add new values to the end, if allowed
	if !found {
		if !allowNew {
			lg.ErrorContext(ctx, "Record not found, insert new is not allowed.")
			return false, fmt.Errorf("%w: %s %v", ErrRecordNotFound, domain, rrTypes)
		}

		lg.DebugContext(ctx, "Record not found, inserting to the end")
		newEntries = append(newEntries, values...)
	}

	// 3. Check if file changed
	changed = len(allEnt) != len(newEntries)
	if !changed {
	}

	return false, nil
}

func (s *File) UpdateDDNSAddress(ctx context.Context, domain string, addrs []netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	changed := false

	zf, _, err := s.load()
	if err != nil {
		return err
	}

	slices.SortFunc(addrs, func(a, b netip.Addr) int {
		return a.Compare(b)
	})

	newA := make([]netip.Addr, 0, len(addrs))
	newAAAA := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.Is4() {
			newA = append(newA, a)
			continue
		}
		newAAAA = append(newAAAA, a)
	}

	shortDomain := []byte(StripOrigin(domain, s.origin))

	allEnt := zf.Entries()
	entA := make([]*zonefile.Entry, 0, len(newA))
	entAAAA := make([]*zonefile.Entry, 0, len(newAAAA))
	newent := make([]byte, 0, 4096)

	for _, ent := range allEnt {
		if !bytes.Equal(ent.Domain(), shortDomain) {
			continue
		}

		if ent.RRType() == dns.TypeA {
			entA = append(entA, &ent)
		} else if ent.RRType() == dns.TypeAAAA {
			entAAAA = append(entAAAA, &ent)
		}
	}

	for i := len(entA); i < len(newA); i++ {
		newent = fmt.Appendf(newent, "\n%s IN A %v\n", shortDomain, newA[i])
		changed = true
	}
	for i := len(entAAAA); i < len(newAAAA); i++ {
		newent = fmt.Appendf(newent, "\n%s IN AAAA %v\n", shortDomain, newAAAA[i])
		changed = true
	}

	if len(newent) > 0 {
		zf2, err := zonefile.Load(newent)
		if err != nil {
			return err
		}

		for _, ent := range zf2.Entries() {
			allEnt = append(allEnt, ent)
			if ent.RRType() == dns.TypeA {
				entA = append(entA, &ent)
			} else if ent.RRType() == dns.TypeAAAA {
				entAAAA = append(entAAAA, &ent)
			}
		}
	}

	for i, ent := range entA {
		if i < len(newA) {

			changed, err = setEntryAddr(ent, newA[i], changed)
			if err != nil {
				return err
			}

			continue
		}

		if len(newA) != 0 {
			changed, err = setEntryAddr(ent, newA[0], changed)
			if err != nil {
				return err
			}
		}
	}

	for i, ent := range entAAAA {
		if i < len(newAAAA) {
			changed, err = setEntryAddr(ent, newAAAA[i], changed)
			if err != nil {
				return err
			}

			continue
		}

		if len(newAAAA) != 0 {
			changed, err = setEntryAddr(ent, newAAAA[0], changed)
			if err != nil {
				return err
			}
		}
	}

	if !changed {
		s.lg.InfoContext(ctx, "domain not changed", "domain", domain)
		return nil
	}

	uglyBuf := bytes.NewBuffer(nil)
	PrintEntries(allEnt, uglyBuf)

	// fmt.Println(string(uglyBuf.String()))

	ret := bytes.NewBuffer(nil)
	err = dnsfmt.Reformat(uglyBuf.Bytes(), nil, ret, true)
	if err != nil {
		return err
	}

	err = os.WriteFile(s.path, ret.Bytes(), 0644)
	if err != nil {
		s.lg.ErrorContext(ctx, "Failed to save file", "error", err)
		return err
	}

	return nil
}

func (s *File) UpdateACMEChallenge(ctx context.Context, domain string, newToken, oldToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	zf, _, err := s.load()
	if err != nil {
		return err
	}

	lg := s.lg.With("domain", domain)
	if newToken == "" {
		lg.Warn("Use placeholder for empty TXT record")
		newToken = EmptyPlaceholder
	}

	shortDomain := []byte(StripOrigin(domain, s.origin))

	allEnt := zf.Entries()
	entTXT := make([]*zonefile.Entry, 0, 1)
	newent := make([]byte, 0, 4096)

	for _, ent := range allEnt {
		if !bytes.Equal(ent.Domain(), shortDomain) {
			continue
		}

		if ent.RRType() == dns.TypeTXT {
			if oldToken == "" {
				// ACMEDNS mode - replace all TXTs
				entTXT = append(entTXT, &ent)
			} else {
				// HTTP-REQ mode - replace only matching TXTs
				vals := ent.Values()
				if len(vals) == 1 && bytes.Equal(vals[0], []byte(oldToken)) {
					entTXT = append(entTXT, &ent)
					if oldToken == EmptyPlaceholder {
						// leave other placeholders for next requests
						break
					}
				}
			}
		}
	}

	if len(entTXT) < 1 {
		newent = fmt.Appendf(newent, "\n%s IN TXT %v\n", shortDomain, quoteTXT(newToken))
	}

	if len(newent) > 0 {
		zf2, err := zonefile.Load(newent)
		if err != nil {
			return err
		}

		for _, ent := range zf2.Entries() {
			allEnt = append(allEnt, ent)
			if ent.RRType() == dns.TypeTXT {
				entTXT = append(entTXT, &ent)
			}
		}
	}

	for _, ent := range entTXT {
		vals := ent.Values()
		if len(vals) == 1 {
			lg.Info("Replace value", "old_value", string(vals[0]), "new_value", newToken)
		} else if len(vals) > 1 {
			lg.Warn("Possibly bad record matched", "vals", vals)
		}

		err := ent.SetValue(0, []byte(newToken))
		if err != nil {
			return err
		}
	}

	uglyBuf := bytes.NewBuffer(nil)
	PrintEntries(allEnt, uglyBuf)

	// fmt.Println(string(uglyBuf.String()))

	ret := bytes.NewBuffer(nil)
	err = dnsfmt.Reformat(uglyBuf.Bytes(), nil, ret, true)
	if err != nil {
		return err
	}

	err = os.WriteFile(s.path, ret.Bytes(), 0644)
	if err != nil {
		lg.ErrorContext(ctx, "Failed to save file", "error", err)
		return err
	}

	return nil
}

func StripOrigin(name, origin string) string {
	if !strings.HasSuffix(name, origin) {
		return name
	}

	l1 := len(name)
	l2 := len(origin)
	if l1 == l2 {
		return "@"
	}

	// strip suffix + dot
	return name[:l1-l2-1]
}

func PrintEntries(entries []zonefile.Entry, w io.Writer) {
	for _, e := range entries {

		if e.IsComment {
			for _, c := range e.Comments() {
				fmt.Fprintf(w, "%s\n", c) // nolint:errcheck
			}
			continue
		} else if e.IsControl {
			fmt.Fprintf(w, "%s %s\n", e.Command(), bytes.Join(e.Values(), []byte(" "))) // nolint:errcheck
			continue
		}

		fmt.Fprintf(w, "%s ", e.Domain()) // nolint:errcheck
		if ttl := e.TTL(); ttl != nil {
			fmt.Fprintf(w, " %d ", *ttl) // nolint:errcheck
		}
		if cls := e.Class(); cls != nil {
			fmt.Fprintf(w, " %s ", cls) // nolint:errcheck
		}
		if typ := e.Type(); typ != nil {
			fmt.Fprintf(w, " %s ", typ) // nolint:errcheck
		}

		for _, v := range e.Values() {
			fmt.Fprintf(w, " %s ", quoteTXT(string(v))) // nolint:errcheck
		}

		fmt.Fprintln(w) // nolint:errcheck
	}
}

func quoteTXT(v string) string {
	return fmt.Sprintf(` "%s" `, strings.ReplaceAll(v, `"`, `\"`))
}

func setEntryAddr(ent *zonefile.Entry, addr netip.Addr, prevChanged bool) (changed bool, err error) {
	baddr := []byte(addr.String())
	changed = prevChanged

	ov := ent.Values()
	if len(ov) > 0 && !slices.Equal(ov[0], baddr) {
		changed = true
	}

	err = ent.SetValue(0, baddr)
	return
}
