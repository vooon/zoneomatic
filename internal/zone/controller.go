package zone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/vooon/zoneomatic/pkg/dnsfmt"
	"github.com/vooon/zoneomatic/pkg/fileutil"
	"github.com/vooon/zoneomatic/pkg/zonefile"
	"go.opentelemetry.io/otel/attribute"
)

// ErrSoaNotFound emited if zone file does not have SOA record, which is mandatory
var (
	ErrSoaNotFound    = errors.New("SOA not found")
	ErrRecordNotFound = errors.New("record not found")
	ErrNoMatchers     = errors.New("no record matchers provided")
	ErrOriginChanged  = errors.New("zone origin changed")
	ErrZoneNotFound   = errors.New("zone not found")
)

// EmptyPlaceholder will be used instead of empty ACME TXT because we cannot really set ""
const EmptyPlaceholder = "placeholder"

// Controller implements zone file modification methods
type Controller interface {
	// ListZones returns all managed zones.
	ListZones(ctx context.Context) ([]ZoneSnapshot, error)
	// GetZone returns a managed zone by its origin name.
	GetZone(ctx context.Context, zoneName string) (ZoneSnapshot, error)
	// UpdateDDNSAddress changes DDNS A/AAAA records
	UpdateDDNSAddress(ctx context.Context, domain string, addrs []netip.Addr) error
	// UpdateACMEChallenge changes ACME TXT record for DNS-01 challenge
	UpdateACMEChallenge(ctx context.Context, domain string, newToken, oldToken string) error
	// ReplaceRRSet replaces or creates the requested RRSet in a specific zone.
	ReplaceRRSet(ctx context.Context, zoneName, name, typ string, ttl int, values []string) (changed bool, err error)
	// DeleteRRSet removes the requested RRSet from a specific zone.
	DeleteRRSet(ctx context.Context, zoneName, name, typ string) (changed bool, err error)
	// ZMUpdateRecord replace record values
	ZMUpdateRecord(ctx context.Context, domain string, typ string, values []string) (changed bool, err error)
}

type Matcher struct {
	Domain []byte
	RRType uint16
	Values [][]byte
}

type Matchers []Matcher

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

func (s *DomainCtrl) UpdateDDNSAddress(ctx context.Context, domain string, addrs []netip.Addr) (err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.domain_ctrl.update_ddns_address")
	span.SetAttributes(
		attribute.String("zone.domain", domain),
		attribute.Int("zone.addr_count", len(addrs)),
	)
	defer func() {
		recordSpanError(span, err)
		span.End()
	}()

	lg := slog.Default().With("domain", domain)

	domainDot := domain
	if !strings.HasSuffix(domainDot, ".") {
		domainDot += "."
	}

	fl := s.findZoneFile(ctx, lg, domainDot)
	if fl != nil {
		span.SetAttributes(attribute.String("zone.file", path.Base(fl.path)))
		lg.InfoContext(ctx, "Zone file found", "zonefile", path.Base(fl.path))
		return fl.UpdateDDNSAddress(ctx, domainDot, addrs)
	}

	err = fmt.Errorf("%w: %s", ErrZoneNotFound, domain)
	return err
}

func (s *DomainCtrl) UpdateACMEChallenge(ctx context.Context, domain string, newToken, oldToken string) (err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.domain_ctrl.update_acme_challenge")
	span.SetAttributes(
		attribute.String("zone.domain", domain),
		attribute.Bool("zone.old_token_provided", oldToken != ""),
		attribute.Bool("zone.new_token_empty", newToken == ""),
	)
	defer func() {
		recordSpanError(span, err)
		span.End()
	}()

	lg := slog.Default().With("domain", domain)

	domainDot := domain
	if !strings.HasSuffix(domainDot, ".") {
		domainDot += "."
	}

	if !strings.HasPrefix(domainDot, "_acme-challenge.") {
		domainDot = "_acme-challenge." + domainDot
	}

	fl := s.findZoneFile(ctx, lg, domainDot)
	if fl != nil {
		span.SetAttributes(attribute.String("zone.file", path.Base(fl.path)))
		lg.InfoContext(ctx, "Zone file found", "zonefile", path.Base(fl.path))
		return fl.UpdateACMEChallenge(ctx, domainDot, newToken, oldToken)
	}

	err = fmt.Errorf("%w: %s", ErrZoneNotFound, domain)
	return err
}

func (s *DomainCtrl) ZMUpdateRecord(ctx context.Context, domain string, typ string, values []string) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.domain_ctrl.update_record")
	span.SetAttributes(
		attribute.String("zone.domain", domain),
		attribute.String("dns.rr.type", typ),
		attribute.Int("zone.value_count", len(values)),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	lg := slog.Default().With("domain", domain)

	domainDot := domain
	if !strings.HasSuffix(domainDot, ".") {
		domainDot += "."
	}

	fl := s.findZoneFile(ctx, lg, domainDot)
	if fl != nil {
		span.SetAttributes(attribute.String("zone.file", path.Base(fl.path)))
		lg.InfoContext(ctx, "Zone file found", "zonefile", path.Base(fl.path))
		return fl.ZMUpdateRecord(ctx, domainDot, typ, values)
	}

	err = fmt.Errorf("%w: %s", ErrZoneNotFound, domain)
	return false, err
}

func (s *DomainCtrl) findZoneFile(ctx context.Context, lg *slog.Logger, domainDot string) *File {
	var best *File
	bestLen := -1
	for _, fl := range s.files {
		lg.DebugContext(ctx, "Check file", "file_origin", fl.origin)
		if !domainMatchesOrigin(domainDot, fl.origin) {
			continue
		}
		if l := len(fl.origin); l > bestLen {
			best = fl
			bestLen = l
		}
	}
	return best
}

func domainMatchesOrigin(domain, origin string) bool {
	domain = strings.ToLower(normalizeZoneName(domain))
	origin = strings.ToLower(normalizeZoneName(origin))

	if domain == origin {
		return true
	}

	originNoDot := strings.TrimSuffix(origin, ".")
	if originNoDot == "" {
		return false
	}

	return strings.HasSuffix(domain, "."+originNoDot+".")
}

func (m Matcher) Match(e zonefile.Entry) bool {
	if m.Domain != nil && !dnsNamesEqual(e.Domain(), m.Domain) {
		return false
	}

	if m.RRType > 0 && m.RRType != e.RRType() {
		return false
	}

	if m.Values != nil && !slices.EqualFunc(e.Values(), m.Values, bytes.Equal) {
		return false
	}

	return true
}

func dnsNamesEqual(a, b []byte) bool {
	return strings.EqualFold(normalizeZoneName(string(a)), normalizeZoneName(string(b)))
}

func (m Matcher) String() string {
	args := make([]string, 0, 3)

	if m.Domain != nil {
		args = append(args, fmt.Sprintf("domain:%s", m.Domain))
	}
	if m.RRType > 0 {
		args = append(args, fmt.Sprintf("rrtype:%s", dns.TypeToString[m.RRType]))
	}
	if m.Values != nil {
		args = append(args, fmt.Sprintf("value:%v", m.Values))
	}

	return fmt.Sprintf("Match(%s)", strings.Join(args, " "))
}

func (mm Matchers) Match(e zonefile.Entry) bool {
	for _, m := range mm {
		if m.Match(e) {
			return true
		}
	}

	return false
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

	if s.origin == "" {
		s.lg.Info("Detected origin", "origin", origin)
		s.origin = origin
	} else if s.origin != origin {
		return nil, nil, fmt.Errorf("%w: prev=%s new=%s", ErrOriginChanged, s.origin, origin)
	}

	// PrintEntries(zf.Entries(), os.Stdout)

	return
}

func (s *File) updateRecords(ctx context.Context, lg1 *slog.Logger, matchers Matchers, values []zonefile.Entry, allowNew bool) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.file.update_records")
	span.SetAttributes(
		attribute.String("zone.file", path.Base(s.path)),
		attribute.Bool("zone.allow_new", allowNew),
		attribute.Int("zone.matcher_count", len(matchers)),
		attribute.Int("zone.new_entry_count", len(values)),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	lg := lg1.With("matchers", matchers)

	if len(matchers) == 0 {
		return false, ErrNoMatchers
	}

	zf, _, err := s.load()
	if err != nil {
		return
	}

	// 1. Copy all non-matching elements, insert new values on the place of first element
	oldEntries := zf.Entries()
	newEntries := make([]zonefile.Entry, 0, len(oldEntries))
	found := false
	matchedCount := 0
	for idx, ent := range oldEntries {
		if matchers.Match(ent) {
			matchedCount++
			if !found {
				lg.DebugContext(ctx, "First matching record found", "index", idx, "old_values", ent.ValuesStrings())
				newEntries = append(newEntries, values...)
				found = true
			} else {
				lg.DebugContext(ctx, "Remove matching record", "index", idx, "old_values", ent.ValuesStrings())
			}
			continue
		}

		newEntries = append(newEntries, ent)
	}
	span.SetAttributes(
		attribute.Int("zone.old_entry_count", len(oldEntries)),
		attribute.Int("zone.matched_entry_count", matchedCount),
	)

	// 2. If old record not found - add new values to the end, if allowed
	if !found {
		if !allowNew {
			lg.ErrorContext(ctx, "No matching record not found, but insert is not allowed.")
			return false, ErrRecordNotFound
		}

		lg.DebugContext(ctx, "No matching record not found, but inserting to the end")
		newEntries = append(newEntries, values...)
	}
	span.SetAttributes(attribute.Int("zone.result_entry_count", len(newEntries)))

	// 3. Check if it is changed
	changed = !slices.EqualFunc(oldEntries, newEntries, func(e1, e2 zonefile.Entry) bool {
		return e1.Equal(e2)
	})

	if !changed {
		lg.InfoContext(ctx, "No records changed", "changed", changed)
		return
	}

	// 4. Update file
	uglyBuf := bytes.NewBuffer(nil)
	PrintEntries(newEntries, uglyBuf)

	// fmt.Println(string(uglyBuf.String()))

	ret := bytes.NewBuffer(nil)
	err = dnsfmt.Reformat(uglyBuf.Bytes(), nil, ret, true)
	if err != nil {
		return
	}

	err = fileutil.AtomicWriteFile(s.path, ret.Bytes())
	if err != nil {
		lg.ErrorContext(ctx, "Failed to save file", "error", err, "changed", changed)
		return
	}

	lg.InfoContext(ctx, "File saved", "changed", changed)
	return
}

func (s *File) UpdateDDNSAddress(ctx context.Context, domain string, addrs []netip.Addr) error {
	ctx, span := zoneTracer.Start(ctx, "zone.file.update_ddns_address")
	span.SetAttributes(
		attribute.String("zone.file", path.Base(s.path)),
		attribute.String("zone.domain", domain),
		attribute.Int("zone.addr_count", len(addrs)),
	)
	defer span.End()

	s.mu.Lock()
	defer s.mu.Unlock()

	lg := s.lg.With("domain", domain, "new_addrs", addrs)

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
	span.SetAttributes(
		attribute.Int("zone.addr_v4_count", len(newA)),
		attribute.Int("zone.addr_v6_count", len(newAAAA)),
	)

	shortDomain := []byte(StripOrigin(domain, s.origin))
	newentbuf := bytes.NewBuffer(nil)

	for _, addr := range newA {
		_, _ = fmt.Fprintf(newentbuf, "\n%s IN A %v\n", shortDomain, addr)
	}
	for _, addr := range newAAAA {
		_, _ = fmt.Fprintf(newentbuf, "\n%s IN AAAA %v\n", shortDomain, addr)
	}

	values, err := parseEntries(newentbuf)
	if err != nil {
		recordSpanError(span, err)
		return err
	}

	matchers := make(Matchers, 0, 2)
	if len(newA) > 0 {
		matchers = append(matchers, Matcher{Domain: shortDomain, RRType: dns.TypeA})
	}
	if len(newAAAA) > 0 {
		matchers = append(matchers, Matcher{Domain: shortDomain, RRType: dns.TypeAAAA})
	}

	_, err = s.updateRecords(ctx, lg, matchers, values, true)
	if err != nil {
		recordSpanError(span, err)
		return err
	}

	return nil
}

func (s *File) UpdateACMEChallenge(ctx context.Context, domain string, newToken, oldToken string) (err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.file.update_acme_challenge")
	span.SetAttributes(
		attribute.String("zone.file", path.Base(s.path)),
		attribute.String("zone.domain", domain),
		attribute.Bool("zone.old_token_provided", oldToken != ""),
		attribute.Bool("zone.new_token_empty", newToken == ""),
	)
	defer func() {
		recordSpanError(span, err)
		span.End()
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	lg := s.lg.With("domain", domain, "old_token", oldToken, "new_token", newToken)
	if newToken == "" {
		lg.Warn("Use placeholder for empty TXT record")
		newToken = EmptyPlaceholder
	}

	shortDomain := []byte(StripOrigin(domain, s.origin))

	newentbuf := bytes.NewBuffer(nil)
	_, _ = fmt.Fprintf(newentbuf, "\n%s IN TXT %v\n", shortDomain, quoteTXT(newToken))

	values, err := parseEntries(newentbuf)
	if err != nil {
		return err
	}

	var oldValues [][]byte // nil - ACME DNS mode - replace all TXTs
	if oldToken != "" {    // HTTP-REQ mode - replace only matching old token
		oldValues = [][]byte{
			[]byte(oldToken),
		}
	}

	matchers := []Matcher{
		{
			Domain: shortDomain,
			RRType: dns.TypeTXT,
			Values: oldValues,
		},
	}

	_, err = s.updateRecords(ctx, lg, matchers, values, true)
	if err != nil {
		return err
	}

	return nil
}

func (s *File) ZMUpdateRecord(ctx context.Context, domain string, typ string, newValues []string) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.file.update_record")
	span.SetAttributes(
		attribute.String("zone.file", path.Base(s.path)),
		attribute.String("zone.domain", domain),
		attribute.String("dns.rr.type", typ),
		attribute.Int("zone.value_count", len(newValues)),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	lg := s.lg.With("domain", domain, "new_values", newValues)

	typ = strings.ToUpper(strings.TrimSpace(typ))
	rrType, ok := dns.StringToType[typ]
	if !ok {
		return false, fmt.Errorf("unknown rrtype: %s", typ)
	}

	shortDomain := []byte(StripOrigin(domain, s.origin))
	newentbuf := bytes.NewBuffer(nil)

	for _, val := range newValues {
		_, _ = fmt.Fprintf(newentbuf, "\n%s IN %s %s\n", shortDomain, typ, val)
	}

	values, err := parseEntries(newentbuf)
	if err != nil {
		return false, err
	}

	matchers := []Matcher{
		{
			Domain: shortDomain,
			RRType: rrType,
		},
	}

	return s.updateRecords(ctx, lg, matchers, values, false)
}

func StripOrigin(name, origin string) string {
	name = strings.TrimSpace(name)
	origin = strings.TrimSpace(origin)
	nameFQDN := normalizeZoneName(name)
	originFQDN := normalizeZoneName(origin)

	if !domainMatchesOrigin(nameFQDN, originFQDN) {
		return name
	}

	if strings.EqualFold(nameFQDN, originFQDN) {
		return "@"
	}

	l1 := len(nameFQDN)
	l2 := len(originFQDN)
	if l1 <= l2 {
		return "@"
	}

	// strip suffix + dot
	return nameFQDN[:l1-l2-1]
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

func parseEntries(zonebuf *bytes.Buffer) ([]zonefile.Entry, error) {
	zf, err := zonefile.Load(zonebuf.Bytes())
	if err != nil {
		return nil, err
	}

	return zf.Entries(), nil
}
