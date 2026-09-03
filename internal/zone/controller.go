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
	ZMUpdateRecord(ctx context.Context, domain string, typ string, ttl int, values []string) (changed bool, err error)
	// UpdatePTR updates PTR records for the given addresses in matching
	// reverse zones, pointing them to the target host. addresses must contain
	// at least one address; mode controls how the PTR records are managed.
	UpdatePTR(ctx context.Context, target string, addresses []netip.Addr, mode PTRUpdateMode) (changed bool, err error)
}

// PTRUpdateMode controls how /zm/update-ptr manages PTR records for a target
// host across the requested addresses.
type PTRUpdateMode string

const (
	// PTRUpdateAppend only adds missing PTR records, never removes anything.
	PTRUpdateAppend PTRUpdateMode = "append"
	// PTRUpdateReplace sets the PTR record for each requested address in
	// place (single record per address, keeping unrelated PTRs on the name).
	PTRUpdateReplace PTRUpdateMode = "replace"
	// PTRUpdateReplaceAll makes the PTR set of the target exactly match the
	// requested addresses, removing stale PTR records pointing to the target.
	PTRUpdateReplaceAll PTRUpdateMode = "replace-all"
)

type Matcher struct {
	Domain []byte
	RRType uint16
	Values [][]byte
}

type Matchers []Matcher

// Option configures the zone controller.
type Option func(*DomainCtrl)

// WithAcmeTTL sets an explicit TTL (in seconds) for ACME challenge TXT records.
// If ttl is 0 (the default), no explicit TTL is written and the zone $TTL is used.
func WithAcmeTTL(ttl int) Option {
	return func(d *DomainCtrl) {
		d.acmeTTL = ttl
	}
}

// WithDDNSManagePTR enables updating PTR records in matching reverse zones on
// DDNS address updates. Reverse zones are matched by the reversed address name
// (in-addr.arpa / ip6.arpa); zones without a matching file are skipped.
func WithDDNSManagePTR(enable bool) Option {
	return func(d *DomainCtrl) {
		d.ddnsPTR = enable
	}
}

type File struct {
	origin  string
	path    string
	lg      *slog.Logger
	mu      sync.Mutex
	acmeTTL int
}

type DomainCtrl struct {
	files   []*File
	acmeTTL int
	ddnsPTR bool
}

func New(zonefiles ...string) (Controller, error) {
	return NewWithOptions(nil, zonefiles...)
}

func NewWithOptions(opts []Option, zonefiles ...string) (Controller, error) {

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

	dc := &DomainCtrl{files: ret}
	for _, opt := range opts {
		opt(dc)
	}
	for _, f := range dc.files {
		f.acmeTTL = dc.acmeTTL
	}

	return dc, nil
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
		if err = fl.UpdateDDNSAddress(ctx, domainDot, addrs); err != nil {
			return err
		}
		if s.ddnsPTR {
			s.updatePTRRecords(ctx, lg, domainDot, addrs)
		}
		return nil
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

func (s *DomainCtrl) ZMUpdateRecord(ctx context.Context, domain string, typ string, ttl int, values []string) (changed bool, err error) {
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
		return fl.ZMUpdateRecord(ctx, domainDot, typ, ttl, values)
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

func (s *File) updateRecords(ctx context.Context, lg1 *slog.Logger, matchers Matchers, values []zonefile.Entry, replaceAll bool, anchor []byte, allowNew bool) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.file.update_records")
	span.SetAttributes(
		attribute.String("zone.file", path.Base(s.path)),
		attribute.Bool("zone.allow_new", allowNew),
		attribute.Bool("zone.replace_all", replaceAll),
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
				continue
			}
			if replaceAll {
				lg.DebugContext(ctx, "Remove duplicate matching record", "index", idx, "old_values", ent.ValuesStrings())
				continue
			}
			lg.DebugContext(ctx, "Keep extra matching record", "index", idx, "old_values", ent.ValuesStrings())
		}

		newEntries = append(newEntries, ent)
	}
	span.SetAttributes(
		attribute.Int("zone.old_entry_count", len(oldEntries)),
		attribute.Int("zone.matched_entry_count", matchedCount),
	)

	// 2. If old record not found - add new values, if allowed
	if !found {
		if !allowNew {
			lg.ErrorContext(ctx, "No matching record not found, but insert is not allowed.")
			return false, ErrRecordNotFound
		}

		if anchor != nil {
			if idx := anchorInsertIndex(newEntries, anchor); idx >= 0 {
				lg.DebugContext(ctx, "No matching record not found, inserting after anchor", "index", idx)
				newEntries = slices.Insert(newEntries, idx+1, values...)
				span.SetAttributes(attribute.Int("zone.anchor_index", idx))
			} else {
				lg.DebugContext(ctx, "No matching record not found, no anchor found, inserting to the end")
				newEntries = append(newEntries, values...)
			}
		} else {
			lg.DebugContext(ctx, "No matching record not found, but inserting to the end")
			newEntries = append(newEntries, values...)
		}
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

// anchorInsertIndex returns the index of the last entry before which the
// new values should be inserted: the last entry with the same domain as the
// anchor, or, if none, the last _acme-challenge.* entry. Returns -1 if there
// is no suitable place, in which case new values are appended to the end.
func anchorInsertIndex(entries []zonefile.Entry, anchor []byte) int {
	same, acme := -1, -1
	for i, e := range entries {
		if e.IsComment || e.IsControl {
			continue
		}
		d := e.Domain()
		if d == nil {
			continue
		}
		if dnsNamesEqual(d, anchor) {
			same = i
			continue
		}
		if strings.HasPrefix(strings.ToLower(normalizeZoneName(string(d))), "_acme-challenge.") {
			acme = i
		}
	}
	if same >= 0 {
		return same
	}
	return acme
}

// UpdatePTR updates PTR records for the requested addresses in matching reverse
// zones, pointing them to the target host. All addresses must have a matching
// reverse zone, otherwise ErrZoneNotFound is returned; when target, addresses
// set is empty or mode is invalid an error is returned without changes.
func (s *DomainCtrl) UpdatePTR(ctx context.Context, target string, addresses []netip.Addr, mode PTRUpdateMode) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.domain_ctrl.update_ptr")
	span.SetAttributes(
		attribute.String("zone.ptr.target", target),
		attribute.String("zone.ptr.mode", string(mode)),
		attribute.Int("zone.addr_count", len(addresses)),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	lg := slog.Default().With("target", target)

	if len(addresses) == 0 {
		return false, fmt.Errorf("no addresses provided for PTR update")
	}
	switch mode {
	case PTRUpdateAppend, PTRUpdateReplace, PTRUpdateReplaceAll:
	default:
		return false, fmt.Errorf("invalid PTR update mode: %q", mode)
	}

	targetDot := target
	if !strings.HasSuffix(targetDot, ".") {
		targetDot += "."
	}

	revNames := make([]string, 0, len(addresses))
	zones := make([]*File, 0, len(addresses))
	for _, addr := range addresses {
		name, err := dns.ReverseAddr(addr.String())
		if err != nil {
			return false, fmt.Errorf("failed to build reverse name for %s: %w", addr, err)
		}
		revNames = append(revNames, name)

		fl := s.findZoneFile(ctx, lg.With("domain", name), name)
		if fl == nil {
			return false, fmt.Errorf("%w: %s", ErrZoneNotFound, name)
		}
		zones = append(zones, fl)
	}

	for i, name := range revNames {
		c, err := zones[i].UpdatePTRAddress(ctx, name, targetDot, mode)
		if err != nil {
			lg.WarnContext(ctx, "Failed to update PTR record", "reverse", name, "zonefile", path.Base(zones[i].path), "error", err)
			return changed, err
		}
		changed = changed || c
	}

	if mode == PTRUpdateReplaceAll {
		c, err := s.removeStalePTR(ctx, lg, targetDot, revNames)
		if err != nil {
			return changed, err
		}
		changed = changed || c
	}

	return changed, nil
}

// updatePTRRecords is a best-effort PTR sync for DDNS address updates
// (--ddns-manage-ptr): it updates PTR records for the current addresses and
// removes stale PTR records pointing to the target, skipping addresses without
// a matching reverse zone.
func (s *DomainCtrl) updatePTRRecords(ctx context.Context, lg *slog.Logger, target string, addrs []netip.Addr) {
	targetDot := target
	if !strings.HasSuffix(targetDot, ".") {
		targetDot += "."
	}

	revNames := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		name, err := dns.ReverseAddr(addr.String())
		if err != nil {
			lg.WarnContext(ctx, "Failed to build reverse name", "addr", addr, "error", err)
			continue
		}
		revNames = append(revNames, name)

		fl := s.findZoneFile(ctx, lg.With("domain", name), name)
		if fl == nil {
			lg.DebugContext(ctx, "No reverse zone for address", "reverse", name)
			continue
		}
		if _, err := fl.UpdatePTRAddress(ctx, name, targetDot, PTRUpdateReplaceAll); err != nil {
			lg.WarnContext(ctx, "Failed to update PTR record", "reverse", name, "zonefile", path.Base(fl.path), "error", err)
			continue
		}
		lg.InfoContext(ctx, "PTR record updated", "zonefile", path.Base(fl.path), "reverse", name, "target", targetDot)
	}

	changed, err := s.removeStalePTR(ctx, lg, targetDot, revNames)
	if err != nil {
		lg.WarnContext(ctx, "Failed to clean stale PTR records", "target", targetDot, "error", err)
		return
	}
	if changed {
		lg.InfoContext(ctx, "Stale PTR records cleaned", "target", targetDot)
	}
}

// removeStalePTR removes PTR records pointing to target in managed reverse
// zones whose (absolute) name is not among keep.
func (s *DomainCtrl) removeStalePTR(ctx context.Context, lg *slog.Logger, target string, keep []string) (changed bool, err error) {
	keepSet := make(map[string]struct{}, len(keep))
	for _, k := range keep {
		keepSet[strings.ToLower(k)] = struct{}{}
	}

	for _, fl := range s.files {
		if !isReverseZone(fl.origin) {
			continue
		}
		names, err := fl.findPTRRecords(ctx, target)
		if err != nil {
			return changed, err
		}
		for _, name := range names {
			if _, ok := keepSet[strings.ToLower(name)]; ok {
				continue
			}
			c, err := fl.DeletePTRRecord(ctx, name, target)
			if err != nil {
				lg.WarnContext(ctx, "Failed to delete stale PTR record", "reverse", name, "zonefile", path.Base(fl.path), "error", err)
				continue
			}
			changed = changed || c
		}
	}
	return changed, nil
}

// isReverseZone reports whether the zone origin is a reverse zone
// (in-addr.arpa or ip6.arpa tree).
func isReverseZone(origin string) bool {
	o := strings.ToLower(normalizeZoneName(origin))
	return strings.HasSuffix(o, ".in-addr.arpa.") || strings.HasSuffix(o, ".ip6.arpa.")
}

// UpdatePTRAddress sets the PTR record for ptrName to target in the zone,
// according to mode:
//
//   - append: insert the record only if it is missing, keeping existing PTRs;
//   - replace: set a single PTR record in place, keeping unrelated PTRs on the
//     same name;
//   - replace-all: the PTR record set at that name becomes exactly {target}.
func (s *File) UpdatePTRAddress(ctx context.Context, ptrName, target string, mode PTRUpdateMode) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.file.update_ptr")
	span.SetAttributes(
		attribute.String("zone.file", path.Base(s.path)),
		attribute.String("zone.domain", ptrName),
		attribute.String("zone.ptr.mode", string(mode)),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	lg := s.lg.With("ptr_name", ptrName, "ptr_target", target, "mode", string(mode))

	shortName := []byte(StripOrigin(ptrName, s.origin))

	var matchers Matchers
	replaceAll := true
	switch mode {
	case PTRUpdateAppend:
		matchers = Matchers{{Domain: shortName, RRType: dns.TypePTR, Values: [][]byte{[]byte(target)}}}
	case PTRUpdateReplace:
		matchers = Matchers{{Domain: shortName, RRType: dns.TypePTR}}
		replaceAll = false
	case PTRUpdateReplaceAll:
		matchers = Matchers{{Domain: shortName, RRType: dns.TypePTR}}
	default:
		return false, fmt.Errorf("invalid PTR update mode: %q", mode)
	}

	values, err := parseEntries(bytes.NewBufferString(fmt.Sprintf("\n%s IN PTR %s\n", shortName, target)))
	if err != nil {
		return false, err
	}

	return s.updateRecords(ctx, lg, matchers, values, replaceAll, shortName, true)
}

// DeletePTRRecord removes the PTR record for ptrName pointing to target.
func (s *File) DeletePTRRecord(ctx context.Context, ptrName, target string) (changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	lg := s.lg.With("ptr_name", ptrName, "ptr_target", target)

	matchers := Matchers{{Domain: []byte(StripOrigin(ptrName, s.origin)), RRType: dns.TypePTR, Values: [][]byte{[]byte(target)}}}
	return s.updateRecords(ctx, lg, matchers, nil, true, nil, false)
}

// findPTRRecords returns the absolute names of PTR records in the zone that
// point to target.
func (s *File) findPTRRecords(ctx context.Context, target string) (names []string, err error) {
	zf, _, err := s.load()
	if err != nil {
		return nil, err
	}

	prevDomain := []byte{}
	for _, ent := range zf.Entries() {
		if ent.IsComment || ent.IsControl {
			continue
		}
		d := ent.Domain()
		if d == nil {
			d = prevDomain
		} else {
			prevDomain = d
		}
		if ent.RRType() != dns.TypePTR {
			continue
		}
		vals := ent.Values()
		if len(vals) == 1 && bytes.Equal(vals[0], []byte(target)) {
			names = append(names, absoluteRecordName(d, s.origin))
		}
	}
	return names, nil
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

	_, err = s.updateRecords(ctx, lg, matchers, values, true, nil, true)
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
	if s.acmeTTL > 0 {
		_, _ = fmt.Fprintf(newentbuf, "\n%s %d IN TXT %v\n", shortDomain, s.acmeTTL, quoteTXT(newToken))
	} else {
		_, _ = fmt.Fprintf(newentbuf, "\n%s IN TXT %v\n", shortDomain, quoteTXT(newToken))
	}

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

	_, err = s.updateRecords(ctx, lg, matchers, values, true, shortDomain, true)
	if err != nil {
		return err
	}

	return nil
}

func (s *File) ZMUpdateRecord(ctx context.Context, domain string, typ string, ttl int, newValues []string) (changed bool, err error) {
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
		if ttl > 0 {
			_, _ = fmt.Fprintf(newentbuf, "\n%s %d IN %s %s\n", shortDomain, ttl, typ, val)
		} else {
			_, _ = fmt.Fprintf(newentbuf, "\n%s IN %s %s\n", shortDomain, typ, val)
		}
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

	return s.updateRecords(ctx, lg, matchers, values, true, nil, false)
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
