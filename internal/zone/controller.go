package zone

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/vooon/go-masterfile"
	"github.com/vooon/zoneomatic/pkg/fileutil"
	"go.opentelemetry.io/otel/attribute"
)

var (
	// ErrSoaNotFound is returned for a zone file without an SOA record, which
	// is mandatory.
	ErrSoaNotFound = errors.New("SOA not found")
	// ErrRecordNotFound is returned when an update needs an existing record
	// and there is none.
	ErrRecordNotFound = errors.New("record not found")
	// ErrNoAddresses is returned for a DDNS or PTR update without addresses.
	ErrNoAddresses = errors.New("no addresses provided")
	// ErrOriginChanged is returned when a zone file's SOA names another zone
	// than it did when it was first loaded.
	ErrOriginChanged = errors.New("zone origin changed")
	ErrZoneNotFound  = errors.New("zone not found")
	// ErrInvalidACMEToken is returned for a challenge value that is not a
	// base64url ACME key authorization digest.
	ErrInvalidACMEToken = errors.New("invalid ACME challenge token")
	// ErrInvalidRecord is returned for a record name, TTL or value that does
	// not form exactly one record.
	ErrInvalidRecord = masterfile.ErrInvalidRecord
)

// EmptyPlaceholder will be used instead of empty ACME TXT because we cannot really set ""
const EmptyPlaceholder = "placeholder"

// ValidACMEToken reports whether v may be stored as an ACME dns-01 TXT value.
// Real values are the 43-character base64url SHA-256 digest of the key
// authorization (RFC 8555, section 8.4); anything else is rejected so that
// clients allowed to answer challenges cannot write arbitrary text into the
// zone. The empty string (no value) and EmptyPlaceholder are also accepted.
func ValidACMEToken(v string) bool {
	if v == "" || v == EmptyPlaceholder {
		return true
	}
	if len(v) > 255 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !isBase64URLChar(v[i]) {
			return false
		}
	}
	return true
}

func isBase64URLChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	default:
		return c == '-' || c == '_'
	}
}

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
	// ApplyRecordUpdate adds and/or removes individual values of an existing
	// RRSet, preserving the position of the RRSet in the zone file. Adding a
	// value that already exists is a no-op; removing a missing value is also a
	// no-op. Used by the RFC2136 update listener.
	ApplyRecordUpdate(ctx context.Context, domain string, typ string, ttl int, add []string, remove []string) (changed bool, err error)
	// RemoveRecordName removes all RRsets that belong to a record name.
	// Used by the RFC2136 update listener for ClassANY + TypeANY deletes.
	RemoveRecordName(ctx context.Context, domain string) (changed bool, err error)
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

		if _, err := f.load(); err != nil {
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

	domainDot := normalizeZoneName(domain)

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

	if !ValidACMEToken(newToken) || !ValidACMEToken(oldToken) {
		err = ErrInvalidACMEToken
		return err
	}

	domainDot := normalizeZoneName(domain)

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

	domainDot := normalizeZoneName(domain)

	fl := s.findZoneFile(ctx, lg, domainDot)
	if fl != nil {
		span.SetAttributes(attribute.String("zone.file", path.Base(fl.path)))
		lg.InfoContext(ctx, "Zone file found", "zonefile", path.Base(fl.path))
		return fl.ZMUpdateRecord(ctx, domainDot, typ, ttl, values)
	}

	err = fmt.Errorf("%w: %s", ErrZoneNotFound, domain)
	return false, err
}

func (s *DomainCtrl) ApplyRecordUpdate(ctx context.Context, domain string, typ string, ttl int, add []string, remove []string) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.domain_ctrl.apply_record_update")
	span.SetAttributes(
		attribute.String("zone.domain", domain),
		attribute.String("dns.rr.type", typ),
		attribute.Int("zone.add_count", len(add)),
		attribute.Int("zone.remove_count", len(remove)),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	lg := slog.Default().With("domain", domain)

	domainDot := normalizeZoneName(domain)

	fl := s.findZoneFile(ctx, lg, domainDot)
	if fl == nil {
		err = fmt.Errorf("%w: %s", ErrZoneNotFound, domain)
		return false, err
	}

	span.SetAttributes(attribute.String("zone.file", path.Base(fl.path)))
	lg.InfoContext(ctx, "Zone file found", "zonefile", path.Base(fl.path))

	return fl.ApplyRecordUpdate(ctx, domainDot, typ, ttl, add, remove)
}

func (s *DomainCtrl) RemoveRecordName(ctx context.Context, domain string) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.domain_ctrl.remove_record_name")
	span.SetAttributes(attribute.String("zone.domain", domain))
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	lg := slog.Default().With("domain", domain)

	domainDot := normalizeZoneName(domain)

	fl := s.findZoneFile(ctx, lg, domainDot)
	if fl == nil {
		err = fmt.Errorf("%w: %s", ErrZoneNotFound, domain)
		return false, err
	}

	span.SetAttributes(attribute.String("zone.file", path.Base(fl.path)))
	return fl.RemoveRecordName(ctx, domainDot)
}

// findZoneFile returns the managed zone whose origin contains domainDot and
// is the longest such origin, or nil.
func (s *DomainCtrl) findZoneFile(ctx context.Context, lg *slog.Logger, domainDot string) *File {
	apexes := make([]string, 0, len(s.files))
	for _, fl := range s.files {
		lg.DebugContext(ctx, "Check file", "file_origin", fl.origin)
		apexes = append(apexes, fl.origin)
	}
	apex, ok := masterfile.LongestZone(domainDot, apexes)
	if !ok {
		return nil
	}
	for _, fl := range s.files {
		if fl.origin == apex {
			return fl
		}
	}
	return nil
}

// load reads and parses the zone file. Every record gets an explicit owner
// relative to the zone origin (see masterfile.Parse). The origin is the SOA
// owner; it must stay the same across loads.
func (s *File) load() (*masterfile.Zone, error) {
	buf, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}

	z, err := masterfile.Parse(buf, s.origin)
	if err != nil {
		if errors.Is(err, masterfile.ErrApexMismatch) {
			return nil, fmt.Errorf("%w: prev=%s: %w", ErrOriginChanged, s.origin, err)
		}
		return nil, err
	}
	if err := z.Check(); err != nil {
		switch {
		case errors.Is(err, masterfile.ErrNoSOA):
			return nil, ErrSoaNotFound
		case errors.Is(err, masterfile.ErrNoOrigin):
			return nil, fmt.Errorf("%w: cannot determine the zone origin, set $ORIGIN or use an absolute SOA owner", ErrSoaNotFound)
		}
		return nil, err
	}

	if s.origin == "" {
		s.origin = z.Apex()
		s.lg.Info("Detected origin", "origin", s.origin)
	}

	return z, nil
}

// apply runs the operations on the zone file and rewrites it atomically when
// the zone's meaning changed; the written file is verified first (see
// masterfile.Zone.Commit). Callers must hold s.mu.
func (s *File) apply(ctx context.Context, lg *slog.Logger, ops ...masterfile.Op) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.file.apply")
	span.SetAttributes(
		attribute.String("zone.file", path.Base(s.path)),
		attribute.Int("zone.op_count", len(ops)),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	z, err := s.load()
	if err != nil {
		return false, err
	}

	results, err := z.Apply(ops...)
	if err != nil {
		if errors.Is(err, masterfile.ErrNotFound) {
			lg.ErrorContext(ctx, "No matching record found, but insert is not allowed")
			return false, fmt.Errorf("%w: %w", ErrRecordNotFound, err)
		}
		return false, err
	}
	for i, r := range results {
		lg.DebugContext(ctx, "Operation applied",
			"op", fmt.Sprintf("%T%+v", ops[i], ops[i]),
			"matched", r.Matched, "removed", r.Removed, "inserted", r.Inserted, "index", r.Index, "changed", r.Changed)
	}

	data, changed, err := z.Commit(true)
	if err != nil {
		lg.ErrorContext(ctx, "Zone file verification failed, not saving", "error", err)
		return false, err
	}
	if !changed {
		lg.InfoContext(ctx, "No records changed", "changed", changed)
		return false, nil
	}

	if err = fileutil.AtomicWriteFile(s.path, data); err != nil {
		lg.ErrorContext(ctx, "Failed to save file", "error", err, "changed", changed)
		return false, err
	}

	lg.InfoContext(ctx, "File saved", "changed", changed)
	return true, nil
}

// ttlValue checks a client-supplied TTL; 0 means no explicit TTL.
func ttlValue(ttl int) (uint32, error) {
	if ttl < 0 || ttl > math.MaxInt32 {
		return 0, fmt.Errorf("%w: ttl %d out of range", ErrInvalidRecord, ttl)
	}
	return uint32(ttl), nil
}

// rrs builds the records of one RRset for the editing operations.
func rrs(rtype uint16, ttl uint32, contents []string) []masterfile.RR {
	ret := make([]masterfile.RR, 0, len(contents))
	for _, c := range contents {
		ret = append(ret, masterfile.RR{Type: rtype, TTL: ttl, Content: c})
	}
	return ret
}

// acmePlacement puts a new challenge record after the records of its own
// name, else after the last _acme-challenge record in the file, else at the
// end.
func acmePlacement(name string) masterfile.Placement {
	return masterfile.Placement{{Owner: name}, {Prefix: "_acme-challenge"}}
}

func parseRRType(typ string) (uint16, error) {
	typ = strings.ToUpper(strings.TrimSpace(typ))
	rrType, ok := dns.StringToType[typ]
	if !ok {
		return 0, fmt.Errorf("unknown rrtype: %s", typ)
	}
	return rrType, nil
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

	targetDot := normalizeZoneName(target)

	revNames := make([]string, 0, len(addresses))
	zones := make([]*File, 0, len(addresses))
	for _, addr := range addresses {
		name := masterfile.ReverseName(addr)
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
	targetDot := normalizeZoneName(target)

	revNames := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		name := masterfile.ReverseName(addr)
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
		if !masterfile.IsReverseZone(fl.origin) {
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

	op := masterfile.Replace{
		Selector:  masterfile.Selector{Owner: ptrName, Types: []uint16{dns.TypePTR}},
		Records:   rrs(dns.TypePTR, 0, []string{target}),
		Placement: masterfile.Placement{{Owner: ptrName}},
	}
	switch mode {
	case PTRUpdateAppend:
		op.Contents = []string{target}
	case PTRUpdateReplace:
		op.Mode = masterfile.ReplaceFirst
	case PTRUpdateReplaceAll:
	default:
		return false, fmt.Errorf("invalid PTR update mode: %q", mode)
	}

	return s.apply(ctx, lg, op)
}

// DeletePTRRecord removes the PTR record for ptrName pointing to target.
func (s *File) DeletePTRRecord(ctx context.Context, ptrName, target string) (changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	lg := s.lg.With("ptr_name", ptrName, "ptr_target", target)

	return s.apply(ctx, lg, masterfile.Delete{Selector: masterfile.Selector{
		Owner: ptrName, Types: []uint16{dns.TypePTR}, Contents: []string{target},
	}})
}

// findPTRRecords returns the absolute names of PTR records in the zone that
// point to target.
func (s *File) findPTRRecords(_ context.Context, target string) (names []string, err error) {
	z, err := s.load()
	if err != nil {
		return nil, err
	}
	return z.Owners(masterfile.Selector{Types: []uint16{dns.TypePTR}, Contents: []string{target}}), nil
}

// UpdateDDNSAddress makes the A and AAAA records of domain exactly the given
// addresses. Only the families present in addrs are touched: an update with
// IPv4 addresses alone keeps the AAAA records.
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

	if len(addrs) == 0 {
		recordSpanError(span, ErrNoAddresses)
		return ErrNoAddresses
	}

	addrs = slices.Clone(addrs)
	slices.SortFunc(addrs, netip.Addr.Compare)

	var v4, v6 []string
	for _, a := range addrs {
		if a.Is4() {
			v4 = append(v4, a.String())
			continue
		}
		v6 = append(v6, a.String())
	}
	span.SetAttributes(
		attribute.Int("zone.addr_v4_count", len(v4)),
		attribute.Int("zone.addr_v6_count", len(v6)),
	)

	var types []uint16
	var records []masterfile.RR
	if len(v4) > 0 {
		types = append(types, dns.TypeA)
		records = append(records, rrs(dns.TypeA, 0, v4)...)
	}
	if len(v6) > 0 {
		types = append(types, dns.TypeAAAA)
		records = append(records, rrs(dns.TypeAAAA, 0, v6)...)
	}

	_, err := s.apply(ctx, lg, masterfile.Replace{
		Selector: masterfile.Selector{Owner: domain, Types: types},
		Records:  records,
	})
	if err != nil {
		recordSpanError(span, err)
		return err
	}
	return nil
}

// UpdateACMEChallenge presents or cleans up a dns-01 challenge TXT record.
//
//   - newToken set, oldToken empty (ACME DNS mode): every TXT of the name is
//     replaced by newToken;
//   - newToken and oldToken set (HTTP-REQ mode): only a TXT equal to oldToken
//     is replaced, other tokens of the name stay (wildcard + apex orders
//     present two tokens for one name);
//   - newToken empty, oldToken set (cleanup): oldToken is removed and exactly
//     one placeholder TXT is left for the name, so the name keeps existing;
//   - both empty: every TXT of the name becomes the placeholder.
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

	ttl, err := ttlValue(s.acmeTTL)
	if err != nil {
		return err
	}

	var op masterfile.Op
	switch {
	case newToken == "" && oldToken != "":
		op = masterfile.Collapse{
			Owner:     domain,
			Type:      dns.TypeTXT,
			Drop:      []string{oldToken},
			Keep:      EmptyPlaceholder,
			KeepTTL:   ttl,
			Placement: acmePlacement(domain),
		}
	default:
		if newToken == "" {
			lg.Warn("Use placeholder for empty TXT record")
			newToken = EmptyPlaceholder
		}
		sel := masterfile.Selector{Owner: domain, Types: []uint16{dns.TypeTXT}}
		if oldToken != "" {
			sel.Contents = []string{oldToken}
		}
		op = masterfile.Replace{
			Selector:  sel,
			Records:   rrs(dns.TypeTXT, ttl, []string{newToken}),
			Placement: acmePlacement(domain),
		}
	}

	_, err = s.apply(ctx, lg, op)
	return err
}

// ZMUpdateRecord replaces the values of an existing RRset; a name and type
// without records is ErrRecordNotFound.
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

	rrType, err := parseRRType(typ)
	if err != nil {
		return false, err
	}
	ttl32, err := ttlValue(ttl)
	if err != nil {
		return false, err
	}

	return s.apply(ctx, lg, masterfile.Replace{
		Selector:  masterfile.Selector{Owner: domain, Types: []uint16{rrType}},
		Records:   rrs(rrType, ttl32, newValues),
		MustExist: true,
	})
}

// ApplyRecordUpdate adds and/or removes individual values of an RRset, as a
// DNS UPDATE does. The RRset keeps its place in the zone file: additions go
// after its last existing value and removals only drop the matching value.
// Adding an already present value and removing a missing value are no-ops.
func (s *File) ApplyRecordUpdate(ctx context.Context, domain string, typ string, ttl int, add []string, remove []string) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.file.apply_record_update")
	span.SetAttributes(
		attribute.String("zone.file", path.Base(s.path)),
		attribute.String("zone.domain", domain),
		attribute.String("dns.rr.type", typ),
		attribute.Int("zone.add_count", len(add)),
		attribute.Int("zone.remove_count", len(remove)),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	lg := s.lg.With("domain", domain, "rr_type", typ, "add", add, "remove", remove)

	rrType, err := parseRRType(typ)
	if err != nil {
		return false, err
	}
	ttl32, err := ttlValue(ttl)
	if err != nil {
		return false, err
	}

	return s.apply(ctx, lg, masterfile.AddRemove{
		Owner:  domain,
		Type:   rrType,
		TTL:    ttl32,
		Add:    add,
		Remove: remove,
	})
}

// RemoveRecordName removes all RRsets that belong to a record name.
func (s *File) RemoveRecordName(ctx context.Context, domain string) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.file.remove_record_name")
	span.SetAttributes(
		attribute.String("zone.file", path.Base(s.path)),
		attribute.String("zone.domain", domain),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	lg := s.lg.With("domain", domain)

	return s.apply(ctx, lg, masterfile.DeleteOwner{Owner: domain})
}
