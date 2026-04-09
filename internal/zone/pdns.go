package zone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/vooon/zoneomatic/pkg/zonefile"
	"go.opentelemetry.io/otel/attribute"
)

type RRSet struct {
	Name    string
	Type    string
	TTL     int
	Records []string
}

type ZoneSnapshot struct {
	ID          string
	Name        string
	Serial      uint32
	RRsets      []RRSet
	Nameservers []string
}

func (s *DomainCtrl) ListZones(ctx context.Context) ([]ZoneSnapshot, error) {
	ctx, span := zoneTracer.Start(ctx, "zone.domain_ctrl.list_zones")
	span.SetAttributes(attribute.Int("zone.file_count", len(s.files)))
	defer span.End()

	ret := make([]ZoneSnapshot, 0, len(s.files))
	for _, fl := range s.files {
		zoneData, err := fl.Snapshot(ctx)
		if err != nil {
			recordSpanError(span, err)
			return nil, err
		}

		ret = append(ret, zoneData)
	}

	slices.SortFunc(ret, func(a, b ZoneSnapshot) int {
		return strings.Compare(a.Name, b.Name)
	})
	span.SetAttributes(attribute.Int("zone.count", len(ret)))

	return ret, nil
}

func (s *DomainCtrl) GetZone(ctx context.Context, zoneName string) (snapshot ZoneSnapshot, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.domain_ctrl.get_zone")
	span.SetAttributes(attribute.String("zone.name", zoneName))
	defer func() {
		recordSpanError(span, err)
		span.End()
	}()

	fl := s.findExactZoneFile(zoneName)
	if fl == nil {
		err = fmt.Errorf("%w: %s", ErrZoneNotFound, zoneName)
		return ZoneSnapshot{}, err
	}

	span.SetAttributes(attribute.String("zone.file", path.Base(fl.path)))
	return fl.Snapshot(ctx)
}

func (s *DomainCtrl) ReplaceRRSet(ctx context.Context, zoneName, name, typ string, ttl int, values []string) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.domain_ctrl.replace_rrset")
	span.SetAttributes(
		attribute.String("zone.name", zoneName),
		attribute.String("dns.rr.name", name),
		attribute.String("dns.rr.type", typ),
		attribute.Int("dns.rr.ttl", ttl),
		attribute.Int("zone.value_count", len(values)),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	fl := s.findExactZoneFile(zoneName)
	if fl == nil {
		err = fmt.Errorf("%w: %s", ErrZoneNotFound, zoneName)
		return false, err
	}

	span.SetAttributes(attribute.String("zone.file", path.Base(fl.path)))
	return fl.ReplaceRRSet(ctx, name, typ, ttl, values)
}

func (s *DomainCtrl) DeleteRRSet(ctx context.Context, zoneName, name, typ string) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.domain_ctrl.delete_rrset")
	span.SetAttributes(
		attribute.String("zone.name", zoneName),
		attribute.String("dns.rr.name", name),
		attribute.String("dns.rr.type", typ),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	fl := s.findExactZoneFile(zoneName)
	if fl == nil {
		err = fmt.Errorf("%w: %s", ErrZoneNotFound, zoneName)
		return false, err
	}

	span.SetAttributes(attribute.String("zone.file", path.Base(fl.path)))
	return fl.DeleteRRSet(ctx, name, typ)
}

func (s *DomainCtrl) findExactZoneFile(zoneName string) *File {
	zoneName = normalizeZoneName(zoneName)
	for _, fl := range s.files {
		if strings.EqualFold(normalizeZoneName(fl.origin), zoneName) {
			return fl
		}
	}

	return nil
}

func (s *File) Snapshot(ctx context.Context) (snapshot ZoneSnapshot, err error) {
	_, span := zoneTracer.Start(ctx, "zone.file.snapshot")
	span.SetAttributes(attribute.String("zone.file", path.Base(s.path)))
	defer func() {
		span.SetAttributes(
			attribute.String("zone.name", snapshot.Name),
			attribute.Int("zone.rrset_count", len(snapshot.RRsets)),
			attribute.Int("zone.nameserver_count", len(snapshot.Nameservers)),
		)
		recordSpanError(span, err)
		span.End()
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	zf, soa, err := s.load()
	if err != nil {
		return ZoneSnapshot{}, err
	}

	origin := normalizeZoneName(s.origin)
	zoneData := ZoneSnapshot{
		ID:   origin,
		Name: origin,
	}

	if soa != nil {
		soaValues := soa.ValuesStrings()
		if len(soaValues) >= 3 {
			serial, err := strconv.ParseUint(soaValues[2], 10, 32)
			if err == nil {
				zoneData.Serial = uint32(serial)
			}
		}
	}

	currentTTL := 0
	rrsetsByKey := make(map[string]*RRSet)
	rrsetOrder := make([]string, 0)

	for _, ent := range zf.Entries() {
		if ent.IsComment {
			continue
		}

		if ent.IsControl {
			if bytes.Equal(ent.Command(), []byte("$TTL")) && len(ent.Values()) > 0 {
				if ttl, ok := zonefile.StringToTTL(string(ent.Values()[0])); ok {
					currentTTL = int(ttl)
				}
			}
			continue
		}

		rrType := ent.RRType()
		if rrType == 0 {
			continue
		}

		name := absoluteRecordName(ent.Domain(), origin)
		typeName := strings.ToUpper(string(ent.Type()))
		ttl := currentTTL
		if entTTL := ent.TTL(); entTTL != nil {
			ttl = *entTTL
		}

		key := name + "\x00" + typeName
		rrset, ok := rrsetsByKey[key]
		if !ok {
			rrset = &RRSet{
				Name: name,
				Type: typeName,
				TTL:  ttl,
			}
			rrsetsByKey[key] = rrset
			rrsetOrder = append(rrsetOrder, key)
		}

		content := entryContent(ent)
		rrset.Records = append(rrset.Records, content)

		if rrType == dns.TypeNS && name == origin {
			zoneData.Nameservers = append(zoneData.Nameservers, content)
		}
	}

	zoneData.RRsets = make([]RRSet, 0, len(rrsetOrder))
	for _, key := range rrsetOrder {
		zoneData.RRsets = append(zoneData.RRsets, *rrsetsByKey[key])
	}

	return zoneData, nil
}

func (s *File) ReplaceRRSet(ctx context.Context, name, typ string, ttl int, values []string) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.file.replace_rrset")
	span.SetAttributes(
		attribute.String("zone.file", path.Base(s.path)),
		attribute.String("dns.rr.name", name),
		attribute.String("dns.rr.type", typ),
		attribute.Int("dns.rr.ttl", ttl),
		attribute.Int("zone.value_count", len(values)),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	if ttl <= 0 {
		return false, fmt.Errorf("invalid ttl: %d", ttl)
	}

	lg := s.lg.With("rr_name", name, "rr_type", typ, "ttl", ttl, "record_count", len(values))

	typ = strings.ToUpper(strings.TrimSpace(typ))
	rrType, ok := dns.StringToType[typ]
	if !ok {
		return false, fmt.Errorf("unknown rrtype: %s", typ)
	}

	shortName, err := s.relativeRecordName(name)
	if err != nil {
		return false, err
	}

	newentbuf := bytes.NewBuffer(nil)
	for _, val := range values {
		_, _ = fmt.Fprintf(newentbuf, "\n%s %d IN %s %s\n", shortName, ttl, typ, formatRecordValue(rrType, val))
	}

	entries, err := parseEntries(newentbuf)
	if err != nil {
		return false, err
	}

	matchers := []Matcher{{
		Domain: []byte(shortName),
		RRType: rrType,
	}}

	return s.updateRecords(ctx, lg, matchers, entries, true)
}

func (s *File) DeleteRRSet(ctx context.Context, name, typ string) (changed bool, err error) {
	ctx, span := zoneTracer.Start(ctx, "zone.file.delete_rrset")
	span.SetAttributes(
		attribute.String("zone.file", path.Base(s.path)),
		attribute.String("dns.rr.name", name),
		attribute.String("dns.rr.type", typ),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("zone.changed", changed))
		recordSpanError(span, err)
		span.End()
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	lg := s.lg.With("rr_name", name, "rr_type", typ)

	typ = strings.ToUpper(strings.TrimSpace(typ))
	rrType, ok := dns.StringToType[typ]
	if !ok {
		return false, fmt.Errorf("unknown rrtype: %s", typ)
	}

	shortName, err := s.relativeRecordName(name)
	if err != nil {
		return false, err
	}

	matchers := []Matcher{{
		Domain: []byte(shortName),
		RRType: rrType,
	}}

	changed, err = s.updateRecords(ctx, lg, matchers, nil, false)
	if errors.Is(err, ErrRecordNotFound) {
		return false, nil
	}

	return changed, err
}

func (s *File) relativeRecordName(name string) (string, error) {
	name = normalizeZoneName(name)
	if !domainMatchesOrigin(name, s.origin) {
		return "", fmt.Errorf("record name not in zone %s: %s", s.origin, name)
	}

	shortName := StripOrigin(name, s.origin)
	if shortName == "@" {
		return shortName, nil
	}

	return strings.TrimSuffix(strings.ToLower(normalizeZoneName(shortName)), "."), nil
}

func normalizeZoneName(name string) string {
	return dns.Fqdn(strings.TrimSpace(name))
}

func absoluteRecordName(name []byte, origin string) string {
	if len(name) == 0 || bytes.Equal(name, []byte("@")) {
		return origin
	}

	if dns.IsFqdn(string(name)) {
		return string(name)
	}

	return dns.Fqdn(string(name) + "." + strings.TrimSuffix(origin, "."))
}

func entryContent(ent zonefile.Entry) string {
	values := ent.ValuesStrings()
	switch ent.RRType() {
	case dns.TypeTXT, dns.TypeSPF:
		return strings.Join(values, "")
	default:
		return strings.Join(values, " ")
	}
}

func formatRecordValue(rrType uint16, value string) string {
	switch rrType {
	case dns.TypeTXT, dns.TypeSPF:
		return quoteTXT(value)
	default:
		return value
	}
}
