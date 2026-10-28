package zone

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/vooon/go-masterfile"
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
		if masterfile.NameEqual(fl.origin, zoneName) {
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

	z, err := s.load()
	if err != nil {
		return ZoneSnapshot{}, err
	}

	origin := normalizeZoneName(s.origin)
	zoneData := ZoneSnapshot{
		ID:   origin,
		Name: origin,
	}
	if serial, ok := z.Serial(); ok {
		zoneData.Serial = serial
	}

	for _, set := range z.RRSets() {
		zoneData.RRsets = append(zoneData.RRsets, RRSet{
			Name:    set.Owner,
			Type:    set.Type,
			TTL:     int(set.TTL),
			Records: set.Contents,
		})
		if set.Type == "NS" && masterfile.NameEqual(set.Owner, origin) {
			zoneData.Nameservers = append(zoneData.Nameservers, set.Contents...)
		}
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

	rrType, err := parseRRType(typ)
	if err != nil {
		return false, err
	}
	ttl32, err := ttlValue(ttl)
	if err != nil {
		return false, err
	}

	return s.apply(ctx, lg, masterfile.Replace{
		Selector: masterfile.Selector{Owner: name, Types: []uint16{rrType}},
		Records:  rrs(rrType, ttl32, values),
	})
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

	rrType, err := parseRRType(typ)
	if err != nil {
		return false, err
	}

	return s.apply(ctx, lg, masterfile.Delete{Selector: masterfile.Selector{Owner: name, Types: []uint16{rrType}}})
}

func normalizeZoneName(name string) string {
	return dns.Fqdn(strings.TrimSpace(name))
}
