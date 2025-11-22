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

var ErrSoaNotFound = errors.New("SOA not found")

type Controller interface {
	UpdateDomain(ctx context.Context, domain string, addrs []netip.Addr) error
	UpdateACMEChallenge(ctx context.Context, domain string, token string) error
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

		_, _, err := f.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to load zone: %s: %w", fileName, err)
		}

		ret = append(ret, f)
	}

	return &DomainCtrl{files: ret}, nil
}

func (s *DomainCtrl) UpdateDomain(ctx context.Context, domain string, addrs []netip.Addr) error {

	lg := slog.Default().With("domain", domain)

	domainDot := domain
	if !strings.HasSuffix(domainDot, ".") {
		domainDot += "."
	}

	for _, fl := range s.files {
		lg.DebugContext(ctx, "Check file", "file_origin", fl.origin)
		if strings.HasSuffix(domainDot, fl.origin) {
			lg.InfoContext(ctx, "Zone file found", "zonefile", path.Base(fl.path))
			return fl.UpdateDomain(ctx, domainDot, addrs)
		}
	}

	return &fuego.HTTPError{
		Title:  "zone not found",
		Detail: fmt.Sprintf("zone not found for domain: %s", domain),
		Status: http.StatusNotFound,
	}
}

func (s *DomainCtrl) UpdateACMEChallenge(ctx context.Context, domain string, token string) error {

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
			return fl.UpdateACMEChallenge(ctx, domainDot, token)
		}
	}

	return &fuego.HTTPError{
		Title:  "zone not found",
		Detail: fmt.Sprintf("zone not found for domain: %s", domain),
		Status: http.StatusNotFound,
	}
}

func (s *File) Load() (zf *zonefile.Zonefile, soa *zonefile.Entry, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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

		_ = ent.SetDomain(dnsfmt.StripOrigin([]byte(s.origin), dom))

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

func (s *File) UpdateDomain(ctx context.Context, domain string, addrs []netip.Addr) error {

	zf, _, err := s.Load()
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

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
	newent := make([]byte, 0, 1024)

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
	}
	for i := len(entAAAA); i < len(newAAAA); i++ {
		newent = fmt.Appendf(newent, "\n%s IN AAAA %v\n", shortDomain, newAAAA[i])
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
			_ = ent.SetValue(0, []byte(newA[i].String()))
			continue
		}

		if len(newA) != 0 {
			_ = ent.SetValue(0, []byte(newA[0].String()))
		}
	}

	for i, ent := range entAAAA {
		if i < len(newAAAA) {
			_ = ent.SetValue(0, []byte(newAAAA[i].String()))
			continue
		}

		if len(newAAAA) != 0 {
			_ = ent.SetValue(0, []byte(newAAAA[0].String()))
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
		s.lg.ErrorContext(ctx, "Failed to save file", "error", err)
		return err
	}

	return nil
}

func (s *File) UpdateACMEChallenge(ctx context.Context, domain string, token string) error {

	zf, _, err := s.Load()
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	shortDomain := []byte(StripOrigin(domain, s.origin))

	allEnt := zf.Entries()
	entTXT := make([]*zonefile.Entry, 0, 1)
	newent := make([]byte, 0, 1024)

	for _, ent := range allEnt {
		if !bytes.Equal(ent.Domain(), shortDomain) {
			continue
		}

		if ent.RRType() == dns.TypeTXT {
			entTXT = append(entTXT, &ent)
		}
	}

	if len(entTXT) < 1 {
		newent = fmt.Appendf(newent, "\n%s IN TXT \"%v\"\n", shortDomain, token)
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
		ent.SetValue(0, []byte(token))
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
			quoted := strings.ReplaceAll(string(v), `"`, `\"`)
			fmt.Fprintf(w, " \"%s\" ", quoted) // nolint:errcheck
		}

		fmt.Fprintln(w) // nolint:errcheck
	}
}
