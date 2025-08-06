package zone

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/bwesterb/go-zonefile"
	"github.com/go-fuego/fuego"
)

type Controller interface {
	UpdateDomain(ctx context.Context, domain string, addrs []netip.Addr) error
}

type File struct {
	origin string
	path   string
	stat   os.FileInfo
	zf     *zonefile.Zonefile
	soa    *zonefile.Entry
	lg     *slog.Logger
	mu     sync.Mutex
}

type DomainCtrl struct {
	files []*File
}

func New(zonefiles ...string) (Controller, error) {

	ret := make([]*File, 0, len(zonefiles))
	for _, fl := range zonefiles {
		f := &File{
			path: fl,
			lg:   slog.Default().With("zone_file", path.Base(fl)),
		}

		err := f.Reload()
		if err != nil {
			return nil, err
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

func (s *File) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := os.Stat(s.path)
	if err != nil {
		return err
	}

	if s.stat == st {
		// nothing to do
		s.lg.Debug("File not changed")
		return nil
	}

	buf, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}

	zf, err := zonefile.Load(buf)
	if err != nil {
		return err
	}

	ok := false
	for _, ent := range zf.Entries() {
		if bytes.Equal(ent.Command(), []byte("$ORIGIN")) {
			s.origin = string(ent.Values()[0])
		}

		if !bytes.Equal(ent.Type(), []byte("SOA")) {
			continue
		}

		s.soa = &ent
		ok = true
	}
	if !ok {
		return fmt.Errorf("SOA not found")
	}

	if s.origin == "" {
		s.origin = string(s.soa.Domain())
	}
	s.stat = st
	s.zf = zf

	return nil
}

func (s *File) UpdateDomain(ctx context.Context, domain string, addrs []netip.Addr) error {

	err := s.Reload()
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

	entA := make([]*zonefile.Entry, 0, len(newA))
	entAAAA := make([]*zonefile.Entry, 0, len(newAAAA))

	for _, ent := range s.zf.Entries() {
		if !bytes.Equal(ent.Domain(), shortDomain) {
			continue
		}

		if bytes.Equal(ent.Type(), []byte("A")) {
			entA = append(entA, &ent)
		} else if bytes.Equal(ent.Type(), []byte("AAAA")) {
			entAAAA = append(entAAAA, &ent)
		}
	}

	for i := len(entA); i < len(newA); i++ {
		// XXX: AddA does not set Type, and it's impossible to change it later
		// ent := s.zf.AddA(string(shortDomain), newA[i].String())

		ent, err := zonefile.ParseEntry(fmt.Appendf(nil, "%s IN A %v", shortDomain, newA[i]))
		if err != nil {
			return err
		}

		entA = append(entA, s.zf.AddEntry(ent))
	}
	for i := len(entAAAA); i < len(newAAAA); i++ {
		ent, err := zonefile.ParseEntry(fmt.Appendf(nil, "%s IN AAAA %v", shortDomain, newAAAA[i]))
		if err != nil {
			return err
		}

		entAAAA = append(entAAAA, s.zf.AddEntry(ent))
	}

	for i, ent := range entA {
		if i < len(newA) {
			ent.SetValue(0, []byte(newA[i].String()))
			continue
		}

		if len(newA) != 0 {
			ent.SetValue(0, []byte(newA[0].String()))
		}
	}

	for i, ent := range entAAAA {
		if i < len(newAAAA) {
			ent.SetValue(0, []byte(newAAAA[i].String()))
			continue
		}

		if len(newAAAA) != 0 {
			ent.SetValue(0, []byte(newAAAA[0].String()))
		}
	}

	fmt.Println(string(s.zf.Save()))

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
