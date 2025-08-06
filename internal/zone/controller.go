package zone

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path"
	"sync"

	"github.com/miekg/dnsfmt/zonefile"
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
	return nil
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
		if !bytes.Equal(ent.Type(), []byte("SOA")) {
			continue
		}

		s.soa = &ent
		ok = true
	}
	if !ok {
		return fmt.Errorf("SOA not found")
	}

	s.origin = string(s.soa.Domain())
	s.stat = st
	s.zf = zf

	return nil
}
