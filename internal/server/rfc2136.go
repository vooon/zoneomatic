package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/vooon/zoneomatic/internal/tsig"
	"github.com/vooon/zoneomatic/internal/zone"
)

var rfc2136Tracer = otel.Tracer("zoneomatic/rfc2136")

// RFC2136Config configures a single dynamic-update listener.
type RFC2136Config struct {
	// Listen is the host:port to bind. Empty disables the listener.
	Listen string
	// TSIGFile is a BIND-format key file. Required when Listen is set.
	TSIGFile string
	// Allow optionally restricts clients to these prefixes. Empty allows all.
	Allow []netip.Prefix
	// ACMEOnly restricts the listener to _acme-challenge.* TXT updates and maps
	// them onto the ACME challenge controller.
	ACMEOnly bool
	// MaxTTL caps the effective TTL of records written through the full-update
	// listener when it is set and smaller than the record TTL.
	MaxTTL int
}

// RFC2136Server runs the UDP and TCP dynamic-update listeners for a config.
type RFC2136Server struct {
	servers []*dns.Server
	lg      *slog.Logger
}

// StartRFC2136 starts the configured listener. It returns nil when cfg.Listen
// is empty, so an unset address means "disabled".
func StartRFC2136(cfg RFC2136Config, zctl zone.Controller) (*RFC2136Server, error) {
	if strings.TrimSpace(cfg.Listen) == "" {
		return nil, nil
	}

	keys, err := tsig.NewFromFile(cfg.TSIGFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TSIG keys for %s: %w", cfg.Listen, err)
	}

	h := &rfc2136Handler{
		zctl:     zctl,
		acmeOnly: cfg.ACMEOnly,
		allow:    cfg.Allow,
		maxTTL:   cfg.MaxTTL,
		lg:       slog.Default().With("component", "rfc2136", "listen", cfg.Listen, "acme_only", cfg.ACMEOnly),
	}

	handler := dns.HandlerFunc(h.serve)

	srv := &RFC2136Server{lg: h.lg}

	for _, network := range []string{"udp", "tcp"} {
		started := make(chan struct{})
		s := &dns.Server{
			Addr:              cfg.Listen,
			Net:               network,
			Handler:           handler,
			TsigProvider:      keys,
			MsgAcceptFunc:     updateMsgAcceptFunc,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			NotifyStartedFunc: func() { close(started) },
		}
		srv.servers = append(srv.servers, s)

		errCh := make(chan error, 1)
		go func(s *dns.Server) {
			h.lg.Info("RFC2136 listener started", "network", s.Net)
			errCh <- s.ListenAndServe()
		}(s)

		// Wait until the socket is bound (or binding failed) so a bad address
		// or port conflict is reported by the caller instead of being lost in
		// the background goroutine.
		select {
		case <-started:
		case err := <-errCh:
			_ = srv.Shutdown(context.Background())
			return nil, fmt.Errorf("failed to start RFC2136 %s listener on %s: %w", network, cfg.Listen, err)
		}

		go func(s *dns.Server, errCh <-chan error) {
			if err := <-errCh; err != nil {
				h.lg.Error("RFC2136 listener stopped", "network", s.Net, "error", err)
			}
		}(s, errCh)
	}

	return srv, nil
}

// Shutdown stops all listeners.
func (s *RFC2136Server) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}

	var err error
	for _, srv := range s.servers {
		err = errors.Join(err, srv.ShutdownContext(ctx))
	}

	return err
}

type rfc2136Handler struct {
	zctl     zone.Controller
	acmeOnly bool
	allow    []netip.Prefix
	maxTTL   int
	lg       *slog.Logger
}

// updateMsgAcceptFunc accepts dynamic updates (rejected by the dns package
// default) with exactly one question (the zone) and any number of update RRs.
func updateMsgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	const qrBit = 1 << 15

	if dh.Bits&qrBit != 0 {
		return dns.MsgIgnore
	}

	opcode := int(dh.Bits>>11) & 0xF
	if opcode != dns.OpcodeUpdate {
		return dns.MsgReject
	}
	if dh.Qdcount != 1 {
		return dns.MsgReject
	}

	return dns.MsgAccept
}

func (h *rfc2136Handler) serve(w dns.ResponseWriter, req *dns.Msg) {
	ctx, span := rfc2136Tracer.Start(context.Background(), "rfc2136.update")
	defer span.End()

	resp := new(dns.Msg)
	resp.SetReply(req)

	span.SetAttributes(
		attribute.String("dns.opcode", dns.OpcodeToString[req.Opcode]),
		attribute.Int("dns.update_rr_count", len(req.Ns)),
	)

	code, err := h.handle(ctx, w, req)
	if err != nil {
		h.lg.ErrorContext(ctx, "RFC2136 update failed", "rcode", dns.RcodeToString[code], "error", err)
	}

	resp.SetRcode(req, code)

	// Sign the response when the request was signed and verified (RFC 2845).
	if tsigRR := req.IsTsig(); tsigRR != nil && w.TsigStatus() == nil {
		resp.SetTsig(tsigRR.Hdr.Name, tsigRR.Algorithm, 300, time.Now().Unix())
	}

	if err := w.WriteMsg(resp); err != nil {
		h.lg.ErrorContext(ctx, "Failed to write RFC2136 response", "error", err)
	}
}

func (h *rfc2136Handler) handle(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) (int, error) {
	if !h.allowed(w.RemoteAddr()) {
		return dns.RcodeRefused, fmt.Errorf("client %s not in allowlist", w.RemoteAddr())
	}

	if req.IsTsig() == nil {
		return dns.RcodeNotAuth, errors.New("missing TSIG signature")
	}
	if err := w.TsigStatus(); err != nil {
		return dns.RcodeNotAuth, fmt.Errorf("TSIG verification failed: %w", err)
	}

	if len(req.Question) != 1 {
		return dns.RcodeFormatError, errors.New("dynamic update must have exactly one question")
	}
	zoneName := req.Question[0].Name

	if _, err := h.zctl.GetZone(ctx, zoneName); err != nil {
		return dns.RcodeNotAuth, fmt.Errorf("zone not managed: %s: %w", zoneName, err)
	}

	for _, rr := range req.Ns {
		if err := h.applyRR(ctx, zoneName, rr); err != nil {
			var reject *rejectError
			if errors.As(err, &reject) {
				return reject.rcode, err
			}
			return dns.RcodeServerFailure, err
		}
	}

	return dns.RcodeSuccess, nil
}

// rejectError marks an update that was refused by policy (as opposed to a
// server-side failure), carrying the rcode to reply with.
type rejectError struct {
	rcode int
	err   error
}

func (e *rejectError) Error() string { return e.err.Error() }
func (e *rejectError) Unwrap() error { return e.err }

func reject(rcode int, format string, args ...any) error {
	return &rejectError{rcode: rcode, err: fmt.Errorf(format, args...)}
}

func (h *rfc2136Handler) applyRR(ctx context.Context, zoneName string, rr dns.RR) error {
	hdr := rr.Header()

	typeName := strings.ToUpper(dns.TypeToString[hdr.Rrtype])
	if !h.allowsRR(hdr) {
		return reject(dns.RcodeRefused, "update for %s %s is not allowed on the ACME listener", hdr.Name, typeName)
	}

	switch hdr.Class {
	case dns.ClassINET:
		return h.addRR(ctx, rr)
	case dns.ClassNONE:
		return h.removeRR(ctx, rr)
	case dns.ClassANY:
		return h.removeRRSet(ctx, zoneName, rr)
	default:
		return reject(dns.RcodeRefused, "unsupported update class %d for %s", hdr.Class, hdr.Name)
	}
}

func (h *rfc2136Handler) addRR(ctx context.Context, rr dns.RR) error {
	hdr := rr.Header()
	typeName := strings.ToUpper(dns.TypeToString[hdr.Rrtype])
	value := rdataValue(rr)

	if h.acmeOnly {
		// Present semantics: replace the placeholder left by a previous cleanup
		// (or append), so that apex and wildcard challenges sharing one
		// _acme-challenge name can coexist.
		return h.zctl.UpdateACMEChallenge(ctx, hdr.Name, value, zone.EmptyPlaceholder)
	}

	ttl := h.effectiveTTL(int(hdr.Ttl))
	_, err := h.zctl.ApplyRecordUpdate(ctx, hdr.Name, typeName, ttl, []string{value}, nil)
	return err
}

func (h *rfc2136Handler) removeRR(ctx context.Context, rr dns.RR) error {
	hdr := rr.Header()
	typeName := strings.ToUpper(dns.TypeToString[hdr.Rrtype])
	value := rdataValue(rr)

	if h.acmeOnly {
		// Cleanup semantics: replace the token with the placeholder in place,
		// keeping the entry (and its TTL inheritance) in the zone file.
		return h.zctl.UpdateACMEChallenge(ctx, hdr.Name, "", value)
	}

	_, err := h.zctl.ApplyRecordUpdate(ctx, hdr.Name, typeName, 0, nil, []string{value})
	return err
}

func (h *rfc2136Handler) removeRRSet(ctx context.Context, zoneName string, rr dns.RR) error {
	hdr := rr.Header()

	if hdr.Rrtype == dns.TypeANY {
		_, err := h.zctl.RemoveRecordName(ctx, hdr.Name)
		return err
	}

	typeName := strings.ToUpper(dns.TypeToString[hdr.Rrtype])
	_, err := h.zctl.DeleteRRSet(ctx, zoneName, hdr.Name, typeName)
	return err
}

// effectiveTTL applies the configured TTL cap to a record TTL.
func (h *rfc2136Handler) effectiveTTL(recordTTL int) int {
	if h.maxTTL > 0 && (recordTTL <= 0 || h.maxTTL < recordTTL) {
		return h.maxTTL
	}
	return recordTTL
}

func (h *rfc2136Handler) allowed(addr net.Addr) bool {
	if len(h.allow) == 0 {
		return true
	}

	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()

	for _, p := range h.allow {
		if p.Contains(ip) {
			return true
		}
	}

	return false
}

// allowsRR reports whether the update record may be applied on this listener.
// A generic listener allows everything; an ACME listener only allows
// _acme-challenge.* TXT records.
func (h *rfc2136Handler) allowsRR(hdr *dns.RR_Header) bool {
	if !h.acmeOnly {
		return true
	}

	if hdr.Rrtype != dns.TypeTXT {
		return false
	}

	return strings.HasPrefix(strings.ToLower(hdr.Name), "_acme-challenge.")
}

// rdataValue returns the logical (unquoted) record value, suitable for the
// zone controller which applies its own formatting/quoting.
func rdataValue(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.TXT:
		return strings.Join(v.Txt, "")
	case *dns.SPF:
		return strings.Join(v.Txt, "")
	default:
		return strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
	}
}
