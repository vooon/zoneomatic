package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vooon/zoneomatic/internal/zone"
)

var testZones = map[string]zone.ZoneSnapshot{
	"example.com.":     {ID: "example.com.", Name: "example.com."},
	"sub.example.com.": {ID: "sub.example.com.", Name: "sub.example.com."},
}

func newFakeCtrl() *fakeZoneController {
	return &fakeZoneController{zones: testZones}
}

// runUpdate routes a crafted update message through the handler and returns
// the response rcode. The message is marked as TSIG-signed; the fake response
// writer reports successful TSIG verification.
func runUpdate(t *testing.T, h *rfc2136Handler, remote net.Addr, msg *dns.Msg) int {
	t.Helper()

	msg.SetTsig("test-key.example.com.", dns.HmacSHA256, 300, time.Now().Unix())

	w := &fakeResponseWriter{remote: remote}
	h.serve(w, msg)
	require.NotNil(t, w.msg, "handler did not write a response")
	return w.msg.Rcode
}

type fakeResponseWriter struct {
	remote  net.Addr
	msg     *dns.Msg
	tsigErr error
}

func (f *fakeResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 15353}
}
func (f *fakeResponseWriter) RemoteAddr() net.Addr { return f.remote }
func (f *fakeResponseWriter) WriteMsg(m *dns.Msg) error {
	f.msg = m.Copy()
	return nil
}
func (f *fakeResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeResponseWriter) Close() error                { return nil }
func (f *fakeResponseWriter) TsigStatus() error           { return f.tsigErr }
func (f *fakeResponseWriter) TsigTimersOnly(bool)         {}
func (f *fakeResponseWriter) Hijack()                     {}

func mustUpdateMsg(t *testing.T, zoneName string, rr dns.RR) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate(zoneName)
	m.Insert([]dns.RR{rr})
	return m
}

func acmeTXT(name, value string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{value},
	}
}

func TestRFC2136_ACME_PresentAndCleanup(t *testing.T) {
	zctl := newFakeCtrl()
	h := &rfc2136Handler{zctl: zctl, acmeOnly: true, lg: discardLogger()}

	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 12345}

	// present
	code := runUpdate(t, h, remote, mustUpdateMsg(t, "example.com.", acmeTXT("_acme-challenge.example.com.", "token-1")))
	assert.Equal(t, dns.RcodeSuccess, code)
	require.Len(t, zctl.acmeCalls, 1)
	assert.Equal(t, "_acme-challenge.example.com.", zctl.acmeCalls[0].domain)
	assert.Equal(t, "token-1", zctl.acmeCalls[0].newToken)
	assert.Equal(t, zone.EmptyPlaceholder, zctl.acmeCalls[0].oldToken)

	// cleanup
	m := new(dns.Msg)
	m.SetUpdate("example.com.")
	rr := acmeTXT("_acme-challenge.example.com.", "token-1")
	m.Remove([]dns.RR{rr})

	code = runUpdate(t, h, remote, m)
	assert.Equal(t, dns.RcodeSuccess, code)
	require.Len(t, zctl.acmeCalls, 2)
	assert.Equal(t, "token-1", zctl.acmeCalls[1].oldToken)
	assert.Empty(t, zctl.acmeCalls[1].newToken)
}

func TestRFC2136_ACME_RejectsForeignName(t *testing.T) {
	zctl := newFakeCtrl()
	h := &rfc2136Handler{zctl: zctl, acmeOnly: true, lg: discardLogger()}

	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 12345}
	code := runUpdate(t, h, remote, mustUpdateMsg(t, "example.com.", acmeTXT("www.example.com.", "token-1")))
	assert.Equal(t, dns.RcodeRefused, code)
	assert.Empty(t, zctl.acmeCalls)
}

func TestRFC2136_ACME_RejectsNonTXT(t *testing.T) {
	zctl := newFakeCtrl()
	h := &rfc2136Handler{zctl: zctl, acmeOnly: true, lg: discardLogger()}

	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 12345}
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(192, 0, 2, 1),
	}
	code := runUpdate(t, h, remote, mustUpdateMsg(t, "example.com.", rr))
	assert.Equal(t, dns.RcodeRefused, code)
}

func TestRFC2136_UnknownZone(t *testing.T) {
	zctl := newFakeCtrl()
	h := &rfc2136Handler{zctl: zctl, lg: discardLogger()}

	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 12345}
	code := runUpdate(t, h, remote, mustUpdateMsg(t, "other.example.org.", acmeTXT("_acme-challenge.other.example.org.", "t")))
	assert.Equal(t, dns.RcodeNotAuth, code)
}

func TestRFC2136_MissingTsig(t *testing.T) {
	zctl := newFakeCtrl()
	h := &rfc2136Handler{zctl: zctl, lg: discardLogger()}

	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 12345}
	w := &fakeResponseWriter{remote: remote}

	// Deliberately unsigned message.
	h.serve(w, mustUpdateMsg(t, "example.com.", acmeTXT("_acme-challenge.example.com.", "t")))

	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeNotAuth, w.msg.Rcode)
	assert.Empty(t, zctl.acmeCalls)
}

func TestRFC2136_BadTsig(t *testing.T) {
	zctl := newFakeCtrl()
	h := &rfc2136Handler{zctl: zctl, lg: discardLogger()}

	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 12345}
	w := &fakeResponseWriter{remote: remote, tsigErr: dns.ErrSig}

	m := mustUpdateMsg(t, "example.com.", acmeTXT("_acme-challenge.example.com.", "t"))
	// Pretend a TSIG was present.
	m.SetTsig("k.example.com.", dns.HmacSHA256, 300, 0)

	h.serve(w, m)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeNotAuth, w.msg.Rcode)
}

func TestRFC2136_Allowlist(t *testing.T) {
	zctl := newFakeCtrl()
	h := &rfc2136Handler{
		zctl:  zctl,
		allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		lg:    discardLogger(),
	}

	denied := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 5), Port: 12345}
	code := runUpdate(t, h, denied, mustUpdateMsg(t, "example.com.", acmeTXT("_acme-challenge.example.com.", "t")))
	assert.Equal(t, dns.RcodeRefused, code)

	allowed := &net.TCPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 12345}
	code = runUpdate(t, h, allowed, mustUpdateMsg(t, "example.com.", acmeTXT("_acme-challenge.example.com.", "t")))
	assert.Equal(t, dns.RcodeSuccess, code)
}

func TestRFC2136_UpdateListener_GenericOps(t *testing.T) {
	zctl := newFakeCtrl()
	h := &rfc2136Handler{zctl: zctl, maxTTL: 30, lg: discardLogger()}

	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 12345}

	// insert A
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(192, 0, 2, 10),
	}
	code := runUpdate(t, h, remote, mustUpdateMsg(t, "example.com.", rr))
	require.Equal(t, dns.RcodeSuccess, code)
	require.Len(t, zctl.applyCalls, 1)
	assert.Equal(t, "www.example.com.", zctl.applyCalls[0].domain)
	assert.Equal(t, "A", zctl.applyCalls[0].typ)
	assert.Equal(t, 30, zctl.applyCalls[0].ttl) // capped by maxTTL
	assert.Equal(t, []string{"192.0.2.10"}, zctl.applyCalls[0].add)

	// remove exact value
	m := new(dns.Msg)
	m.SetUpdate("example.com.")
	m.Remove([]dns.RR{rr})
	code = runUpdate(t, h, remote, m)
	require.Equal(t, dns.RcodeSuccess, code)
	require.Len(t, zctl.applyCalls, 2)
	assert.Equal(t, []string{"192.0.2.10"}, zctl.applyCalls[1].remove)

	// delete RRset (ClassANY + type)
	m = new(dns.Msg)
	m.SetUpdate("example.com.")
	m.RemoveRRset([]dns.RR{rr})
	code = runUpdate(t, h, remote, m)
	require.Equal(t, dns.RcodeSuccess, code)
	require.Len(t, zctl.deleted, 1)
	assert.Equal(t, "example.com.", zctl.deleted[0].zoneName)
	assert.Equal(t, "www.example.com.", zctl.deleted[0].name)
	assert.Equal(t, "A", zctl.deleted[0].typ)

	// delete all RRsets at name (ClassANY + ANY)
	m = new(dns.Msg)
	m.SetUpdate("example.com.")
	m.RemoveName([]dns.RR{rr})
	code = runUpdate(t, h, remote, m)
	require.Equal(t, dns.RcodeSuccess, code)
	require.Len(t, zctl.removeName, 1)
	assert.Equal(t, "www.example.com.", zctl.removeName[0].domain)
}

func TestRFC2136_UpdateListener_KeepsRecordTTL(t *testing.T) {
	zctl := newFakeCtrl()
	h := &rfc2136Handler{zctl: zctl, maxTTL: 30, lg: discardLogger()}

	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 12345}
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 20},
		A:   net.IPv4(192, 0, 2, 10),
	}
	runUpdate(t, h, remote, mustUpdateMsg(t, "example.com.", rr))
	require.Len(t, zctl.applyCalls, 1)
	assert.Equal(t, 20, zctl.applyCalls[0].ttl)
}

func TestRFC2136_StartDisabled(t *testing.T) {
	srv, err := StartRFC2136(RFC2136Config{Listen: ""}, newFakeCtrl())
	require.NoError(t, err)
	assert.Nil(t, srv)
}

func TestRFC2136_StartRequiresTsigFile(t *testing.T) {
	_, err := StartRFC2136(RFC2136Config{Listen: "127.0.0.1:0", TSIGFile: "/nonexistent/file"}, newFakeCtrl())
	require.Error(t, err)
}

func TestRFC2136_StartBindFailure(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/keys.conf"
	require.NoError(t, writeKeyFile(keyPath, "k.example.com", "hmac-sha256", "32pD8A6DfOgRA78uPNzvC4SFhqwEaKySaVEQfQWHZIo="))

	// Occupy a UDP port and try to bind the listener to it.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close() // nolint:errcheck

	_, err = StartRFC2136(RFC2136Config{Listen: conn.LocalAddr().String(), TSIGFile: keyPath}, newFakeCtrl())
	require.Error(t, err)
}

func TestUpdateMsgAcceptFunc(t *testing.T) {
	update := dns.Header{Bits: uint16(dns.OpcodeUpdate) << 11, Qdcount: 1}
	assert.Equal(t, dns.MsgAccept, updateMsgAcceptFunc(update))

	query := dns.Header{Bits: 0, Qdcount: 1}
	assert.Equal(t, dns.MsgReject, updateMsgAcceptFunc(query))

	noQuestion := dns.Header{Bits: uint16(dns.OpcodeUpdate) << 11, Qdcount: 0}
	assert.Equal(t, dns.MsgReject, updateMsgAcceptFunc(noQuestion))
}

func TestRFC2136_ServerPresentCleanup(t *testing.T) {
	// End-to-end-ish: start both listeners and exercise a signed update over
	// UDP through the real dns.Server with a TSIG provider.
	zctl := newFakeCtrl()

	dir := t.TempDir()
	keyPath := dir + "/keys.conf"
	secret := "32pD8A6DfOgRA78uPNzvC4SFhqwEaKySaVEQfQWHZIo="
	require.NoError(t, writeKeyFile(keyPath, "acme.example.com", "hmac-sha256", secret))

	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.LocalAddr().String()
	ln.Close() // nolint:errcheck

	srv, err := StartRFC2136(RFC2136Config{
		Listen:   addr,
		TSIGFile: keyPath,
		ACMEOnly: true,
	}, zctl)
	require.NoError(t, err)
	require.NotNil(t, srv)
	defer func() { _ = srv.Shutdown(context.Background()) }()

	secrets := map[string]string{"acme.example.com.": secret}
	client := &dns.Client{
		Net:        "udp",
		TsigSecret: secrets,
	}

	m := new(dns.Msg)
	m.SetUpdate("example.com.")
	m.Insert([]dns.RR{acmeTXT("_acme-challenge.example.com.", "tok")})
	m.SetTsig("acme.example.com.", dns.HmacSHA256, 300, time.Now().Unix())

	resp, _, err := client.Exchange(m, addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "rcode=%s", dns.RcodeToString[resp.Rcode])

	require.Eventually(t, func() bool {
		return len(zctl.acmeCalls) == 1
	}, 2*time.Second, 10*time.Millisecond, "update was not applied")
	assert.Equal(t, "tok", zctl.acmeCalls[0].newToken)
}

func writeKeyFile(path, name, algo, secret string) error {
	content := "key \"" + name + "\" {\n\talgorithm " + algo + ";\n\tsecret \"" + secret + "\";\n};\n"
	return os.WriteFile(path, []byte(content), 0600)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
