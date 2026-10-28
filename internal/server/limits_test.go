package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaxBodyMiddleware(t *testing.T) {
	h := maxBodyMiddleware(16)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Declared length over the limit: refused before the handler runs.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 17))))
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)

	// Undeclared length (chunked): the handler's read fails.
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 17)))
	req.ContentLength = -1
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("small")))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestClientLimiter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newClientLimiter(1, 2)
	l.now = func() time.Time { return now }

	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	assert.True(t, l.allow(a))
	assert.True(t, l.allow(a))
	assert.False(t, l.allow(a), "burst of 2 is spent")
	assert.True(t, l.allow(b), "other clients are not affected")

	now = now.Add(time.Second)
	assert.True(t, l.allow(a), "one token per second")
	assert.False(t, l.allow(a))

	// Idle clients are forgotten.
	now = now.Add(l.idleTTL + time.Second)
	assert.True(t, l.allow(b))
	assert.Len(t, l.clients, 1)

	// The middleware keys on the remote address; the third request in a
	// burst of two is refused.
	h := l.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	var rec *httptest.ResponseRecorder
	for range 3 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "[::ffff:192.0.2.9]:1234"
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))
}

func TestAcceptProxy_TrustedSenderOnly(t *testing.T) {
	cli := &Cli{
		Listen:             "127.0.0.1:0",
		AcceptProxy:        true,
		ProxyTrusted:       []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		ProxyHeaderTimeout: time.Second,
	}
	srv, listener, err := NewServer(cli)
	require.NoError(t, err)
	srv.OpenAPI.Config.JSONFilePath = filepath.Join(t.TempDir(), "openapi.json")
	RegisterEndpoints(srv, fakeHTPasswd{}, &fakeZoneController{})
	go srv.Run() // nolint:errcheck
	t.Cleanup(func() { _ = listener.Close() })

	get := func(preamble string) (string, error) {
		conn, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		defer conn.Close() // nolint:errcheck
		require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
		_, err = io.WriteString(conn, preamble+"GET /myip HTTP/1.0\r\nHost: x\r\n\r\n")
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close() // nolint:errcheck
		body, _ := io.ReadAll(resp.Body)
		return strings.TrimSpace(string(body)), nil
	}

	// A trusted sender's header is used: the service sees the client it names.
	body, err := get("PROXY TCP4 203.0.113.5 127.0.0.1 40000 80\r\n")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.5", body)

	// A trusted sender must send a header; a bare request is not served.
	_, err = get("")
	assert.Error(t, err)

	// Untrusted senders are dropped: nobody else can forge a client address.
	cli.ProxyTrusted = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	srv2, listener2, err := NewServer(cli)
	require.NoError(t, err)
	srv2.OpenAPI.Config.JSONFilePath = filepath.Join(t.TempDir(), "openapi.json")
	RegisterEndpoints(srv2, fakeHTPasswd{}, &fakeZoneController{})
	go srv2.Run() // nolint:errcheck
	t.Cleanup(func() { _ = listener2.Close() })
	listener = listener2
	_, err = get("PROXY TCP4 203.0.113.5 127.0.0.1 40000 80\r\n")
	assert.Error(t, err)
}
