package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-fuego/fuego"
	"github.com/stretchr/testify/assert"

	"github.com/vooon/zoneomatic/internal/zone"
)

type fakeHTPasswd struct {
	user string
	pass string
}

func (f fakeHTPasswd) Authenticate(user, password string) (ok, present bool) {
	if user != f.user {
		return false, false
	}
	return password == f.pass, true
}

type fakeZoneController struct {
	lastDomain string
	lastAddrs  []netip.Addr
	ddnsErr    error
}

func (f *fakeZoneController) UpdateDDNSAddress(_ context.Context, domain string, addrs []netip.Addr) error {
	if f.ddnsErr != nil {
		return f.ddnsErr
	}
	f.lastDomain = domain
	f.lastAddrs = addrs
	return nil
}

func (f *fakeZoneController) UpdateACMEChallenge(_ context.Context, _ string, _, _ string) error {
	return nil
}

func (f *fakeZoneController) ZMUpdateRecord(_ context.Context, _ string, _ string, _ []string) (changed bool, err error) {
	return false, nil
}

func newTestServer(htp fakeHTPasswd, zctl *fakeZoneController) *fuego.Server {
	srv := fuego.NewServer(
		fuego.WithSecurity(
			map[string]*openapi3.SecuritySchemeRef{
				"basicAuth": {
					Value: openapi3.NewSecurityScheme().
						WithType("http").
						WithScheme("basic"),
				},
				"apiUserAuth": {
					Value: openapi3.NewSecurityScheme().
						WithType("apiKey").
						WithIn("header").
						WithName("X-Api-User"),
				},
				"apiKeyAuth": {
					Value: openapi3.NewSecurityScheme().
						WithType("apiKey").
						WithIn("header").
						WithName("X-Api-Key"),
				},
			},
		),
	)
	RegisterEndpoints(srv, htp, zctl)
	return srv
}

func TestNICUpdate(t *testing.T) {
	testCases := []struct {
		name         string
		url          string
		withAuth     bool
		wantCode     int
		wantBody     string
		wantDomain   string
		wantHasAddrs []netip.Addr
	}{
		{
			name:     "missing hostname",
			url:      "/nic/update?myip=1.2.3.4",
			withAuth: true,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid ip",
			url:      "/nic/update?hostname=test.example.com&myip=not-an-ip",
			withAuth: true,
			wantCode: http.StatusBadRequest,
		},
		{
			name:       "valid request",
			url:        "/nic/update?hostname=test.example.com&myip=1.2.3.4&myipv6=2001:db8::1",
			withAuth:   true,
			wantCode:   http.StatusOK,
			wantBody:   "OK",
			wantDomain: "test.example.com",
			wantHasAddrs: []netip.Addr{
				netip.MustParseAddr("1.2.3.4"),
				netip.MustParseAddr("2001:db8::1"),
			},
		},
		{
			name:     "unauthorized",
			url:      "/nic/update?hostname=test.example.com&myip=1.2.3.4",
			withAuth: false,
			wantCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			htp := fakeHTPasswd{user: "u", pass: "p"}
			zctl := &fakeZoneController{}
			srv := newTestServer(htp, zctl)

			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			if tc.withAuth {
				req.SetBasicAuth("u", "p")
			}
			rec := httptest.NewRecorder()
			srv.Mux.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantCode, rec.Code)
			if tc.wantBody != "" {
				assert.Equal(t, tc.wantBody, rec.Body.String())
			}
			if tc.wantDomain != "" {
				assert.Equal(t, tc.wantDomain, zctl.lastDomain)
			}
			for _, want := range tc.wantHasAddrs {
				assert.True(t, slices.Contains(zctl.lastAddrs, want))
			}
		})
	}
}

func TestNICUpdate_ZoneNotFoundMappedTo404(t *testing.T) {
	htp := fakeHTPasswd{user: "u", pass: "p"}
	zctl := &fakeZoneController{
		ddnsErr: fmt.Errorf("wrapped: %w", zone.ErrZoneNotFound),
	}
	srv := newTestServer(htp, zctl)

	req := httptest.NewRequest(http.MethodGet, "/nic/update?hostname=test.example.com&myip=1.2.3.4", nil)
	req.SetBasicAuth("u", "p")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}
