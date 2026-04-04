package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
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

type fakeRRSetReplaceCall struct {
	zoneName string
	name     string
	typ      string
	ttl      int
	values   []string
}

type fakeRRSetDeleteCall struct {
	zoneName string
	name     string
	typ      string
}

type fakeZoneController struct {
	lastDomain string
	lastAddrs  []netip.Addr
	ddnsErr    error
	zones      map[string]zone.ZoneSnapshot
	getZoneErr error
	replaceErr error
	deleteErr  error
	replaced   []fakeRRSetReplaceCall
	deleted    []fakeRRSetDeleteCall
}

func (f *fakeZoneController) ListZones(_ context.Context) ([]zone.ZoneSnapshot, error) {
	ret := make([]zone.ZoneSnapshot, 0, len(f.zones))
	for _, zoneData := range f.zones {
		ret = append(ret, zoneData)
	}

	return ret, nil
}

func (f *fakeZoneController) GetZone(_ context.Context, zoneName string) (zone.ZoneSnapshot, error) {
	if f.getZoneErr != nil {
		return zone.ZoneSnapshot{}, f.getZoneErr
	}

	if zoneData, ok := f.zones[zoneName]; ok {
		return zoneData, nil
	}

	return zone.ZoneSnapshot{}, fmt.Errorf("wrapped: %w", zone.ErrZoneNotFound)
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

func (f *fakeZoneController) ReplaceRRSet(_ context.Context, zoneName, name, typ string, ttl int, values []string) (changed bool, err error) {
	if f.replaceErr != nil {
		return false, f.replaceErr
	}

	f.replaced = append(f.replaced, fakeRRSetReplaceCall{
		zoneName: zoneName,
		name:     name,
		typ:      typ,
		ttl:      ttl,
		values:   append([]string(nil), values...),
	})

	return true, nil
}

func (f *fakeZoneController) DeleteRRSet(_ context.Context, zoneName, name, typ string) (changed bool, err error) {
	if f.deleteErr != nil {
		return false, f.deleteErr
	}

	f.deleted = append(f.deleted, fakeRRSetDeleteCall{
		zoneName: zoneName,
		name:     name,
		typ:      typ,
	})

	return true, nil
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
				"pdnsApiKeyAuth": {
					Value: openapi3.NewSecurityScheme().
						WithType("apiKey").
						WithIn("header").
						WithName("X-API-Key"),
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

func TestPDNSServerDiscovery(t *testing.T) {
	htp := fakeHTPasswd{user: "u", pass: "p"}
	zctl := &fakeZoneController{}
	srv := newTestServer(htp, zctl)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers/localhost", nil)
	req.Header.Set("X-API-Key", testPDNSAPIKey("u", "p"))
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "localhost", body["id"])
	assert.Equal(t, "authoritative", body["daemon_type"])
}

func TestPDNSZoneGet(t *testing.T) {
	htp := fakeHTPasswd{user: "u", pass: "p"}
	zctl := &fakeZoneController{
		zones: map[string]zone.ZoneSnapshot{
			"example.com.": {
				ID:     "example.com.",
				Name:   "example.com.",
				Serial: 123,
				RRsets: []zone.RRSet{{
					Name:    "www.example.com.",
					Type:    "A",
					TTL:     60,
					Records: []string{"1.2.3.4"},
				}},
			},
		},
	}
	srv := newTestServer(htp, zctl)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers/localhost/zones/example.com.?rrsets=false", nil)
	req.Header.Set("X-API-Key", testPDNSAPIKey("u", "p"))
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "example.com.", body["id"])
	_, hasRRsets := body["rrsets"]
	assert.False(t, hasRRsets)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/servers/localhost/zones/example.com.", nil)
	req.Header.Set("X-API-Key", testPDNSAPIKey("u", "p"))
	rec = httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	rrsets, hasRRsets := body["rrsets"].([]any)
	assert.True(t, hasRRsets)
	assert.Len(t, rrsets, 1)
}

func TestPDNSPatchZoneReplaceAndDelete(t *testing.T) {
	htp := fakeHTPasswd{user: "u", pass: "p"}
	zctl := &fakeZoneController{}
	srv := newTestServer(htp, zctl)

	patchBody := `{"rrsets":[{"name":"www.example.com.","type":"A","ttl":60,"changetype":"REPLACE","records":[{"content":"1.2.3.4","disabled":false}]},{"name":"old.example.com.","type":"TXT","changetype":"DELETE","records":[]}]}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/servers/localhost/zones/example.com.", strings.NewReader(patchBody))
	req.Header.Set("X-API-Key", testPDNSAPIKey("u", "p"))
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Len(t, zctl.replaced, 1)
	assert.Equal(t, fakeRRSetReplaceCall{
		zoneName: "example.com.",
		name:     "www.example.com.",
		typ:      "A",
		ttl:      60,
		values:   []string{"1.2.3.4"},
	}, zctl.replaced[0])
	assert.Len(t, zctl.deleted, 1)
	assert.Equal(t, fakeRRSetDeleteCall{
		zoneName: "example.com.",
		name:     "old.example.com.",
		typ:      "TXT",
	}, zctl.deleted[0])
}

func TestPDNSUnauthorized(t *testing.T) {
	htp := fakeHTPasswd{user: "u", pass: "p"}
	zctl := &fakeZoneController{}
	srv := newTestServer(htp, zctl)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers/localhost", nil)
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.JSONEq(t, `{"error":"unauthorized"}`, rec.Body.String())
}

func TestPDNSUnsupportedZoneOperation(t *testing.T) {
	htp := fakeHTPasswd{user: "u", pass: "p"}
	zctl := &fakeZoneController{}
	srv := newTestServer(htp, zctl)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/servers/localhost/zones", nil)
	req.Header.Set("X-API-Key", testPDNSAPIKey("u", "p"))
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
	assert.JSONEq(t, `{"error":"create zone is not implemented"}`, rec.Body.String())
}

func testPDNSAPIKey(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}
