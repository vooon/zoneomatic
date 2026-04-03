package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-fuego/fuego"
	"github.com/go-fuego/fuego/option"

	"github.com/vooon/zoneomatic/internal/htpasswd"
	"github.com/vooon/zoneomatic/internal/zone"
)

const pdnsServerID = "localhost"

type pdnsErrorResponse struct {
	Error  string   `json:"error"`
	Errors []string `json:"errors,omitempty"`
}

type pdnsServer struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	DaemonType string `json:"daemon_type"`
	Version    string `json:"version"`
	URL        string `json:"url"`
	ConfigURL  string `json:"config_url"`
	ZonesURL   string `json:"zones_url"`
}

type pdnsRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type pdnsRRSet struct {
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	TTL        int          `json:"ttl,omitempty"`
	ChangeType string       `json:"changetype,omitempty"`
	Records    []pdnsRecord `json:"records"`
	Comments   []any        `json:"comments,omitempty"`
}

type pdnsZone struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Type           string      `json:"type"`
	URL            string      `json:"url"`
	Kind           string      `json:"kind"`
	RRsets         []pdnsRRSet `json:"rrsets,omitempty"`
	Serial         uint32      `json:"serial"`
	NotifiedSerial uint32      `json:"notified_serial"`
	EditedSerial   uint32      `json:"edited_serial"`
	Masters        []string    `json:"masters"`
	DNSSEC         bool        `json:"dnssec"`
	Account        string      `json:"account"`
	Nameservers    []string    `json:"nameservers,omitempty"`
	SOAEditAPI     string      `json:"soa_edit_api,omitempty"`
	APIRectify     bool        `json:"api_rectify"`
	Zone           string      `json:"zone,omitempty"`
	Catalog        string      `json:"catalog,omitempty"`
	LastCheck      uint32      `json:"last_check"`
	Presigned      bool        `json:"presigned"`
	NSEC3Narrow    bool        `json:"nsec3narrow"`
	NSEC3Param     string      `json:"nsec3param"`
	MasterTSIGKeys []string    `json:"master_tsig_key_ids"`
	SlaveTSIGKeys  []string    `json:"slave_tsig_key_ids"`
}

type pdnsPatchZoneRequest struct {
	RRsets []pdnsRRSet `json:"rrsets"`
}

func registerPDNSEndpoints(srv *fuego.Server, htp htpasswd.HTPasswd, zctl zone.Controller) {
	pdnsAuth := newPDNSAPIKeyMiddleware(htp)
	pdnsSecurity := option.Security(openapi3.SecurityRequirement{
		"pdnsApiKeyAuth": []string{},
	})

	fuego.GetStd(srv, "/api/v1/servers",
		func(w http.ResponseWriter, r *http.Request) {
			server := pdnsServerInfo()
			sendPDNSJSON(w, http.StatusOK, []pdnsServer{server})
		},
		option.Summary("pdns list servers"),
		option.Description("List the forged PowerDNS-compatible server instance"),
		option.Middleware(pdnsAuth),
		pdnsSecurity,
	)

	fuego.GetStd(srv, "/api/v1/servers/{server_id}",
		func(w http.ResponseWriter, r *http.Request) {
			if !requirePDNSServerID(w, r) {
				return
			}

			sendPDNSJSON(w, http.StatusOK, pdnsServerInfo())
		},
		option.Summary("pdns get server"),
		option.Description("Return the forged PowerDNS-compatible server instance"),
		option.Middleware(pdnsAuth),
		pdnsSecurity,
	)

	fuego.GetStd(srv, "/api/v1/servers/{server_id}/zones",
		func(w http.ResponseWriter, r *http.Request) {
			if !requirePDNSServerID(w, r) {
				return
			}

			zones, err := zctl.ListZones(r.Context())
			if err != nil {
				sendPDNSError(w, http.StatusInternalServerError, err.Error())
				return
			}

			zoneFilter := r.URL.Query().Get("zone")
			result := make([]pdnsZone, 0, len(zones))
			for _, zoneData := range zones {
				if zoneFilter != "" && zoneData.Name != dnsFQDN(zoneFilter) {
					continue
				}

				result = append(result, zoneSnapshotToPDNSZone(zoneData, false))
			}

			sendPDNSJSON(w, http.StatusOK, result)
		},
		option.Summary("pdns list zones"),
		option.Description("List managed zones in a PowerDNS-compatible format"),
		option.Middleware(pdnsAuth),
		pdnsSecurity,
	)

	fuego.GetStd(srv, "/api/v1/servers/{server_id}/zones/{zone_id}",
		func(w http.ResponseWriter, r *http.Request) {
			if !requirePDNSServerID(w, r) {
				return
			}

			zoneData, err := zctl.GetZone(r.Context(), r.PathValue("zone_id"))
			if err != nil {
				sendPDNSZoneError(w, err)
				return
			}

			includeRRsets := !strings.EqualFold(r.URL.Query().Get("rrsets"), "false")
			rrsetName := r.URL.Query().Get("rrset_name")
			rrsetType := r.URL.Query().Get("rrset_type")
			if rrsetType != "" && rrsetName == "" {
				sendPDNSError(w, http.StatusUnprocessableEntity, "rrset_type requires rrset_name")
				return
			}

			zoneResp := zoneSnapshotToPDNSZone(zoneData, includeRRsets)
			if includeRRsets && rrsetName != "" {
				zoneResp.RRsets = filterPDNSRRsets(zoneResp.RRsets, rrsetName, rrsetType)
			}

			sendPDNSJSON(w, http.StatusOK, zoneResp)
		},
		option.Summary("pdns get zone"),
		option.Description("Return a managed zone in PowerDNS-compatible format"),
		option.Middleware(pdnsAuth),
		pdnsSecurity,
	)

	fuego.PatchStd(srv, "/api/v1/servers/{server_id}/zones/{zone_id}",
		func(w http.ResponseWriter, r *http.Request) {
			if !requirePDNSServerID(w, r) {
				return
			}

			defer r.Body.Close() // nolint:errcheck

			var req pdnsPatchZoneRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				sendPDNSError(w, http.StatusBadRequest, "invalid json body", err.Error())
				return
			}

			zoneName := r.PathValue("zone_id")
			for _, rrset := range req.RRsets {
				if rrset.Name == "" || rrset.Type == "" {
					sendPDNSError(w, http.StatusUnprocessableEntity, "rrset name and type are required")
					return
				}

				switch strings.ToUpper(strings.TrimSpace(rrset.ChangeType)) {
				case "DELETE":
					if _, err := zctl.DeleteRRSet(r.Context(), zoneName, rrset.Name, rrset.Type); err != nil {
						sendPDNSZoneError(w, err)
						return
					}
				case "REPLACE":
					if len(rrset.Records) == 0 {
						if _, err := zctl.DeleteRRSet(r.Context(), zoneName, rrset.Name, rrset.Type); err != nil {
							sendPDNSZoneError(w, err)
							return
						}

						continue
					}

					if rrset.TTL <= 0 {
						sendPDNSError(w, http.StatusUnprocessableEntity, "ttl must be greater than zero for REPLACE")
						return
					}

					values := make([]string, 0, len(rrset.Records))
					for _, record := range rrset.Records {
						if record.Disabled {
							sendPDNSError(w, http.StatusNotImplemented, "disabled records are not supported")
							return
						}

						values = append(values, record.Content)
					}

					if _, err := zctl.ReplaceRRSet(r.Context(), zoneName, rrset.Name, rrset.Type, rrset.TTL, values); err != nil {
						sendPDNSZoneError(w, err)
						return
					}
				default:
					sendPDNSError(w, http.StatusNotImplemented, "unsupported changetype: "+rrset.ChangeType)
					return
				}
			}

			w.WriteHeader(http.StatusNoContent)
		},
		option.Summary("pdns patch zone"),
		option.Description("Replace or delete managed RRSets in PowerDNS-compatible format"),
		option.Middleware(pdnsAuth),
		pdnsSecurity,
	)

	registerPDNSUnsupportedZoneRoute(srv, pdnsAuth, "/api/v1/servers/{server_id}/zones", http.MethodPost, "create zone")
	registerPDNSUnsupportedZoneRoute(srv, pdnsAuth, "/api/v1/servers/{server_id}/zones/{zone_id}", http.MethodPut, "update zone")
	registerPDNSUnsupportedZoneRoute(srv, pdnsAuth, "/api/v1/servers/{server_id}/zones/{zone_id}", http.MethodDelete, "delete zone")
	registerPDNSUnsupportedZoneRoute(srv, pdnsAuth, "/api/v1/servers/{server_id}/zones/{zone_id}/notify", http.MethodPut, "notify zone")
	registerPDNSUnsupportedZoneRoute(srv, pdnsAuth, "/api/v1/servers/{server_id}/zones/{zone_id}/rectify", http.MethodPut, "rectify zone")
}

func registerPDNSUnsupportedZoneRoute(srv *fuego.Server, authMw func(http.Handler) http.Handler, path, method, operation string) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if !requirePDNSServerID(w, r) {
			return
		}

		slog.WarnContext(r.Context(), "Unsupported PDNS operation", "operation", operation, "path", r.URL.Path)
		sendPDNSError(w, http.StatusNotImplemented, operation+" is not implemented")
	}

	switch method {
	case http.MethodPost:
		fuego.PostStd(srv, path, handler, option.Middleware(authMw), option.Security(openapi3.SecurityRequirement{"pdnsApiKeyAuth": []string{}}))
	case http.MethodPut:
		fuego.PutStd(srv, path, handler, option.Middleware(authMw), option.Security(openapi3.SecurityRequirement{"pdnsApiKeyAuth": []string{}}))
	case http.MethodDelete:
		fuego.DeleteStd(srv, path, handler, option.Middleware(authMw), option.Security(openapi3.SecurityRequirement{"pdnsApiKeyAuth": []string{}}))
	}
}

func pdnsServerInfo() pdnsServer {
	return pdnsServer{
		Type:       "Server",
		ID:         pdnsServerID,
		DaemonType: "authoritative",
		Version:    "zoneomatic",
		URL:        "/api/v1/servers/localhost",
		ConfigURL:  "/api/v1/servers/localhost/config",
		ZonesURL:   "/api/v1/servers/localhost/zones",
	}
}

func zoneSnapshotToPDNSZone(zoneData zone.ZoneSnapshot, includeRRsets bool) pdnsZone {
	resp := pdnsZone{
		ID:             zoneData.ID,
		Name:           zoneData.Name,
		Type:           "Zone",
		URL:            "/api/v1/servers/localhost/zones/" + zoneData.ID,
		Kind:           "Native",
		Serial:         zoneData.Serial,
		EditedSerial:   zoneData.Serial,
		NotifiedSerial: 0,
		Masters:        []string{},
		DNSSEC:         false,
		Account:        "",
		Nameservers:    zoneData.Nameservers,
		SOAEditAPI:     "",
		APIRectify:     false,
		LastCheck:      0,
		Presigned:      false,
		NSEC3Narrow:    false,
		NSEC3Param:     "",
		MasterTSIGKeys: []string{},
		SlaveTSIGKeys:  []string{},
	}

	if includeRRsets {
		resp.RRsets = make([]pdnsRRSet, 0, len(zoneData.RRsets))
		for _, rrset := range zoneData.RRsets {
			records := make([]pdnsRecord, 0, len(rrset.Records))
			for _, record := range rrset.Records {
				records = append(records, pdnsRecord{Content: record, Disabled: false})
			}

			resp.RRsets = append(resp.RRsets, pdnsRRSet{
				Name:    rrset.Name,
				Type:    rrset.Type,
				TTL:     rrset.TTL,
				Records: records,
			})
		}
	}

	return resp
}

func filterPDNSRRsets(rrsets []pdnsRRSet, rrsetName, rrsetType string) []pdnsRRSet {
	rrsetName = dnsFQDN(rrsetName)
	rrsetType = strings.ToUpper(strings.TrimSpace(rrsetType))

	filtered := make([]pdnsRRSet, 0, len(rrsets))
	for _, rrset := range rrsets {
		if rrset.Name != rrsetName {
			continue
		}
		if rrsetType != "" && rrset.Type != rrsetType {
			continue
		}

		filtered = append(filtered, rrset)
	}

	return filtered
}

func requirePDNSServerID(w http.ResponseWriter, r *http.Request) bool {
	if r.PathValue("server_id") == pdnsServerID {
		return true
	}

	sendPDNSError(w, http.StatusNotFound, "server not found")
	return false
}

func sendPDNSZoneError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, zone.ErrZoneNotFound):
		sendPDNSError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, zone.ErrRecordNotFound):
		sendPDNSError(w, http.StatusNotFound, err.Error())
	default:
		sendPDNSError(w, http.StatusUnprocessableEntity, err.Error())
	}
}

func sendPDNSError(w http.ResponseWriter, status int, msg string, errs ...string) {
	sendPDNSJSON(w, status, pdnsErrorResponse{Error: msg, Errors: errs})
}

func sendPDNSJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil || status == http.StatusNoContent {
		return
	}

	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("Failed to encode PDNS response", "error", err)
	}
}

func dnsFQDN(name string) string {
	if name == "" {
		return ""
	}

	return strings.TrimSpace(strings.TrimSuffix(name, ".")) + "."
}

func newPDNSAPIKeyMiddleware(ht htpasswd.HTPasswd) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, password, ok := r.BasicAuth()
			if ok {
				ok, _ = ht.Authenticate(user, password)
			} else {
				password = r.Header.Get("X-API-Key")
				ok = password != "" && ht.AuthenticateAny(password)
			}

			if ok {
				h.ServeHTTP(w, r)
				return
			}

			sendPDNSError(w, http.StatusUnauthorized, "unauthorized")
		})
	}
}
