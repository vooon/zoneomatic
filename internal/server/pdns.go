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

type pdnsHTTPError struct {
	status  int
	Message string   `json:"error"`
	Errors  []string `json:"errors,omitempty"`
}

func (e pdnsHTTPError) Error() string { return e.Message }

func (e pdnsHTTPError) StatusCode() int { return e.status }

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
	pdnsAuth := htpasswd.NewAPIKeyMiddlewareWithUnauthorized(htp, func(w http.ResponseWriter, r *http.Request) {
		sendPDNSError(w, r, http.StatusUnauthorized, "unauthorized")
	})
	pdnsSecurity := option.Security(openapi3.SecurityRequirement{
		"pdnsApiKeyAuth": []string{},
	})

	fuego.Get(srv, "/api/v1/servers",
		func(ctx fuego.ContextNoBody) ([]pdnsServer, error) {
			return []pdnsServer{pdnsServerInfo()}, nil
		},
		option.Summary("pdns list servers"),
		option.Description("List the forged PowerDNS-compatible server instance"),
		option.Middleware(pdnsAuth),
		pdnsSecurity,
	)

	fuego.Get(srv, "/api/v1/servers/{server_id}",
		func(ctx fuego.ContextNoBody) (pdnsServer, error) {
			serverID := ctx.PathParam("server_id")
			if serverID != pdnsServerID {
				return pdnsServer{}, newPDNSError(http.StatusNotFound, "server not found")
			}

			return pdnsServerInfo(), nil
		},
		option.Summary("pdns get server"),
		option.Description("Return the forged PowerDNS-compatible server instance"),
		option.Middleware(pdnsAuth),
		pdnsSecurity,
	)

	fuego.Get(srv, "/api/v1/servers/{server_id}/zones",
		func(ctx fuego.ContextNoBody) ([]pdnsZone, error) {
			serverID := ctx.PathParam("server_id")
			if serverID != pdnsServerID {
				return nil, newPDNSError(http.StatusNotFound, "server not found")
			}

			zones, err := zctl.ListZones(ctx)
			if err != nil {
				return nil, newPDNSError(http.StatusInternalServerError, err.Error())
			}

			zoneFilter := ctx.QueryParam("zone")
			result := make([]pdnsZone, 0, len(zones))
			for _, zoneData := range zones {
				if zoneFilter != "" && zoneData.Name != dnsFQDN(zoneFilter) {
					continue
				}

				result = append(result, zoneSnapshotToPDNSZone(zoneData, false))
			}

			return result, nil
		},
		option.Summary("pdns list zones"),
		option.Description("List managed zones in a PowerDNS-compatible format"),
		option.Middleware(pdnsAuth),
		pdnsSecurity,
		option.Query("zone", "Filter zones by fully-qualified zone name"),
	)

	fuego.Get(srv, "/api/v1/servers/{server_id}/zones/{zone_id}",
		func(ctx fuego.ContextNoBody) (*pdnsZone, error) {
			serverID := ctx.PathParam("server_id")
			if serverID != pdnsServerID {
				return nil, newPDNSError(http.StatusNotFound, "server not found")
			}

			zoneData, err := zctl.GetZone(ctx, ctx.PathParam("zone_id"))
			if err != nil {
				switch {
				case errors.Is(err, zone.ErrZoneNotFound):
					return nil, newPDNSError(http.StatusNotFound, err.Error())
				case errors.Is(err, zone.ErrRecordNotFound):
					return nil, newPDNSError(http.StatusNotFound, err.Error())
				default:
					return nil, newPDNSError(http.StatusUnprocessableEntity, err.Error())
				}
			}

			includeRRsets := !strings.EqualFold(ctx.QueryParam("rrsets"), "false")
			rrsetName := ctx.QueryParam("rrset_name")
			rrsetType := ctx.QueryParam("rrset_type")
			if rrsetType != "" && rrsetName == "" {
				return nil, newPDNSError(http.StatusUnprocessableEntity, "rrset_type requires rrset_name")
			}

			zoneResp := zoneSnapshotToPDNSZone(zoneData, includeRRsets)
			if includeRRsets && rrsetName != "" {
				zoneResp.RRsets = filterPDNSRRsets(zoneResp.RRsets, rrsetName, rrsetType)
			}

			return &zoneResp, nil
		},
		option.Summary("pdns get zone"),
		option.Description("Return a managed zone in PowerDNS-compatible format"),
		option.Middleware(pdnsAuth),
		pdnsSecurity,
		option.QueryBool("rrsets", "Include rrsets in the zone response. Defaults to true."),
		option.Query("rrset_name", "Filter returned rrsets by fully-qualified record name"),
		option.Query("rrset_type", "Filter returned rrsets by record type; requires rrset_name"),
	)

	fuego.PatchStd(srv, "/api/v1/servers/{server_id}/zones/{zone_id}",
		func(w http.ResponseWriter, r *http.Request) {
			if !requirePDNSServerID(w, r) {
				return
			}

			defer r.Body.Close() // nolint:errcheck

			var req pdnsPatchZoneRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				sendPDNSError(w, r, http.StatusBadRequest, "invalid json body", err.Error())
				return
			}

			zoneName := r.PathValue("zone_id")
			for _, rrset := range req.RRsets {
				if rrset.Name == "" || rrset.Type == "" {
					sendPDNSError(w, r, http.StatusUnprocessableEntity, "rrset name and type are required")
					return
				}

				switch strings.ToUpper(strings.TrimSpace(rrset.ChangeType)) {
				case "DELETE":
					if _, err := zctl.DeleteRRSet(r.Context(), zoneName, rrset.Name, rrset.Type); err != nil {
						sendPDNSZoneError(w, r, err)
						return
					}
				case "REPLACE":
					if len(rrset.Records) == 0 {
						if _, err := zctl.DeleteRRSet(r.Context(), zoneName, rrset.Name, rrset.Type); err != nil {
							sendPDNSZoneError(w, r, err)
							return
						}

						continue
					}

					if rrset.TTL <= 0 {
						sendPDNSError(w, r, http.StatusUnprocessableEntity, "ttl must be greater than zero for REPLACE")
						return
					}

					values := make([]string, 0, len(rrset.Records))
					for _, record := range rrset.Records {
						if record.Disabled {
							sendPDNSError(w, r, http.StatusNotImplemented, "disabled records are not supported")
							return
						}

						values = append(values, record.Content)
					}

					if _, err := zctl.ReplaceRRSet(r.Context(), zoneName, rrset.Name, rrset.Type, rrset.TTL, values); err != nil {
						sendPDNSZoneError(w, r, err)
						return
					}
				default:
					sendPDNSError(w, r, http.StatusNotImplemented, "unsupported changetype: "+rrset.ChangeType)
					return
				}
			}

			w.WriteHeader(http.StatusNoContent)
		},
		option.Summary("pdns patch zone"),
		option.Description("Replace or delete managed RRSets in PowerDNS-compatible format"),
		option.Middleware(pdnsAuth),
		pdnsSecurity,
		option.RequestBody(
			fuego.RequestBody{
				Type:         new(pdnsPatchZoneRequest),
				ContentTypes: []string{"application/json"},
			},
		),
		option.AddResponse(http.StatusNoContent, "RRSets updated",
			fuego.Response{Type: struct{}{}},
		),
		option.AddResponse(http.StatusBadRequest, "Invalid request body",
			fuego.Response{Type: new(pdnsHTTPError)},
		),
		option.AddResponse(http.StatusUnauthorized, "Unauthorized",
			fuego.Response{Type: new(pdnsHTTPError)},
		),
		option.AddResponse(http.StatusNotFound, "Zone or server not found",
			fuego.Response{Type: new(pdnsHTTPError)},
		),
		option.AddResponse(http.StatusUnprocessableEntity, "Invalid rrset request",
			fuego.Response{Type: new(pdnsHTTPError)},
		),
		option.AddResponse(http.StatusNotImplemented, "Unsupported patch request",
			fuego.Response{Type: new(pdnsHTTPError)},
		),
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
		sendPDNSError(w, r, http.StatusNotImplemented, operation+" is not implemented")
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

	sendPDNSError(w, r, http.StatusNotFound, "server not found")
	return false
}

func sendPDNSZoneError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, zone.ErrZoneNotFound):
		sendPDNSError(w, r, http.StatusNotFound, err.Error())
	case errors.Is(err, zone.ErrRecordNotFound):
		sendPDNSError(w, r, http.StatusNotFound, err.Error())
	default:
		sendPDNSError(w, r, http.StatusUnprocessableEntity, err.Error())
	}
}

func sendPDNSError(w http.ResponseWriter, r *http.Request, status int, msg string, errs ...string) {
	fuego.SendJSONError(w, r, newPDNSError(status, msg, errs...))
}

func newPDNSError(status int, msg string, errs ...string) pdnsHTTPError {
	return pdnsHTTPError{status: status, Message: msg, Errors: errs}
}

func dnsFQDN(name string) string {
	if name == "" {
		return ""
	}

	return strings.TrimSpace(strings.TrimSuffix(name, ".")) + "."
}
