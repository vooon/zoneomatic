package server

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-fuego/fuego"
	"github.com/go-fuego/fuego/option"
	"github.com/go-fuego/fuego/param"
	"github.com/pires/go-proxyproto"
	"github.com/vooon/zoneomatic/internal/htpasswd"
	"github.com/vooon/zoneomatic/internal/zone"
)

type ACMEUpdateRequest struct {
	Subdomain string `json:"subdomain" validate:"required"`
	TXT       string `json:"txt" validate:"required"`
}

type ACMEUpdateResponse struct {
	TXT string `json:"txt"`
}

func NewServer(cli *Cli) (*fuego.Server, net.Listener, error) {

	listener, err := net.Listen("tcp", cli.Listen)
	if err != nil {
		return nil, nil, err
	}

	if cli.AcceptProxy {
		pl := &proxyproto.Listener{
			Listener:          listener,
			ReadHeaderTimeout: cli.ProxyHeaderTimeout,
		}
		listener = pl
	}

	srv := fuego.NewServer(
		fuego.WithListener(listener),
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
						WithName("X-Api-User").
						WithDescription("username"),
				},
				"apiKeyAuth": {
					Value: openapi3.NewSecurityScheme().
						WithType("apiKey").
						WithIn("header").
						WithName("X-Api-Key").
						WithDescription("password"),
				},
			},
		),
	)

	return srv, listener, nil
}

func RegisterEndpoints(srv *fuego.Server, htp htpasswd.HTPasswd, zctl zone.Controller) {

	authMw := htpasswd.NewBasicAuthMiddleware(htp)

	fuego.Get(srv, "/health",
		func(ctx fuego.ContextNoBody) (string, error) {
			return "OK", nil
		},
		option.Summary("health"),
		option.Description("Health check endpoint"),
	)

	fuego.Get(srv, "/myip",
		func(ctx fuego.ContextNoBody) (string, error) {
			a, err := netip.ParseAddrPort(ctx.Request().RemoteAddr)
			if err != nil {
				return "", err
			}

			return a.Addr().String() + "\n", nil
		},
		option.Summary("myip"),
		option.Description("Return client's connection IP address"),
	)

	fuego.Get(srv, "/nic/update",
		func(ctx fuego.ContextNoBody) (string, error) {

			lg := slog.Default()

			hns := ctx.QueryParamArr("hostname")
			myip := ctx.QueryParamArr("myip")
			myipv6 := ctx.QueryParamArr("myipv6")

			if len(hns) > 1 {
				lg.WarnContext(ctx, "Update more than one hostname not supported", "hostnames", hns)
			}
			domain := hns[0]

			var err error
			newAddrs := make([]netip.Addr, 0)
			for _, ip := range slices.Concat(myip, myipv6) {
				a, err2 := netip.ParseAddr(ip)
				if err2 != nil {
					err = errors.Join(err, err2)
					continue
				}

				newAddrs = append(newAddrs, a)
			}
			if err != nil {
				lg.ErrorContext(ctx, "Failed to parse myip", "error", err)
				return "", err
			}

			if len(newAddrs) == 0 {
				a, err := netip.ParseAddrPort(ctx.Request().RemoteAddr)
				if err != nil {
					return "", err
				}

				newAddrs = append(newAddrs, a.Addr())
			}

			err = zctl.UpdateDomain(ctx, domain, newAddrs)
			if err != nil {
				return "", err
			}

			return "OK", nil
		},
		option.Summary("update ddns"),
		option.Description("Update DDNS record"),
		option.Middleware(authMw),
		option.Security(openapi3.SecurityRequirement{
			"basicAuth": []string{},
		}),
		option.Query("hostname", "record domain to update", param.Required()),
		option.Query("myip", "IP address to set"),
		option.Query("myipv6", "IPv6 address to set"),
		option.QueryBool("offline", "Not supported, a no-op for compatibility."),
	)

	fuego.PostStd(srv, "/acme/update",
		func(w http.ResponseWriter, r *http.Request) {

			ctx := r.Context()
			lg := slog.Default()
			defer r.Body.Close() // nolint: errcheck

			req, err := fuego.ReadJSON[ACMEUpdateRequest](ctx, r.Body)
			if err != nil {
				lg.ErrorContext(ctx, "Failed to parse body", "error", err)
				fuego.SendError(w, r, err)
				return
			}

			err = zctl.UpdateACMEChallenge(ctx, req.Subdomain, req.TXT)
			if err != nil {
				fuego.SendError(w, r, err)
				return
			}

			fuego.SendJSON(w, r, &ACMEUpdateResponse{TXT: req.TXT}) // nolint: errcheck
		},
		option.Summary("update acme"),
		option.Description("Update ACME challenge TXT record"),
		option.Middleware(authMw),
		option.Security(
			openapi3.SecurityRequirement{
				"apiUserAuth": []string{},
				"apiKeyAuth":  []string{},
			},
			openapi3.SecurityRequirement{
				"basicAuth": []string{},
			},
		),
		option.RequestBody(
			fuego.RequestBody{
				Type:         new(ACMEUpdateRequest),
				ContentTypes: []string{"application/json"},
			},
		),
		option.AddResponse(http.StatusOK, "Record updated",
			fuego.Response{
				Type: new(ACMEUpdateResponse),
			},
		),
	)
}
