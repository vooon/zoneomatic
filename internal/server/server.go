package server

import (
	"net"

	openapiv3 "github.com/getkin/kin-openapi/openapi3"
	"github.com/go-fuego/fuego"
	"github.com/pires/go-proxyproto"
)

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
			map[string]*openapiv3.SecuritySchemeRef{
				"basicAuth": {
					Value: openapiv3.NewSecurityScheme().
						WithType("http").
						WithScheme("basic"),
				},
			},
		),
	)

	return srv, listener, nil
}
