package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"

	"github.com/vooon/zoneomatic/internal/buildinfo"
	"github.com/vooon/zoneomatic/internal/htpasswd"
	"github.com/vooon/zoneomatic/internal/zone"
)

type Cli struct {
	Listen             string           `name:"listen" default:"localhost:9999" help:"Server listen address"`
	AcceptProxy        bool             `name:"accept-proxy" help:"Accept PROXY protocol"`
	ProxyHeaderTimeout time.Duration    `name:"proxy-header-timeout" default:"10s" help:"Timeout for PROXY headers"`
	HTPasswdFile       string           `short:"p" name:"htpasswd" required:"" type:"existingfile" placeholder:"FILE" help:"Passwords file (bcrypt only)"`
	ZoneFiles          []string         `short:"z" name:"zone" required:"" type:"existingfile" placeholder:"FILE,..." help:"Zone files to update"`
	AcmeTTL            int              `name:"acme-ttl" default:"0" help:"TTL (seconds) for ACME challenge TXT records; 0 = use zone $TTL"`
	DDNSManagePTR      bool             `name:"ddns-manage-ptr" help:"Update PTR records in matching reverse zones on DDNS update; missing reverse zone is ignored"`
	Debug              bool             `name:"debug" help:"Enable debug logging"`
	Version            kong.VersionFlag `help:"Print version and exit"`

	RFC2136ACME RFC2136ListenerConfig `embed:"" prefix:"rfc2136-acme-" envprefix:"ZM_RFC2136_ACME_"`
	RFC2136Upd  RFC2136ListenerConfig `embed:"" prefix:"rfc2136-update-" envprefix:"ZM_RFC2136_UPDATE_"`

	RFC2136UpdateMaxTTL int `name:"rfc2136-update-max-ttl" env:"ZM_RFC2136_UPDATE_MAX_TTL" default:"0" help:"Cap the TTL (seconds) of records written through the full-update listener; 0 = honor the update packet TTL"`

	OTEL OTelConfig `embed:"" prefix:"otel-"`
}

// RFC2136ListenerConfig holds the flags for one RFC2136 listener. The same
// options are embedded twice: for the ACME dns-01 listener and for the
// full-zone update listener.
type RFC2136ListenerConfig struct {
	Listen   string         `name:"listen" env:"LISTEN" help:"Listen address (host:port); empty disables the listener"`
	TSIGFile string         `name:"tsig-file" env:"TSIG_FILE" type:"existingfile" placeholder:"FILE" help:"BIND-format TSIG key file (as produced by tsig-keygen); required when listen is set"`
	Allow    []netip.Prefix `name:"allow" env:"ALLOW" sep:"," placeholder:"CIDR" help:"Allowed client CIDRs (comma-separated or repeated); empty allows all"`
}

func Main() {
	var cli Cli

	kctx := kong.Parse(&cli,
		kong.Description("DNS Zone file updater"),
		kong.DefaultEnvars("ZM"),
		kong.Vars{"version": buildinfo.String()},
	)

	baseHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: func() slog.Level {
			if cli.Debug {
				return slog.LevelDebug
			}
			return slog.LevelInfo
		}(),
	})

	// Keep default stderr logging in place even when OTel logs are enabled.
	slog.SetDefault(slog.New(baseHandler))

	otelShutdown, err := setupTelemetry(context.Background(), cli.OTEL, cli.Debug)
	kctx.FatalIfErrorf(err)
	if otelShutdown.LogHandler != nil {
		slog.SetDefault(slog.New(newTeeSlogHandler(baseHandler, otelShutdown.LogHandler)))
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		if err := otelShutdown.Shutdown(shutdownCtx); err != nil {
			slog.Error("OpenTelemetry shutdown failed", "error", err)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	zctl, err := zone.NewWithOptions([]zone.Option{zone.WithAcmeTTL(cli.AcmeTTL), zone.WithDDNSManagePTR(cli.DDNSManagePTR)}, cli.ZoneFiles...)
	kctx.FatalIfErrorf(err)

	htp, err := htpasswd.NewFromFile(cli.HTPasswdFile)
	kctx.FatalIfErrorf(err)

	srv, listener, err := NewServer(&cli)
	kctx.FatalIfErrorf(err)

	defer listener.Close() // nolint:errcheck

	RegisterEndpoints(srv, htp, zctl)

	acmeSrv, err := StartRFC2136(RFC2136Config{
		Listen:   cli.RFC2136ACME.Listen,
		TSIGFile: cli.RFC2136ACME.TSIGFile,
		Allow:    cli.RFC2136ACME.Allow,
		ACMEOnly: true,
	}, zctl)
	kctx.FatalIfErrorf(err)

	updateSrv, err := StartRFC2136(RFC2136Config{
		Listen:   cli.RFC2136Upd.Listen,
		TSIGFile: cli.RFC2136Upd.TSIGFile,
		Allow:    cli.RFC2136Upd.Allow,
		MaxTTL:   cli.RFC2136UpdateMaxTTL,
	}, zctl)
	kctx.FatalIfErrorf(err)

	go func() {
		err := srv.Run()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server run failed", "error", err)
		}
	}()

	// serve until sigint/sigterm
	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := acmeSrv.Shutdown(shutdownCtx); err != nil {
		slog.Error("RFC2136 ACME listener shutdown failed", "error", err)
	}
	if err := updateSrv.Shutdown(shutdownCtx); err != nil {
		slog.Error("RFC2136 update listener shutdown failed", "error", err)
	}

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server shutdown failed", "error", err)
	}
}
