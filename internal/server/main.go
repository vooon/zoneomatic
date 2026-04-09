package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"

	"github.com/vooon/zoneomatic/internal/htpasswd"
	"github.com/vooon/zoneomatic/internal/zone"
)

type Cli struct {
	Listen             string        `name:"listen" default:"localhost:9999" help:"Server listen address"`
	AcceptProxy        bool          `name:"accept-proxy" help:"Accept PROXY protocol"`
	ProxyHeaderTimeout time.Duration `name:"proxy-header-timeout" default:"10s" help:"Timeout for PROXY headers"`
	HTPasswdFile       string        `short:"p" name:"htpasswd" required:"" type:"existingfile" placeholder:"FILE" help:"Passwords file (bcrypt only)"`
	ZoneFiles          []string      `short:"z" name:"zone" required:"" type:"existingfile" placeholder:"FILE,..." help:"Zone files to update"`
	Debug              bool          `name:"debug" help:"Enable debug logging"`

	OTEL OTelConfig `embed:"" prefix:"otel-"`
}

func Main() {
	var cli Cli

	kctx := kong.Parse(&cli,
		kong.Description("DNS Zone file updater"),
		kong.DefaultEnvars("ZM"),
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

	zctl, err := zone.New(cli.ZoneFiles...)
	kctx.FatalIfErrorf(err)

	htp, err := htpasswd.NewFromFile(cli.HTPasswdFile)
	kctx.FatalIfErrorf(err)

	srv, listener, err := NewServer(&cli)
	kctx.FatalIfErrorf(err)

	defer listener.Close() // nolint:errcheck

	RegisterEndpoints(srv, htp, zctl)

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

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server shutdown failed", "error", err)
	}
}
