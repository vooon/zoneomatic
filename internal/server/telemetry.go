package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type OTelConfig struct {
	Endpoint        string `name:"endpoint" help:"Shared OTLP/HTTP endpoint URL for enabled signals (typically collector URL)"`
	TracesEnabled   bool   `name:"enable-traces" help:"Enable OpenTelemetry traces signal"`
	TracesEndpoint  string `name:"traces-endpoint" help:"OTLP/HTTP traces endpoint URL (e.g. http://127.0.0.1:4318/v1/traces)"`
	MetricsEnabled  bool   `name:"enable-metrics" help:"Enable OpenTelemetry metrics signal"`
	MetricsEndpoint string `name:"metrics-endpoint" help:"OTLP/HTTP metrics endpoint URL (e.g. http://127.0.0.1:4318/v1/metrics)"`
	LogsEnabled     bool   `name:"enable-logs" help:"Enable OpenTelemetry logs signal"`
	LogsEndpoint    string `name:"logs-endpoint" help:"OTLP/HTTP logs endpoint URL (e.g. http://127.0.0.1:4318/v1/logs)"`
	ServiceName     string `name:"service-name" default:"zoneomatic" help:"OpenTelemetry service name"`
}

type telemetryShutdown struct {
	Shutdown   func(context.Context) error
	LogHandler slog.Handler
}

func setupTelemetry(ctx context.Context, cfg OTelConfig, includeLogSource bool) (telemetryShutdown, error) {
	ret := telemetryShutdown{
		Shutdown: func(context.Context) error { return nil },
	}

	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)

	serviceName := strings.TrimSpace(cfg.ServiceName)
	if serviceName == "" {
		serviceName = "zoneomatic"
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			"",
			attribute.String("service.name", serviceName),
		),
	)
	if err != nil {
		return ret, err
	}

	shutdownFns := make([]func(context.Context) error, 0, 3)

	if cfg.TracesEnabled {
		endpoint := signalEndpoint(cfg.TracesEndpoint, cfg.Endpoint)
		if endpoint == "" {
			return ret, errors.New("otel traces enabled, but neither --otel-traces-endpoint nor --otel-endpoint is set")
		}

		exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint))
		if err != nil {
			return ret, fmt.Errorf("init traces exporter: %w", err)
		}

		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(res),
		)
		otel.SetTracerProvider(tp)
		shutdownFns = append(shutdownFns, tp.Shutdown)
		slog.Info("OpenTelemetry traces enabled", "endpoint", endpoint, "service_name", serviceName)
	}

	if cfg.MetricsEnabled {
		endpoint := signalEndpoint(cfg.MetricsEndpoint, cfg.Endpoint)
		if endpoint == "" {
			return ret, errors.New("otel metrics enabled, but neither --otel-metrics-endpoint nor --otel-endpoint is set")
		}

		exp, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(endpoint))
		if err != nil {
			return ret, fmt.Errorf("init metrics exporter: %w", err)
		}

		mp := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)),
			sdkmetric.WithResource(res),
		)
		otel.SetMeterProvider(mp)
		shutdownFns = append(shutdownFns, mp.Shutdown)
		slog.Info("OpenTelemetry metrics enabled", "endpoint", endpoint, "service_name", serviceName)
	}

	if cfg.LogsEnabled {
		endpoint := signalEndpoint(cfg.LogsEndpoint, cfg.Endpoint)
		if endpoint == "" {
			return ret, errors.New("otel logs enabled, but neither --otel-logs-endpoint nor --otel-endpoint is set")
		}

		exp, err := otlploghttp.New(ctx, otlploghttp.WithEndpointURL(endpoint))
		if err != nil {
			return ret, fmt.Errorf("init logs exporter: %w", err)
		}

		lp := sdklog.NewLoggerProvider(
			sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
			sdklog.WithResource(res),
		)
		global.SetLoggerProvider(lp)
		shutdownFns = append(shutdownFns, lp.Shutdown)
		ret.LogHandler = otelslog.NewHandler(
			"zoneomatic",
			otelslog.WithLoggerProvider(lp),
			otelslog.WithSource(includeLogSource),
		)

		slog.Info("OpenTelemetry logs enabled", "endpoint", endpoint, "service_name", serviceName)
	}

	ret.Shutdown = func(ctx context.Context) error {
		var err error
		for i := len(shutdownFns) - 1; i >= 0; i-- {
			err = errors.Join(err, shutdownFns[i](ctx))
		}
		return err
	}

	return ret, nil
}

func signalEndpoint(specific, common string) string {
	specific = strings.TrimSpace(specific)

	if specific != "" {
		return specific
	}

	return strings.TrimSpace(common)
}

func otelHTTPMiddleware() func(http.Handler) http.Handler {
	return otelhttp.NewMiddleware(
		"zoneomatic-http",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			route := r.Pattern
			if route == "" {
				route = r.URL.Path
			}
			return r.Method + " " + route
		}),
	)
}
