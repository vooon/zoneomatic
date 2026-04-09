package server

import (
	"context"
	"errors"
	"log/slog"
)

type teeSlogHandler struct {
	handlers []slog.Handler
}

func newTeeSlogHandler(handlers ...slog.Handler) *teeSlogHandler {
	hs := make([]slog.Handler, 0, len(handlers))
	for _, h := range handlers {
		if h != nil {
			hs = append(hs, h)
		}
	}

	return &teeSlogHandler{handlers: hs}
}

func (h *teeSlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}

	return false
}

func (h *teeSlogHandler) Handle(ctx context.Context, record slog.Record) error {
	var err error
	for _, handler := range h.handlers {
		if !handler.Enabled(ctx, record.Level) {
			continue
		}
		err = errors.Join(err, handler.Handle(ctx, record))
	}

	return err
}

func (h *teeSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Handler, 0, len(h.handlers))
	for _, handler := range h.handlers {
		out = append(out, handler.WithAttrs(attrs))
	}

	return &teeSlogHandler{handlers: out}
}

func (h *teeSlogHandler) WithGroup(name string) slog.Handler {
	out := make([]slog.Handler, 0, len(h.handlers))
	for _, handler := range h.handlers {
		out = append(out, handler.WithGroup(name))
	}

	return &teeSlogHandler{handlers: out}
}
