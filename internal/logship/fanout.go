package logship

import (
	"context"
	"log/slog"
)

// Fanout returns an slog.Handler that dispatches each record to every child
// handler whose level is enabled. It lets the app keep stdout logging while also
// shipping to omnilog.
func Fanout(handlers ...slog.Handler) slog.Handler {
	return &fanout{handlers: handlers}
}

type fanout struct{ handlers []slog.Handler }

var _ slog.Handler = (*fanout)(nil)

func (f *fanout) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (f *fanout) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range f.handlers {
		if h.Enabled(ctx, r.Level) {
			// Clone so a handler that mutates the record can't affect the others.
			_ = h.Handle(ctx, r.Clone())
		}
	}
	return nil
}

func (f *fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		next[i] = h.WithAttrs(attrs)
	}
	return &fanout{handlers: next}
}

func (f *fanout) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		next[i] = h.WithGroup(name)
	}
	return &fanout{handlers: next}
}
