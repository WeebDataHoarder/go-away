package tests

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
)

type logger struct {
	t     *testing.T
	attrs []slog.Attr
}

func (l logger) Enabled(ctx context.Context, level slog.Level) bool {
	return true
}

func (l logger) Handle(ctx context.Context, record slog.Record) error {
	str := fmt.Sprintf("[%s] %s", record.Level, record.Message)

	if record.NumAttrs() > 0 || len(l.attrs) > 0 {
		str += ": "
	}
	for _, attr := range l.attrs {
		str += fmt.Sprintf("%s=%s ", attr.Key, attr.Value.String())
	}
	record.Attrs(func(attr slog.Attr) bool {
		str += fmt.Sprintf("%s=%s ", attr.Key, attr.Value.String())
		return true
	})

	if record.Level == slog.LevelError {
		l.t.Error(str)
	} else {
		l.t.Log(str)
	}
	return nil
}

func (l logger) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, 0, len(attrs)+len(l.attrs))
	newAttrs = append(newAttrs, l.attrs...)
	newAttrs = append(newAttrs, attrs...)
	return logger{
		t:     l.t,
		attrs: newAttrs,
	}
}

func (l logger) WithGroup(name string) slog.Handler {
	return l
}

func initLogger(t *testing.T) slog.Handler {
	return logger{t: t}
}
