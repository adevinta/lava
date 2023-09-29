// Copyright 2023 Adevinta

package engine

import (
	"bytes"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"testing"
)

func TestAgentLogger(t *testing.T) {
	tests := []struct {
		name   string
		level  slog.Level
		logf   func(l agentLogger, format string, args ...any)
		format string
		args   []any
		want   string
	}{
		{
			name:   "Debugf at debug level",
			level:  slog.LevelDebug,
			logf:   agentLogger.Debugf,
			format: "msg %v %v",
			args:   []any{"Go", 60},
			want:   `level=DEBUG source=$SOURCE msg="msg Go 60"`,
		},
		{
			name:   "Debugf at info level",
			level:  slog.LevelInfo,
			logf:   agentLogger.Debugf,
			format: "msg %v %v",
			args:   []any{"Go", 60},
			want:   ``,
		},
		{
			name:   "Debugf at warn level",
			level:  slog.LevelWarn,
			logf:   agentLogger.Debugf,
			format: "msg %v %v",
			args:   []any{"Go", 60},
			want:   ``,
		},
		{
			name:   "Debugf at error level",
			level:  slog.LevelError,
			logf:   agentLogger.Debugf,
			format: "msg %v %v",
			args:   []any{"Go", 60},
			want:   ``,
		},
		{
			name:   "Infof at debug level",
			level:  slog.LevelDebug,
			logf:   agentLogger.Infof,
			format: "msg %v %v",
			args:   []any{"Go", 60},
			want:   `level=INFO source=$SOURCE msg="msg Go 60"`,
		},
		{
			name:   "Infof at info level",
			level:  slog.LevelInfo,
			logf:   agentLogger.Infof,
			format: "msg %v %v",
			args:   []any{"Go", 60},
			want:   `level=INFO source=$SOURCE msg="msg Go 60"`,
		},
		{
			name:   "Infof at warn level",
			level:  slog.LevelWarn,
			logf:   agentLogger.Infof,
			format: "msg %v %v",
			args:   []any{"Go", 60},
			want:   ``,
		},
		{
			name:   "Infof at error level",
			level:  slog.LevelError,
			logf:   agentLogger.Infof,
			format: "msg %v %v",
			args:   []any{"Go", 60},
			want:   ``,
		},
		{
			name:   "Errorf at debug level",
			level:  slog.LevelDebug,
			logf:   agentLogger.Errorf,
			format: "msg %v %v",
			args:   []any{"Go", 60},
			want:   `level=ERROR source=$SOURCE msg="msg Go 60"`,
		},
		{
			name:   "Errorf at info level",
			level:  slog.LevelInfo,
			logf:   agentLogger.Errorf,
			format: "msg %v %v",
			args:   []any{"Go", 60},
			want:   `level=ERROR source=$SOURCE msg="msg Go 60"`,
		},
		{
			name:   "Errorf at warn level",
			level:  slog.LevelWarn,
			logf:   agentLogger.Errorf,
			format: "msg %v %v",
			args:   []any{"Go", 60},
			want:   `level=ERROR source=$SOURCE msg="msg Go 60"`,
		},
		{
			name:   "Errorf at error level",
			level:  slog.LevelError,
			logf:   agentLogger.Errorf,
			format: "msg %v %v",
			args:   []any{"Go", 60},
			want:   `level=ERROR source=$SOURCE msg="msg Go 60"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
				Level:     tt.level,
				AddSource: true,
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					// Remove time.
					if a.Key == slog.TimeKey {
						return slog.Attr{}
					}
					return a
				},
			})
			logger := newAgentLogger(slog.New(handler))

			tt.logf(logger, tt.format, tt.args...)
			_, file, line, ok := runtime.Caller(0)
			if !ok {
				t.Fatalf("could not get source line")
			}

			// The call to tt.logf happens one line before
			// calling runtime.Caller.
			source := fmt.Sprintf("%v:%v", file, line-1)

			got := strings.TrimSuffix(buf.String(), "\n")
			want := strings.ReplaceAll(tt.want, "$SOURCE", source)
			if got != want {
				t.Errorf("unexpected output: got: %#q, want: %#q", got, want)
			}
		})
	}
}
