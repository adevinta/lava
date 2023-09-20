// Copyright 2023 Adevinta

package engine

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"
)

// agentLogger wraps [slog] to implement
// [github.com/adevinta/vulcan-agent/log.Logger].
type agentLogger struct {
	logger *slog.Logger
}

// newAgentLogger creates a new [agentLogger].
func newAgentLogger(l *slog.Logger) agentLogger {
	return agentLogger{logger: l}
}

// Debugf formats according to a format specifier and logs at
// [slog.LevelDebug].
func (l agentLogger) Debugf(format string, args ...any) {
	l.log(slog.LevelDebug, format, args...)
}

// Infof formats according to a format specifier and logs at
// [slog.LevelInfo].
func (l agentLogger) Infof(format string, args ...any) {
	l.log(slog.LevelInfo, format, args...)
}

// Errorf formats according to a format specifier and logs at
// [slog.LevelError].
func (l agentLogger) Errorf(format string, args ...any) {
	l.log(slog.LevelError, format, args...)
}

// log formats according to a format specifier and logs at the
// specified [slog.Level].
func (l agentLogger) log(level slog.Level, format string, args ...any) {
	if !l.logger.Enabled(context.Background(), level) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:]) // skip [Callers, agentLogger.log, agentLogger.Levelf]
	r := slog.NewRecord(time.Now(), level, fmt.Sprintf(format, args...), pcs[0])
	_ = l.logger.Handler().Handle(context.Background(), r)
}
