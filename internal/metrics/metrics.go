// Copyright 2023 Adevinta

// Package metrics collects Lava execution metrics.
package metrics

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// DefaultCollector is the default [Collector].
var DefaultCollector = NewCollector()

// Collector represents a metrics collector.
type Collector struct {
	mutex   sync.Mutex
	metrics map[string]any
}

// NewCollector returns a new metrics collector.
func NewCollector() *Collector {
	return &Collector{
		metrics: make(map[string]any),
	}
}

// Collect records a metric with the provided name and value.
func (c *Collector) Collect(name string, value any) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.metrics[name] = value
}

// Write writes the metrics to the specified [io.Writer].
func (c *Collector) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c.metrics); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	return nil
}

// Collect records a metric with the provided name and value using
// [DefaultCollector].
func Collect(name string, value any) {
	DefaultCollector.Collect(name, value)
}

// Write writes the collected metrics to the specified [io.Writer]
// using [DefaultCollector].
func Write(w io.Writer) error {
	return DefaultCollector.Write(w)
}

// WriteFile writes the collected metrics into the specified file
// using [DefaultCollector].
func WriteFile(file string) error {
	f, err := os.Create(file)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	return Write(f)
}
