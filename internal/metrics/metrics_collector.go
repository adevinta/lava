// Copyright 2023 Adevinta

// Package metrics collects all kind of Lava metrics.
package metrics

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// DefaultCollector is the default [Collector] and is used by [Collect] and [Write].
var DefaultCollector *Collector

// init initializes the DefaultCollector.
func init() {
	realInitialization()
}

func realInitialization() {
	DefaultCollector = &Collector{
		metrics: make(map[string]interface{}),
		emitter: NewJSONEmitter(),
	}
}

// Collector represents a metrics collector.
type Collector struct {
	mutex   sync.Mutex
	metrics map[string]interface{}
	emitter emitter
}

// Collect stores the metric.
func (c *Collector) Collect(metric string, value interface{}) {
	c.mutex.Lock()
	c.metrics[metric] = value
	c.mutex.Unlock()
}

// Write renders the metrics.
func (c *Collector) Write(metricsFile string) error {
	if err := c.emitter.Emit(metricsFile, c.metrics); err != nil {
		return fmt.Errorf("emit metrics: %w", err)
	}
	return nil
}

// A emitter emit metrics.
type emitter interface {
	Emit(metricsFile string, metrics map[string]interface{}) error
}

// JSONEmitter emits metrics in JSON format.
type JSONEmitter struct {
	createWriter func(metricsFile string) (io.WriteCloser, error)
}

// NewJSONEmitter create a metrics emitter.
func NewJSONEmitter() *JSONEmitter {
	return &JSONEmitter{
		// For lazy file creation.
		createWriter: func(metricsFile string) (io.WriteCloser, error) {
			f, err := os.Create(metricsFile)
			if err != nil {
				return nil, fmt.Errorf("create file: %w", err)
			}
			return f, nil
		},
	}
}

// Emit renders the metrics in JSON format.
func (c *JSONEmitter) Emit(metricsFile string, metrics map[string]interface{}) error {
	w, err := c.createWriter(metricsFile)
	if err != nil {
		return fmt.Errorf("create writer: %w", err)
	}
	defer w.Close()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err = enc.Encode(metrics); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}

// Collect stores the metric.
func Collect(metric string, value interface{}) {
	DefaultCollector.Collect(metric, value)
}

// Write renders the metrics.
func Write(metricsFile string) error {
	return DefaultCollector.Write(metricsFile)
}
