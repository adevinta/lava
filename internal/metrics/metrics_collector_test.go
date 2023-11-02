// Copyright 2023 Adevinta

package metrics

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type mockWriteClose struct {
	*bytes.Buffer
}

func (mwc *mockWriteClose) Close() error {
	return nil
}

func TestMetrics_JSONCollector(t *testing.T) {
	tests := []struct {
		name    string
		metrics map[string]interface{}
		want    map[string]interface{}
	}{
		{
			name: "Happy Path",
			metrics: map[string]interface{}{
				"metric 1": "metric value 1",
				"metric 2": 12345,
				"metric 3": 25.5,
				"metric 4": map[string]int{
					"key 1": 1,
					"key 2": 2,
				},
				"metric 5": []string{
					"one", "two", "three",
				},
			},
			want: map[string]interface{}{
				"metric 1": "metric value 1",
				"metric 2": float64(12345),
				"metric 3": 25.5,
				"metric 4": map[string]any{
					"key 1": float64(1),
					"key 2": float64(2),
				},
				"metric 5": []any{
					"one", "two", "three",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realInitialization()
			buf := &bytes.Buffer{}
			je := &JSONEmitter{
				createWriter: func(metricsFile string) (io.WriteCloser, error) {
					return &mockWriteClose{buf}, nil
				},
			}
			mc := Collector{
				metrics: make(map[string]interface{}),
				emitter: je,
			}
			for key, value := range tt.metrics {
				mc.Collect(key, value)
			}

			if err := mc.Write("fakeFile.json"); err != nil {
				t.Fatalf("write metrics %v", err)
			}
			var got map[string]interface{}
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Errorf("unmarshal json metrics: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("metrics mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestMetrics_DefaultCollector(t *testing.T) {
	tests := []struct {
		name    string
		metrics map[string]interface{}
		want    map[string]interface{}
	}{
		{
			name: "Happy Path",
			metrics: map[string]interface{}{
				"metric 1": "metric value 1",
				"metric 2": 12345,
				"metric 3": 25.5,
				"metric 4": map[string]int{
					"key 1": 1,
					"key 2": 2,
				},
				"metric 5": []string{
					"one", "two", "three",
				},
			},
			want: map[string]interface{}{
				"metric 1": "metric value 1",
				"metric 2": float64(12345),
				"metric 3": 25.5,
				"metric 4": map[string]any{
					"key 1": float64(1),
					"key 2": float64(2),
				},
				"metric 5": []any{
					"one", "two", "three",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realInitialization()
			buf := &bytes.Buffer{}
			je := &JSONEmitter{
				createWriter: func(metricsFile string) (io.WriteCloser, error) {
					return &mockWriteClose{buf}, nil
				},
			}
			mc := &Collector{
				metrics: make(map[string]interface{}),
				emitter: je,
			}
			DefaultCollector = mc
			for key, value := range tt.metrics {
				Collect(key, value)
			}

			if err := Write("fakeFile.json"); err != nil {
				t.Fatalf("write metrics %v", err)
			}
			var got map[string]interface{}
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Errorf("unmarshal json metrics: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("metrics mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestMetrics_OutputFile(t *testing.T) {
	tests := []struct {
		name    string
		metrics map[string]interface{}
		want    map[string]interface{}
	}{
		{
			name: "Happy Path",
			metrics: map[string]interface{}{
				"metric 1": "metric value 1",
				"metric 2": 12345,
				"metric 3": 25.5,
				"metric 4": map[string]int{
					"key 1": 1,
					"key 2": 2,
				},
				"metric 5": []string{
					"one", "two", "three",
				},
			},
			want: map[string]interface{}{
				"metric 1": "metric value 1",
				"metric 2": float64(12345),
				"metric 3": 25.5,
				"metric 4": map[string]any{
					"key 1": float64(1),
					"key 2": float64(2),
				},
				"metric 5": []any{
					"one", "two", "three",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realInitialization()
			tmpPath, err := os.MkdirTemp("", "")
			if err != nil {
				t.Fatalf("unable to create a temporary dir")
			}
			defer os.RemoveAll(tmpPath)
			metricsFile := path.Join(tmpPath, "metrics.json")

			for key, value := range tt.metrics {
				Collect(key, value)
			}

			if err = Write(metricsFile); err != nil {
				t.Fatalf("write metrics %v", err)
			}

			file, err := os.Open(metricsFile)
			if err != nil {
				t.Fatalf("open metrics file: %v", err)
			}
			defer file.Close()

			content, err := io.ReadAll(file)
			if err != nil {
				t.Fatalf("read metrics file: %v", err)
			}
			var got map[string]interface{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Errorf("unmarshal json metrics: %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("metrics mismatch (-want +got):\n%v", diff)
			}
		})
	}
}
