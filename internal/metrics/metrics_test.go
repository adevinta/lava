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

var testdata = []struct {
	name    string
	metrics map[string]any
	want    map[string]any
}{
	{
		name: "happy path",
		metrics: map[string]any{
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
		want: map[string]any{
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

func TestWrite(t *testing.T) {
	for _, tt := range testdata {
		t.Run(tt.name, func(t *testing.T) {
			oldDefaultCollector := DefaultCollector
			defer func() { DefaultCollector = oldDefaultCollector }()

			DefaultCollector = NewCollector()

			var buf bytes.Buffer

			for key, value := range tt.metrics {
				Collect(key, value)
			}

			if err := Write(&buf); err != nil {
				t.Fatalf("error writing metrics: %v", err)
			}

			var got map[string]any
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Errorf("error decoding json metrics: %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("metrics mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestWriteFile(t *testing.T) {
	for _, tt := range testdata {
		t.Run(tt.name, func(t *testing.T) {
			oldDefaultCollector := DefaultCollector
			defer func() { DefaultCollector = oldDefaultCollector }()

			DefaultCollector = NewCollector()

			tmpPath, err := os.MkdirTemp("", "")
			if err != nil {
				t.Fatalf("error creating temp dir: %v", err)
			}
			defer os.RemoveAll(tmpPath)

			file := path.Join(tmpPath, "metrics.json")

			for key, value := range tt.metrics {
				Collect(key, value)
			}

			if err = WriteFile(file); err != nil {
				t.Fatalf("error writing metrics: %v", err)
			}

			f, err := os.Open(file)
			if err != nil {
				t.Fatalf("error opening metrics file: %v", err)
			}
			defer f.Close()

			data, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("error reading metrics file: %v", err)
			}

			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Errorf("error decoding json metrics: %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("metrics mismatch (-want +got):\n%v", diff)
			}
		})
	}
}
