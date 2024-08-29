// Copyright 2024 Adevinta

package dag

import (
	"errors"
	"testing"
)

func TestDAG_Contains(t *testing.T) {
	tests := []struct {
		name     string
		vertices []string
		vertex   string
		want     bool
	}{
		{
			name:     "Vertex has been added",
			vertices: []string{"a", "b", "c"},
			vertex:   "a",
			want:     true,
		},
		{
			name:     "Vertex has not been added",
			vertices: []string{"a", "b", "c"},
			vertex:   "d",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dag := New()
			for _, v := range tt.vertices {
				if _, err := dag.AddVertex(v); err != nil {
					t.Fatalf("failed to add vertex %s: %v", v, err)
				}
			}
			if got := dag.Contains(tt.vertex); got != tt.want {
				t.Errorf("HasVertexBeenIncluded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDAG_AddVertex(t *testing.T) {
	tests := []struct {
		name     string
		vertices []string
		vertex   string
		wantErr  error
	}{
		{
			name:     "add unique vertex",
			vertices: []string{"a"},
			vertex:   "b",
			wantErr:  nil,
		},
		{
			name:     "add duplicate vertex",
			vertices: []string{"a"},
			vertex:   "a",
			wantErr:  ErrDuplicatedVertex,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dag := New()
			for _, v := range tt.vertices {
				if _, err := dag.AddVertex(v); err != nil {
					t.Fatalf("failed to add vertex %s: %v", v, err)
				}
			}
			_, err := dag.AddVertex(tt.vertex)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("unexpected error: got: %v, want: %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error adding the vertex: %v", err)
				}
			}
		})
	}
}

func TestDAG_AddEdge(t *testing.T) {
	tests := []struct {
		name     string
		vertices []string
		edges    [][]string
		from     string
		to       string
		wantErr  error
	}{
		{
			name:     "add edge",
			vertices: []string{"a", "b"},
			edges:    [][]string{},
			from:     "a",
			to:       "b",
			wantErr:  nil,
		},
		{
			name:     "add edge to invalid vertex",
			vertices: []string{"a", "b"},
			edges:    [][]string{},
			from:     "a",
			to:       "c",
			wantErr:  ErrUnknownVertex,
		},
		{
			name:     "add edge from invalid vertex",
			vertices: []string{"a", "b"},
			edges:    [][]string{},
			from:     "c",
			to:       "a",
			wantErr:  ErrUnknownVertex,
		},
		{
			name:     "add duplicate edge",
			vertices: []string{"a", "b"},
			edges:    [][]string{{"a", "b"}},
			from:     "a",
			to:       "b",
			wantErr:  ErrDuplicatedEdge,
		},
		{
			name:     "add a cycle",
			vertices: []string{"a", "b", "c"},
			edges:    [][]string{{"a", "b"}, {"b", "c"}},
			from:     "c",
			to:       "a",
			wantErr:  ErrCycle,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dag := New()
			for _, v := range tt.vertices {
				if _, err := dag.AddVertex(v); err != nil {
					t.Fatalf("failed to add vertex %s: %v", v, err)
				}
			}
			for _, edge := range tt.edges {
				if err := dag.AddEdge(edge[0], edge[1]); err != nil {
					t.Errorf("failed to add edge %s, %s: %v", edge[0], edge[1], err)
				}
			}
			err := dag.AddEdge(tt.from, tt.to)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("unexpected error: got: %v, want: %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error adding the edge: %v", err)
				}
			}
		})
	}
}
