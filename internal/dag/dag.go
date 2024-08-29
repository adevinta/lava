// Copyright 2024 Adevinta

// Package dag contains the functionality for Directed Acyclic Graphs.
package dag

import (
	"errors"
	"fmt"

	hdag "github.com/heimdalr/dag"
)

var (
	// ErrDuplicatedVertex is the error returned when the vertex has
	// already added before.
	ErrDuplicatedVertex = errors.New("duplicated vertex")

	// ErrUnknownVertex is the error returned when the vertex has not
	// been seen.
	ErrUnknownVertex = errors.New("unknown vertex")

	// ErrDuplicatedEdge is the error returned when the edge has
	// already added before.
	ErrDuplicatedEdge = errors.New("duplicated edge")

	// ErrCycle is the error returned when a cycled is detected.
	ErrCycle = errors.New("cycle detected")
)

// DAG represents a Direct Acyclic Graph object.
type DAG struct {
	dag      *hdag.DAG
	vertices map[string]string
}

// NewDAG returns a Directed Acyclic Graph object.
func NewDAG() *DAG {
	return &DAG{
		dag:      hdag.NewDAG(),
		vertices: make(map[string]string),
	}
}

// AddVertex adds the vertex x to the DAG. AddVertex returns an error, if s is
// nil, s is already part of the graph, or the id of s is already part of the
// graph.
func (d *DAG) AddVertex(s string) (string, error) {
	d.dag.GetVertices()
	id, err := d.dag.AddVertex(s)
	if err != nil {
		var vertexDuplicateError hdag.VertexDuplicateError
		if errors.As(err, &vertexDuplicateError) {
			return id, fmt.Errorf("%w: %s", ErrDuplicatedVertex, s)
		}
	}
	d.vertices[s] = id
	return id, nil
}

// AddEdge adds an edge between from and to. AddEdge returns an
// error, if from, or to are empty strings or unknown, if the edge
// already exists, or if the new edge would create a loop.
func (d *DAG) AddEdge(from, to string) error {
	fromID := d.getVertexID(from)
	if fromID == "" {
		return fmt.Errorf("%w: %s", ErrUnknownVertex, from)
	}
	toID := d.getVertexID(to)
	if toID == "" {
		return fmt.Errorf("%w: %s", ErrUnknownVertex, to)
	}
	err := d.dag.AddEdge(fromID, toID)
	if err != nil {
		if errors.As(err, &hdag.EdgeDuplicateError{}) {
			return fmt.Errorf("%w: from %s to %s", ErrDuplicatedEdge, from, to)
		}
		if errors.As(err, &hdag.EdgeLoopError{}) {
			return fmt.Errorf("%w: from %s to %s", ErrCycle, from, to)
		}
		return fmt.Errorf("add edge: %w", err)
	}
	return nil
}

// HasVertexBeenAdded check if a vertex has already been added.
func (d *DAG) HasVertexBeenAdded(s string) bool {
	if _, ok := d.vertices[s]; !ok {
		return false
	}
	return true
}

// getVertexID get the vertex id.
func (d *DAG) getVertexID(s string) string {
	if i, ok := d.vertices[s]; ok {
		return i
	}
	return ""
}
