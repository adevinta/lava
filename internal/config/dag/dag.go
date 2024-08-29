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
	// already been added.
	ErrDuplicatedVertex = errors.New("duplicated vertex")

	// ErrUnknownVertex is the error returned when the vertex has not
	// been seen.
	ErrUnknownVertex = errors.New("unknown vertex")

	// ErrDuplicatedEdge is the error returned when the edge has
	// already been added.
	ErrDuplicatedEdge = errors.New("duplicated edge")

	// ErrCycle is the error returned when a cycle is detected.
	ErrCycle = errors.New("cycle detected")
)

// DAG represents a Direct Acyclic Graph object.
type DAG struct {
	dag      *hdag.DAG
	vertices map[string]string
}

// New returns a Directed Acyclic Graph object.
func New() *DAG {
	return &DAG{
		dag:      hdag.NewDAG(),
		vertices: make(map[string]string),
	}
}

// AddVertex adds the vertex x to the DAG. AddVertex returns an error if s is
// nil or s is already part of the graph.
func (d *DAG) AddVertex(s string) (string, error) {
	id, err := d.dag.AddVertex(s)
	if err != nil {
		if errors.As(err, &hdag.VertexDuplicateError{}) {
			return id, fmt.Errorf("%w: %s", ErrDuplicatedVertex, s)
		}
	}
	d.vertices[s] = id
	return id, nil
}

// AddEdge adds an edge between from and to. AddEdge returns an
// error if from or to are empty strings or unknown, if the edge
// already exists or if the new edge would create a loop.
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

// Contains checks if a vertex has already been added.
func (d *DAG) Contains(s string) bool {
	if _, ok := d.vertices[s]; !ok {
		return false
	}
	return true
}

// getVertexID gets the vertex id.
func (d *DAG) getVertexID(s string) string {
	if id, ok := d.vertices[s]; ok {
		return id
	}
	return ""
}
