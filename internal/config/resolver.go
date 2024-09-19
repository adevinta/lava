// Copyright 2024 Adevinta

package config

import (
	"errors"
	"fmt"

	"github.com/adevinta/lava/internal/dag"
)

// ErrRootIncludeNotResolved is returned when the root config of the
// resolver cannot be resolved, typically because it does not exist.
var ErrRootIncludeNotResolved = errors.New("unable to resolve root include")

// resolver is the representation of the structure of includes.
type resolver struct {
	url  string
	root *include
	dag  *dag.DAG
}

// newResolver creates a new resolver that represents the whole configuration.
func newResolver(URL string) resolver {
	return resolver{
		url: URL,
	}
}

// resolve recursively finds all the includes for the root Include
// with the config provided, and the includes it depends on.
func (r *resolver) resolve() (cfg Config, err error) {
	r.dag = dag.NewDAG()
	r.root = &include{
		url:      r.url,
		resolver: r,
	}

	if _, err := r.dag.AddVertex(r.url); err != nil {
		return Config{}, fmt.Errorf("could not add vertex: %w", err)
	}

	if err := r.root.resolve(); err != nil {
		return Config{}, fmt.Errorf("could not resolve root: %w", err)
	}

	if !r.root.resolved {
		return Config{}, ErrRootIncludeNotResolved
	}
	return *r.root.cfg, nil
}
