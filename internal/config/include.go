// Copyright 2024 Adevinta

package config

import (
	"bytes"
	"fmt"

	"github.com/adevinta/lava/internal/urlutil"
)

// include represents every include reference in a config file.
type include struct {
	url      string
	resolved bool
	resolver *resolver
	cfg      *Config
	parent   *include
	includes []include
}

// Resolve parses the configuration of an include recursively.
func (in *include) resolve() error {
	// resolved is always true, regardless of if we skip the include,
	// it is only false if there is an error while importing.
	in.resolved = true
	url := in.url
	if url == "" {
		return fmt.Errorf("no URL provided")
	}
	cfg, err := parseInclude(url)
	if err != nil {
		in.resolved = false
		return fmt.Errorf("parse include: %w", err)
	}
	in.cfg = cfg
	unique := make(map[string]struct{})
	if err := in.setIncludes(in.cfg.Includes, unique); err != nil {
		in.resolved = false
		return fmt.Errorf("set includes: %w", err)
	}
	return nil
}

// setIncludes sets the includes skipping the duplicate ones.
func (in *include) setIncludes(includes []string, unique map[string]struct{}) error {
	for _, incl := range includes {
		// Skip duplicates.
		if _, ok := unique[incl]; ok {
			continue
		}
		unique[incl] = struct{}{}
		if err := in.addInclude(incl); err != nil {
			return fmt.Errorf("could not add include %q: %w", incl, err)
		}
	}
	return nil
}

// addIncludes adds a new include to the graph and resolves it.
func (in *include) addInclude(URL string) error {
	incl := include{
		url:      URL,
		parent:   in,
		resolver: in.resolver,
	}
	if !in.resolver.dag.HasVertexBeenAdded(URL) {
		_, err := in.resolver.dag.AddVertex(URL)
		if err != nil {
			return fmt.Errorf("could not add vertex: %w", err)
		}
	}
	if err := in.resolver.dag.AddEdge(in.url, URL); err != nil {
		return fmt.Errorf("could not add edge: %w", err)
	}
	if err := incl.resolve(); err != nil {
		return fmt.Errorf("could not resolve %q: %w", incl.url, err)
	}
	in.includes = append(in.includes, incl)
	return nil
}

// parseInclude parses the configuration corresponding to an include file.
func parseInclude(url string) (*Config, error) {
	data, err := urlutil.Get(url)
	if err != nil {
		return nil, fmt.Errorf("could not resolve %s: %w", url, err)
	}
	cfg, err := Parse(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", url, err)
	}
	return &cfg, nil
}
