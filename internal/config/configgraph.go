// Copyright 2024 Adevinta

package config

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"

	"github.com/adevinta/lava/internal/config/dag"
	"github.com/adevinta/lava/internal/urlutil"
)

// ConfigGraph is the representation of the structure of includes.
type ConfigGraph struct {
	dag     *dag.DAG
	configs map[string]Config
}

// NewConfigGraph creates a new [ConfigGraph] that represents the whole configuration.
func NewConfigGraph(url string) (ConfigGraph, error) {
	d := dag.New()
	configs := map[string]Config{}
	if err := discoverConfig(url, "", d, configs); err != nil {
		return ConfigGraph{}, fmt.Errorf("could not discover config %s: %w", url, err)
	}
	return ConfigGraph{
		dag:     d,
		configs: configs,
	}, nil
}

// discoverConfig explores the included configs to build the dag.
func discoverConfig(url, parent string, d *dag.DAG, configs map[string]Config) error {
	if !d.Contains(url) {
		_, err := d.AddVertex(url)
		if err != nil {
			return fmt.Errorf("could not add vertex: %w", err)
		}
	}
	// We don't add edges for the root url.
	if parent != "" {
		if err := d.AddEdge(parent, url); err != nil {
			return fmt.Errorf("could not add edge: %w", err)
		}
	}
	// Retrieve the parsed config of the include.
	data, err := urlutil.Get(url)
	if err != nil {
		return fmt.Errorf("could not resolve %s: %w", url, err)
	}
	r := bytes.NewReader(data)
	content, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read include config: %w", err)
	}
	cfg, err := Decode(content)
	if err != nil {
		return fmt.Errorf("could not decode include config: %w", err)
	}
	configs[url] = cfg

	unique := make(map[string]struct{})
	for _, incl := range cfg.Includes {
		// Skip duplicates.
		if _, ok := unique[incl]; ok {
			slog.Warn("config has been already included", "include", incl)
			continue
		}
		unique[incl] = struct{}{}
		if err = discoverConfig(incl, url, d, configs); err != nil {
			return fmt.Errorf("could not discover config %s: %w", incl, err)
		}
	}
	return nil
}

// Config returns a configuration for the given URL.
func (cg *ConfigGraph) Config(url string) (Config, error) {
	if cfg, ok := cg.configs[url]; ok {
		return cfg, nil
	}
	return Config{}, fmt.Errorf("could not find config for %s", url)
}

// Resolve walks the dag and merge the configuration.
func (cg *ConfigGraph) Resolve() Config {
	var cfg *Config
	cg.dag.DFSWalk(func(vertexID string, vertex interface{}) {
		vexCfg, err := cg.Config(vertex.(string))
		if err != nil {
			panic(err)
		}

		if cfg == nil {
			cfg = &vexCfg
			return
		}

		vexCfg, err = merge(vexCfg, *cfg)
		if err != nil {
			panic(err)
		}
		cfg = &vexCfg
	})
	return *cfg
}
