// Copyright 2024 Adevinta

package config

import (
	"fmt"

	"dario.cat/mergo"
)

// merge merges two configurations. The values of the configuration
// passed as first parameter will be overridden by those in the
// configuration passed as second parameter avoiding overriding with
// nil values.
func merge(dst, src Config) (Config, error) {
	merged := Config{}
	mergeOpts := []func(*mergo.Config){
		mergo.WithOverride,
		mergo.WithoutDereference,
		mergo.WithAppendSlice,
	}
	if err := mergo.Merge(&merged, dst, mergeOpts...); err != nil {
		return Config{}, fmt.Errorf("merging dst config into new config: %w", err)
	}
	if err := mergo.Merge(&merged, src, mergeOpts...); err != nil {
		return Config{}, fmt.Errorf("merging src config into new config: %w", err)
	}
	return merged, nil
}
