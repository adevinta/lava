// Copyright 2023 Adevinta

// Package assettype defines a set of asset types that are valid in
// the context of Lava.
package assettype

import (
	"slices"

	types "github.com/adevinta/vulcan-types"
)

// Lava asset types.
const (
	Path = types.AssetType("Path")
)

// vulcanMap is the mapping between Lava and Vulcan asset types.
var vulcanMap = map[types.AssetType]types.AssetType{
	Path: types.GitRepository,
}

// lavaTypes is the list of all Lava asset types.
var lavaTypes = []types.AssetType{Path}

// IsValid reports whether the provided asset type is valid in the
// context of Lava.
func IsValid(at types.AssetType) bool {
	return slices.Contains(lavaTypes, at)
}

// ToVulcan maps a Lava asset type to a Vulcan asset type. If there is
// no such mapping, the provided asset type is returned.
func ToVulcan(at types.AssetType) types.AssetType {
	if vt, ok := vulcanMap[at]; ok {
		return vt
	}
	return at
}
