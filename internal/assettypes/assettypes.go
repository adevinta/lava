// Copyright 2023 Adevinta

// Package assettypes defines a set of asset types that are valid in
// the context of Lava.
package assettypes

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"

	types "github.com/adevinta/vulcan-types"
)

// ErrUnsupported is returned when the requested operation does not
// support the specified asset type.
var ErrUnsupported = errors.New("unsupported asset type")

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

// CheckReachable checks if the asset with the specified type and
// identifier is reachable. CheckReachable does not check if the asset
// is functional. If the asset is reachable, it returns a nil
// error. If the asset is unreachable, it returns an error explaining
// the cause. If the asset type is not supported, it returns an
// [ErrUnsupported] error. If the reachability test fails, it returns
// the error that caused the failure.
func CheckReachable(typ types.AssetType, ident string) error {
	switch typ {
	case types.GitRepository:
		info, err := os.Stat(ident)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// If the path does not exist, assume
				// it is a remote Git repository and,
				// thus, reachability test is not
				// supported.
				return ErrUnsupported
			}
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("not a directory")
		}
	case Path:
		if _, err := os.Stat(ident); err != nil {
			return err
		}
	default:
		return ErrUnsupported
	}
	return nil
}
