// Copyright 2023 Adevinta

// Package checktypes provides utilities for working with checktypes
// and chektype catalogs.
package checktypes

import (
	"encoding/json"
	"errors"
	"fmt"

	checkcatalog "github.com/adevinta/vulcan-check-catalog/pkg/model"
	types "github.com/adevinta/vulcan-types"

	"github.com/adevinta/lava/internal/urlutil"
)

// ErrMalformedCatalog is returned by [NewCatalog] when the format of
// the retrieved catalog is not valid.
var ErrMalformedCatalog = errors.New("malformed catalog")

// Accepts reports whether the specified checktype accepts an asset
// type.
func Accepts(ct checkcatalog.Checktype, at types.AssetType) bool {
	for _, accepted := range ct.Assets {
		if accepted == string(at) {
			return true
		}
	}
	return false
}

// Catalog represents a collection of Vulcan checktypes.
type Catalog map[string]checkcatalog.Checktype

// NewCatalog retrieves the specified checktype catalogs and
// consolidates them in a single catalog with all the checktypes
// indexed by name. If a checktype is duplicated it is overridden with
// the last one.
func NewCatalog(urls []string) (Catalog, error) {
	catalog := make(Catalog)
	for _, url := range urls {
		data, err := urlutil.Get(url)
		if err != nil {
			return nil, err
		}

		var decData struct {
			Checktypes []checkcatalog.Checktype `json:"checktypes"`
		}
		err = json.Unmarshal(data, &decData)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedCatalog, err)
		}

		for _, checktype := range decData.Checktypes {
			catalog[checktype.Name] = checktype
		}
	}
	return catalog, nil
}
