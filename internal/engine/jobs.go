// Copyright 2023 Adevinta

package engine

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"time"

	"github.com/adevinta/vulcan-agent/jobrunner"
	"github.com/adevinta/vulcan-agent/queue"
	types "github.com/adevinta/vulcan-types"
	"github.com/google/uuid"

	"github.com/adevinta/lava/internal/checktype"
	"github.com/adevinta/lava/internal/config"
)

// generateJobs generates the jobs to be sent to the agent.
func generateJobs(checktypes checktype.Catalog, targets []config.Target) ([]jobrunner.Job, error) {
	checks, err := generateChecks(checktypes, targets)
	if err != nil {
		return nil, fmt.Errorf("generate checks: %w", err)
	}

	var jobs []jobrunner.Job
	for _, check := range checks {
		// Convert the options to a marshalled json string.
		jsonOpts, err := json.Marshal(check.options)
		if err != nil {
			return nil, fmt.Errorf("encode check options: %w", err)
		}

		var reqVars []string
		if check.checktype.RequiredVars != nil {
			// TODO(sg): find out why the type of
			// github.com/adevinta/vulcan-check-catalog/pkg/model.Checktype.RequiredVars
			// is interface{}.
			ctReqVars, ok := check.checktype.RequiredVars.([]any)
			if !ok {
				return nil, fmt.Errorf("invalid required vars type: %#v", ctReqVars)
			}

			for _, rv := range ctReqVars {
				v, ok := rv.(string)
				if !ok {
					return nil, fmt.Errorf("invalid var type: %#v", rv)
				}
				reqVars = append(reqVars, v)
			}
		}

		jobs = append(jobs, jobrunner.Job{
			CheckID:      check.id,
			Image:        check.checktype.Image,
			Target:       check.target.Identifier,
			Timeout:      check.checktype.Timeout,
			AssetType:    string(check.target.AssetType),
			Options:      string(jsonOpts),
			RequiredVars: reqVars,
		})
	}
	return jobs, nil
}

// check represents an instance of a checktype.
type check struct {
	id        string
	checktype checktype.Checktype
	target    config.Target
	options   map[string]interface{}
}

// generateChecks generates a list of checks combining a map of
// checktypes and a list of targets. It returns an error if any of the
// targets has an invalid asset type.
func generateChecks(checktypes checktype.Catalog, targets []config.Target) ([]check, error) {
	ts, err := resolveTargets(targets)
	if err != nil {
		return nil, fmt.Errorf("resolve targets: %w", err)
	}

	var checks []check
	for _, t := range ts {
		for _, c := range checktypes {
			if !c.Accepts(t.AssetType) {
				continue
			}

			// Merge target and check options. Target
			// options take precedence for being more
			// restrictive.
			opts := make(map[string]interface{})
			maps.Copy(opts, c.Options)
			maps.Copy(opts, t.Options)
			checks = append(checks, check{
				id:        uuid.New().String(),
				checktype: c,
				target:    t,
				options:   opts,
			})
		}
	}
	return checks, nil
}

// resolveTargets returns a list of targets built using the target
// list passed as argument. The returned list contains all the targets
// with the asset type resolved and without duplicates. It returns an
// error if any of the identifiers has an invalid asset type.
func resolveTargets(targets []config.Target) ([]config.Target, error) {
	var ts []config.Target
	for _, target := range targets {
		if target.AssetType != "" {
			// The target has an asset type.
			if !contains(ts, target) {
				ts = append(ts, target)
			}
			continue
		}

		ats, err := types.DetectAssetTypes(target.Identifier)
		if err != nil {
			return nil, fmt.Errorf("resolve targets: %w", err)
		}

		for _, at := range ats {
			t := config.Target{
				Identifier: target.Identifier,
				AssetType:  at,
				Options:    target.Options,
			}
			if !contains(ts, t) {
				ts = append(ts, t)
			}
		}
	}
	return ts, nil
}

// contains reports whether v is present in s. It uses
// [reflect.DeepEqual] to compare elements.
func contains[S ~[]E, E any](s S, v E) bool {
	return slices.ContainsFunc(s, func(e E) bool {
		return reflect.DeepEqual(e, v)
	})
}

// sendJobs feeds the provided queue with jobs.
func sendJobs(jobs []jobrunner.Job, qw queue.Writer) error {
	for _, job := range jobs {
		job.StartTime = time.Now()
		bytes, err := json.Marshal(job)
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}
		if err := qw.Write(string(bytes)); err != nil {
			return fmt.Errorf("queue write: %w", err)
		}
	}
	return nil
}
