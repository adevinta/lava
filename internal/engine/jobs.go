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
	checkcatalog "github.com/adevinta/vulcan-check-catalog/pkg/model"
	"github.com/google/uuid"

	"github.com/adevinta/lava/internal/assettypes"
	"github.com/adevinta/lava/internal/checktypes"
	"github.com/adevinta/lava/internal/config"
)

// generateJobs generates the jobs to be sent to the agent.
func generateJobs(catalog checktypes.Catalog, targets []config.Target) ([]jobrunner.Job, error) {
	var jobs []jobrunner.Job
	for _, check := range generateChecks(catalog, targets) {
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
	checktype checkcatalog.Checktype
	target    config.Target
	options   map[string]interface{}
}

// generateChecks generates a list of checks combining a map of
// checktypes and a list of targets.
func generateChecks(catalog checktypes.Catalog, targets []config.Target) []check {
	var checks []check
	for _, t := range dedup(targets) {
		for _, ct := range catalog {
			at := assettypes.ToVulcan(t.AssetType)
			if !checktypes.Accepts(ct, at) {
				continue
			}

			// Merge target and check options. Target
			// options take precedence for being more
			// restrictive.
			opts := make(map[string]interface{})
			maps.Copy(opts, ct.Options)
			maps.Copy(opts, t.Options)
			checks = append(checks, check{
				id:        uuid.New().String(),
				checktype: ct,
				target:    t,
				options:   opts,
			})
		}
	}
	return checks
}

// dedup returns a deduplicated slice.
func dedup[S ~[]E, E any](s S) S {
	var ret S
	for _, v := range s {
		if !contains(ret, v) {
			ret = append(ret, v)
		}
	}
	return ret
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
