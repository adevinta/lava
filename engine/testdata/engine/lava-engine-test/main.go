// Copyright 2023 Adevinta

// lava-engine-test is a Vulcan check used to test the engine package.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	check "github.com/adevinta/vulcan-check-sdk"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const name = "lava-engine-test"

func main() {
	c := check.NewCheckFromHandler(name, run)
	c.RunAndServe()
}

// run implements the Lava engine test check.
func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
	logger := check.NewCheckLog(name)
	logger.Printf("Starting the %v check", name)

	if target == "" {
		return errors.New("no target provided")
	}

	resp, err := http.Get(target)
	if err != nil {
		return fmt.Errorf("HTTP get: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	vuln := report.Vulnerability{
		Summary: "Lava engine test",
		Details: string(body),
		Score:   report.SeverityThresholdNone,
	}
	state.AddVulnerabilities(vuln)

	return nil
}
