// Copyright 2024 Adevinta

// lava-run-test is a Vulcan check used to test the lava run
// command. It justs reports one dummy critical vulnerability.
package main

import (
	"context"

	check "github.com/adevinta/vulcan-check-sdk"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const name = "lava-run-test"

func main() {
	c := check.NewCheckFromHandler(name, run)
	c.RunAndServe()
}

// run implements the lava run test check.
func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
	logger := check.NewCheckLog(name)
	logger.Printf("Starting the %v check", name)

	vuln := report.Vulnerability{
		Summary: "Lava run test",
		Score:   report.SeverityThresholdCritical,
	}
	state.AddVulnerabilities(vuln)

	return nil
}
