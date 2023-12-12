// Copyright 2023 Adevinta

// Package scan implements the scan command.
package scan

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"

	"github.com/adevinta/lava/cmd/lava/internal/base"
	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/engine"
	"github.com/adevinta/lava/internal/metrics"
	"github.com/adevinta/lava/internal/report"
)

// CmdScan represents the scan command.
var CmdScan = &base.Command{
	UsageLine: "scan [flags]",
	Short:     "run scan",
	Long: `
Run a scan using the provided config file.

The -c flag allows to specify a configuration file. By default, "lava
scan" looks for a configuration file with the name "lava.yaml" in the
current directory.

The -forcecolor flag forces colorized output. By default, colorized
output is disabled in the following cases:

  - Lava is not executed from a terminal.
  - Lava is executed from a "dumb" terminal.
  - The NO_COLOR environment variable is set (regardless of its value).

The exit code of the command depends on the highest severity among all
the vulnerabilities that have been found.

  - 104: Critical severity vulnerabilities found
  - 103: High severity vulnerabilities found
  - 102: Medium severity vulnerabilities found
  - 101: Low severity vulnerabilities found
  - 100: Informational vulnerabilities found
  -   2: Syntax error
  -   1: Command error
  -   0: No vulnerabilities found

Those vulnerabilities that has been excluded in the configuration are
not considered in the computation of the exit code. In other words,
vulnerabilities with a severity that is lower than "report.severity"
and vulnerabilities that match any "report.exclusions" rules are
ignored.
	`,
}

var (
	cfgfile    = CmdScan.Flag.String("c", "lava.yaml", "config file")
	forceColor = CmdScan.Flag.Bool("forcecolor", false, "force colorized output")
)

func init() {
	CmdScan.Run = run // Break initialization cycle.
}

// osExit is used by tests to capture the exit code.
var osExit = os.Exit

// run is the entry point of the scan command.
func run(args []string) error {
	if len(args) > 0 {
		return errors.New("too many arguments")
	}

	if *forceColor {
		color.NoColor = false
	}

	executionTime := time.Now()
	metrics.Collect("execution_time", executionTime)

	cfg, err := config.ParseFile(*cfgfile)
	if err != nil {
		return fmt.Errorf("parse config file: %w", err)
	}

	metrics.Collect("lava_version", cfg.LavaVersion)
	metrics.Collect("targets", cfg.Targets)

	base.LogLevel.Set(cfg.LogLevel)
	er, err := engine.Run(cfg.ChecktypeURLs, cfg.Targets, cfg.AgentConfig)
	if err != nil {
		return fmt.Errorf("engine run: %w", err)
	}

	rw, err := report.NewWriter(cfg.ReportConfig)
	if err != nil {
		return fmt.Errorf("new writer: %w", err)
	}
	defer rw.Close()

	exitCode, err := rw.Write(er)
	if err != nil {
		return fmt.Errorf("render report: %w", err)
	}

	metrics.Collect("exit_code", exitCode)
	duration := time.Since(executionTime)
	metrics.Collect("duration", duration.String())

	if cfg.ReportConfig.Metrics != "" {
		if err = metrics.WriteFile(cfg.ReportConfig.Metrics); err != nil {
			return fmt.Errorf("write metrics: %w", err)
		}
	}

	osExit(int(exitCode))

	return nil
}
