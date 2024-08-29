// Copyright 2023 Adevinta

// Package scan implements the scan command.
package scan

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"time"

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

The exit code of the command depends on the correct execution of the
security scan and the highest severity among all the vulnerabilities
that have been found.

  -   0: No vulnerabilities found
  -   1: Command error
  -   2: Syntax error
  -   3: Check error
  -   4: Stale exclusions
  - 100: Informational vulnerabilities found
  - 101: Low severity vulnerabilities found
  - 102: Medium severity vulnerabilities found
  - 103: High severity vulnerabilities found
  - 104: Critical severity vulnerabilities found

Those vulnerabilities that has been excluded in the configuration are
not considered in the computation of the exit code. In other words,
vulnerabilities with a severity that is lower than "report.severity"
and vulnerabilities that match one or more "report.exclusions" rules
are ignored.

Lava supports several container runtimes. The environment variable
LAVA_RUNTIME allows to select which one is in use. For more details,
use "lava help environment".
	`,
}

// Command-line flags.
var scanC string // -c flag

func init() {
	CmdScan.Run = runScan // Break initialization cycle.
	CmdScan.Flag.StringVar(&scanC, "c", "lava.yaml", "config file")
}

// osExit is used by tests to capture the exit code.
var osExit = os.Exit

// debugReadBuildInfo is used by tests to set the command version.
var debugReadBuildInfo = debug.ReadBuildInfo

// runScan is the entry point of the scan command.
func runScan(args []string) error {
	exitCode, err := scan(args)
	if err != nil {
		return err
	}
	osExit(exitCode)
	return nil
}

// scan contains the logic of the [CmdScan] command. It is wrapped by
// the run function, so the deferred functions can be executed
// before calling [os.Exit]. It returns the exit code that must be
// passed to [os.Exit].
func scan(args []string) (int, error) {
	if len(args) > 0 {
		return 0, errors.New("too many arguments")
	}

	startTime := time.Now()
	metrics.Collect("start_time", startTime)

	cfg, err := config.Parse(scanC)
	if err != nil {
		return 0, fmt.Errorf("parse config file: %w", err)
	}

	base.LogLevel.Set(config.Get(cfg.LogLevel))

	bi, ok := debugReadBuildInfo()
	if !ok {
		return 0, errors.New("could not read build info")
	}

	// Config compatibility is not checked for development builds.
	if bi.Main.Version != "(devel)" && !cfg.IsCompatible(bi.Main.Version) {
		return 0, fmt.Errorf("minimum required version %v", cfg.LavaVersion)
	}

	metrics.Collect("lava_version", bi.Main.Version)
	metrics.Collect("config_version", config.Get(cfg.LavaVersion))
	metrics.Collect("checktype_urls", cfg.ChecktypeURLs)
	metrics.Collect("targets", cfg.Targets)
	metrics.Collect("severity", config.Get(cfg.ReportConfig.Severity))
	metrics.Collect("exclusion_count", len(cfg.ReportConfig.Exclusions))

	eng, err := engine.New(cfg.AgentConfig, cfg.ChecktypeURLs)
	if err != nil {
		return 0, fmt.Errorf("engine initialization: %w", err)
	}
	defer eng.Close()

	er, err := eng.Run(cfg.Targets)
	if err != nil {
		return 0, fmt.Errorf("engine run: %w", err)
	}

	rw, err := report.NewWriter(cfg.ReportConfig)
	if err != nil {
		return 0, fmt.Errorf("new writer: %w", err)
	}
	defer rw.Close()

	exitCode, err := rw.Write(er)
	if err != nil {
		return 0, fmt.Errorf("render report: %w", err)
	}

	metrics.Collect("exit_code", exitCode)
	metrics.Collect("duration", time.Since(startTime).Seconds())

	if metricsFile := config.Get(cfg.ReportConfig.Metrics); metricsFile != "" {
		if err = metrics.WriteFile(metricsFile); err != nil {
			return 0, fmt.Errorf("write metrics: %w", err)
		}
	}

	return int(exitCode), nil
}
