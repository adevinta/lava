// Copyright 2023 Adevinta

// Package run implements the run command.
package run

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"

	"github.com/adevinta/lava/cmd/lava/internal/base"
	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/engine"
	"github.com/adevinta/lava/internal/metrics"
	"github.com/adevinta/lava/internal/report"
)

// CmdRun represents the run command.
var CmdRun = &base.Command{
	UsageLine: "run [flags]",
	Short:     "run scan",
	Long: `
Run a scan using the provided config file.

The -c flag allows to specify a configuration file. By default, "lava
run" looks for a configuration file with the name "lava.yaml" in the
current directory.

The -forcecolor flag forces colorized output. By default, colorized
output is disabled in the following cases:

- Lava is not executed from a terminal.
- Lava is executed from a "dumb" terminal.
- The NO_COLOR environment variable is set (regardless of its value).
	`,
}

var (
	cfgfile     = CmdRun.Flag.String("c", "lava.yaml", "config file")
	forceColor  = CmdRun.Flag.Bool("forcecolor", false, "force colorized output")
	metricsFile = CmdRun.Flag.String("m", "", "metrics output file")
)

func init() {
	CmdRun.Run = run // Break initialization cycle.
}

// run is the entry point of the run command.
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

	if err = os.Chdir(filepath.Dir(*cfgfile)); err != nil {
		return fmt.Errorf("change directory: %w", err)
	}
	metrics.Collect("lava_version", cfg.LavaVersion)
	metrics.Collect("targets", cfg.Targets)
	if os.Getenv("GITHUB_SERVER_URL") != "" && os.Getenv("GITHUB_REPOSITORY") != "" {
		ghRepo, err := url.JoinPath(os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"))
		if err != nil {
			slog.Warn("error collecting the GitHub repo URI")
		} else {
			metrics.Collect("repository_uri", ghRepo)
		}
	}

	base.LogLevel.Set(cfg.LogLevel)
	er, err := engine.Run(cfg.ChecktypesURLs, cfg.Targets, cfg.AgentConfig)
	if err != nil {
		return fmt.Errorf("run: %w", err)
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
	finishTime := time.Now()
	duration := finishTime.Sub(executionTime)
	metrics.Collect("duration", duration.String())

	if *metricsFile != "" {
		if err = metrics.Write(*metricsFile); err != nil {
			return fmt.Errorf("write metrics: %w", err)
		}
	}
	os.Exit(int(exitCode))

	return nil
}
