// Copyright 2023 Adevinta

// Package run implements the run command.
package run

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/adevinta/lava/cmd/lava/internal/base"
	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/engine"
	"github.com/adevinta/lava/internal/report"
)

// CmdRun represents the run command.
var CmdRun = &base.Command{
	UsageLine: "run [-c config.yaml]",
	Short:     "run scan",
	Long: `
Run a scan using the provided config file.

By default, "lava run" looks for a configuration file with the name
"lava.yaml" in the current directory. The -c flag allows to specify a
custom configuration file.
	`,
}

var cfgfile = CmdRun.Flag.String("c", "lava.yaml", "config file")

func init() {
	CmdRun.Run = run // Break initialization cycle.
}

// run is the entry point of the run command.
func run(args []string) error {
	if len(args) > 0 {
		return errors.New("too many arguments")
	}

	cfg, err := config.ParseFile(*cfgfile)
	if err != nil {
		return fmt.Errorf("parse config file: %w", err)
	}

	if err := os.Chdir(filepath.Dir(*cfgfile)); err != nil {
		return fmt.Errorf("change directory: %w", err)
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

	os.Exit(int(exitCode))

	return nil
}
