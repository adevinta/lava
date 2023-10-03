// Copyright 2023 Adevinta

// Package run implements the run command.
package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/adevinta/lava/cmd/lava/internal/base"
	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/engine"
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

	report, err := engine.Run(cfg.ChecktypesURLs, cfg.Targets, cfg.AgentConfig)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	// TODO(rm): show report and exit with the proper exit code.
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}

	return nil
}
