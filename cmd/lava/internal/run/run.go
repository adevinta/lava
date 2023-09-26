// Copyright 2023 Adevinta

// Package run implements the run command.
package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/adevinta/lava/cmd/lava/internal/base"
	"github.com/adevinta/lava/config"
	"github.com/adevinta/lava/engine"
)

// CmdRun represents the run command.
var CmdRun = &base.Command{
	UsageLine: "run [file.yaml]",
	Short:     "run scan",
	Long: `
Run a scan using the specified config file. If no config file is
provided, Lava defaults to a file named lava.yaml in the current
directory.
	`,
	Run: run,
}

// run is the entry point of the run command.
func run(args []string) error {
	var cfgfile string
	switch len(args) {
	case 0:
		cfgfile = "lava.yaml"
	case 1:
		cfgfile = args[0]
	default:
		return errors.New("too many arguments")
	}

	cfg, err := config.ParseFile(cfgfile)
	if err != nil {
		return fmt.Errorf("parse config file: %w", err)
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
