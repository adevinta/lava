// Copyright 2023 Adevinta

// Lava is a tool for running security checks in your local and CI/CD
// environments.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/fatih/color"
	"github.com/jroimartin/clilog"

	"github.com/adevinta/lava/cmd/lava/internal/base"
	"github.com/adevinta/lava/cmd/lava/internal/help"
	"github.com/adevinta/lava/cmd/lava/internal/initialize"
	"github.com/adevinta/lava/cmd/lava/internal/run"
	"github.com/adevinta/lava/cmd/lava/internal/scan"
	"github.com/adevinta/lava/cmd/lava/internal/version"
)

func init() {
	base.Commands = []*base.Command{
		scan.CmdScan,
		run.CmdRun,
		initialize.CmdInit,
		version.CmdVersion,

		help.HelpEnvironment,
		help.HelpLavaYAML,
		help.HelpMetrics,
		help.HelpChecktypes,
	}
}

func main() {
	h := clilog.NewCLIHandler(os.Stderr, &clilog.HandlerOptions{Level: base.LogLevel})
	slog.SetDefault(slog.New(h))

	flag.Usage = func() {
		help.PrintUsage(os.Stderr)
	}
	flag.Parse() //nolint:errcheck

	args := flag.Args()
	if len(args) < 1 {
		help.PrintUsage(os.Stderr)
		os.Exit(2)
	}

	if err := parseEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if args[0] == "help" {
		help.Help(args[1:])
		return
	}

	for _, cmd := range base.Commands {
		if cmd.Run == nil {
			continue
		}
		cmd.Flag.Usage = cmd.Usage
		if cmd.Name() == args[0] {
			cmd.Flag.Parse(args[1:]) //nolint:errcheck
			args = cmd.Flag.Args()
			if err := cmd.Run(args); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	fmt.Fprintf(os.Stderr, "Unknown command %q. Run \"lava help\".\n", args[0])
	os.Exit(2)
}

func parseEnv() error {
	if envForceColor := os.Getenv("LAVA_FORCECOLOR"); envForceColor != "" {
		forceColor, err := strconv.ParseBool(envForceColor)
		if err != nil {
			return fmt.Errorf("invalid LAVA_FORCECOLOR value: %v", envForceColor)
		}
		color.NoColor = !forceColor
	}
	return nil
}
