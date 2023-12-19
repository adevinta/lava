// Copyright 2023 Adevinta

// Lava runs security checks locally.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/jroimartin/clilog"

	"github.com/adevinta/lava/cmd/lava/internal/base"
	"github.com/adevinta/lava/cmd/lava/internal/help"
	"github.com/adevinta/lava/cmd/lava/internal/initialize"
	"github.com/adevinta/lava/cmd/lava/internal/scan"
	"github.com/adevinta/lava/cmd/lava/internal/version"
)

func init() {
	base.Commands = []*base.Command{
		scan.CmdScan,
		initialize.CmdInit,
		version.CmdVersion,

		help.HelpLavaYAML,
		help.HelpMetrics,
	}
}

func main() {
	h := clilog.NewCLIHandler(os.Stderr, &clilog.HandlerOptions{Level: base.LogLevel})
	slog.SetDefault(slog.New(h))

	flag.Usage = help.PrintUsage
	flag.Parse() //nolint:errcheck

	args := flag.Args()
	if len(args) < 1 {
		help.PrintUsage()
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

	fmt.Fprintf(os.Stderr, "Unknown command %q. Run 'lava help'.\n", args[0])
	os.Exit(2)
}
