// Copyright 2023 Adevinta

// Package version implements the version command.
package version

import (
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/adevinta/lava/cmd/lava/internal/base"
)

// CmdVersion represents the version command.
var CmdVersion = &base.Command{
	UsageLine: "version",
	Short:     "print Lava version",
	Long: `
Version prints the version of the Lava command.
	`,
}

func init() {
	CmdVersion.Run = run // Break initialization cycle.
}

// run is the entry point of the version command.
func run(args []string) error {
	if len(args) > 0 {
		return errors.New("too many arguments")
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("could not read build info")
	}

	fmt.Printf("Lava version %v\n", bi.Main.Version)
	return nil
}
