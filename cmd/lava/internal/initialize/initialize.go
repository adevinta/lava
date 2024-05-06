// Copyright 2023 Adevinta

// Package initialize implements the init command.
package initialize

import (
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/adevinta/lava/cmd/lava/internal/base"
)

// CmdInit represents the init command.
var CmdInit = &base.Command{
	UsageLine: "init [flags]",
	Short:     "init Lava project",
	Long: `
Initializes a Lava project.

This command creates a default Lava configuration file.

The -c flag allows to specify the name of the configuration file. By
default, a file with the name "lava.yaml" is created in the current
directory.

The -f flag allows to overwrite the output configuration file if it
exists.
	`,
}

// Command-line flags.
var (
	initC string // -c flag
	initF bool   // -f flag
)

//go:embed default.yaml
var defaultConfig []byte

func init() {
	CmdInit.Run = runInit // Break initialization cycle.
	CmdInit.Flag.StringVar(&initC, "c", "lava.yaml", "config file")
	CmdInit.Flag.BoolVar(&initF, "f", false, "overwrite config file")
}

// runInit is the entry point of the init command.
func runInit(args []string) error {
	if len(args) > 0 {
		return errors.New("too many arguments")
	}

	if !initF {
		_, err := os.Stat(initC)
		if err == nil {
			return fs.ErrExist
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("stat: %w", err)
		}
	}

	if err := os.WriteFile(initC, defaultConfig, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}
