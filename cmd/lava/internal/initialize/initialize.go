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

var (
	cfgfile = CmdInit.Flag.String("c", "lava.yaml", "config file")
	force   = CmdInit.Flag.Bool("f", false, "overwrite config file")

	//go:embed default.yaml
	defaultConfig []byte
)

func init() {
	CmdInit.Run = run // Break initialization cycle.
}

// run is the entry point of the init command.
func run(args []string) error {
	if len(args) > 0 {
		return errors.New("too many arguments")
	}

	if !*force {
		_, err := os.Stat(*cfgfile)
		if err == nil {
			return fs.ErrExist
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("stat: %w", err)
		}
	}

	if err := os.WriteFile(*cfgfile, defaultConfig, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}
