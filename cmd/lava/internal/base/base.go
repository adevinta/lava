// Copyright 2023 Adevinta

// Package base defines shared basic pieces of the Lava command, in
// particular logging and the Command structure.
package base

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// LogLevel is the level of the default logger.
var LogLevel = &slog.LevelVar{}

// Command represents a Lava command.
type Command struct {
	Run       func(args []string) error
	UsageLine string
	Short     string
	Long      string
	Flag      flag.FlagSet
}

// Commands is initialized with all the Lava commands.
var Commands []*Command

// Name returns the name of the command, which is the text before the
// first white space character in the UsageLine field.
func (c *Command) Name() string {
	name := c.UsageLine
	i := strings.Index(name, " ")
	if i >= 0 {
		name = name[:i]
	}
	return name
}

// Usage prints a usage message documenting the command.
func (c *Command) Usage() {
	fmt.Fprintf(os.Stderr, "usage: %s\n", c.UsageLine)
	fmt.Fprintf(os.Stderr, "Run \"lava help %s\" for details.\n", c.Name())
	os.Exit(2)
}
