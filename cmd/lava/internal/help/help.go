// Copyright 2023 Adevinta

// Package help implements the help command.
package help

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/template"

	"github.com/adevinta/lava/cmd/lava/internal/base"
)

// Help prints the documentation of the provided command.
func Help(args []string) {
	if len(args) == 0 {
		PrintUsage(os.Stdout)
		return
	}
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: lava help <topic>\n\nToo many arguments given.\n")
		os.Exit(2)
	}

	arg := args[0]

	for _, cmd := range base.Commands {
		if cmd.Name() == arg {
			tmpl(os.Stdout, helpTemplate, cmd)
			return
		}
	}

	fmt.Fprintf(os.Stderr, "Unknown help topic %q. Run \"lava help\".\n", arg)
	os.Exit(2)
}

// PrintUsage prints a usage message documenting all the Lava
// commands.
func PrintUsage(w io.Writer) {
	tmpl(w, usageTemplate, base.Commands)
}

func tmpl(w io.Writer, text string, data interface{}) {
	t := template.New("top")
	t.Funcs(template.FuncMap{"trim": strings.TrimSpace})
	template.Must(t.Parse(text))
	if err := t.Execute(w, data); err != nil {
		panic(err)
	}
}

const usageTemplate = `Lava is a tool for running security checks in your local and CI/CD
environments.

Usage:

	lava <command> [arguments]

The commands are:
{{range .}}{{ if .Run}}
	{{.Name | printf "%-11s"}} {{.Short}}{{end}}{{end}}

Use "lava help <command>" for more information about a command.

Additional help topics:
{{range .}}{{if not .Run}}
	{{.Name | printf "%-11s"}} {{.Short}}{{end}}{{end}}

Use "lava help <topic>" for more information about that topic.
`

const helpTemplate = `{{if .Run}}Usage:

	lava {{.UsageLine}}

{{end}}{{.Long | trim}}
`
