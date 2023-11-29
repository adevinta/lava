// Copyright 2023 Adevinta

// Package help implements the help command.
package help

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/adevinta/lava/cmd/lava/internal/base"
)

// Help prints the documentation of the provided command.
func Help(args []string) {
	if len(args) == 0 {
		PrintUsage()
		return
	}
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: lava help <topic>\n\nToo many arguments given.\n")
		os.Exit(2)
	}

	arg := args[0]

	for _, cmd := range base.Commands {
		if cmd.Name() == arg {
			tmpl(helpTemplate, cmd)
			return
		}
	}

	fmt.Fprintf(os.Stderr, "Unknown help topic %q. Run 'lava help'.\n", arg)
	os.Exit(2)
}

// PrintUsage prints a usage message documenting all the Lava
// commands.
func PrintUsage() {
	tmpl(usageTemplate, base.Commands)
}

func tmpl(text string, data interface{}) {
	t := template.New("top")
	t.Funcs(template.FuncMap{"trim": strings.TrimSpace})
	template.Must(t.Parse(text))
	if err := t.Execute(os.Stderr, data); err != nil {
		panic(err)
	}
}

const usageTemplate = `Lava runs Vulcan checks locally

Usage:

	lava <command> [arguments]

The commands are:
{{range .}}{{ if .Run}}
	{{.Name | printf "%-11s"}} {{.Short}}{{end}}{{end}}

Use 'lava help <command>' for more information about a command.

Additional help topics:
{{range .}}{{if not .Run}}
	{{.Name | printf "%-11s"}} {{.Short}}{{end}}{{end}}

Use 'lava help <topic>' for more information about that topic.
`

const helpTemplate = `{{if .Run}}usage: lava {{.UsageLine}}

{{end}}{{.Long | trim}}
`
