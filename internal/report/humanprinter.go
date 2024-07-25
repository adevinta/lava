// Copyright 2023 Adevinta

package report

import (
	_ "embed"
	"fmt"
	"io"
	"strings"
	"text/template"

	"github.com/fatih/color"

	"github.com/adevinta/lava/internal/config"
)

// humanView represents the human-readable view of the report.
type humanView struct {
	Stats    map[string]int
	Total    int
	Excluded int
	Vulns    []repVuln
	Status   []checkStatus
}

// humanPrinter represents a human-readable report printer.
type humanPrinter struct{}

var (
	//go:embed human.tmpl
	humanReport string

	// humanTmplFuncs stores the functions called from the
	// template used to render the human-readable report.
	humanTmplFuncs = template.FuncMap{
		"magenta":   color.New(color.FgMagenta).SprintfFunc(),
		"red":       color.New(color.FgRed).SprintfFunc(),
		"yellow":    color.New(color.FgYellow).SprintfFunc(),
		"cyan":      color.New(color.FgCyan).SprintfFunc(),
		"bold":      color.New(color.Bold).SprintfFunc(),
		"underline": color.New(color.Underline).SprintfFunc(),
		"upper":     strings.ToUpper,
		"trim":      strings.TrimSpace,
	}

	// humanTmpl is the template used to render the human-readable
	// report.
	humanTmpl = template.Must(template.New("").Funcs(humanTmplFuncs).Parse(humanReport))
)

// Print renders the scan results in a human-readable format.
func (prn humanPrinter) Print(w io.Writer, vulns []repVuln, summ summary, status []checkStatus) error {
	// count the total non-excluded vulnerabilities found.
	var total int
	for _, ss := range summ.Count {
		total += ss
	}

	stats := make(map[string]int)
	for s := config.SeverityCritical; s >= config.SeverityInfo; s-- {
		stats[s.String()] = summ.Count[s]
	}

	data := humanView{
		Stats:    stats,
		Total:    total,
		Excluded: summ.Excluded,
		Vulns:    vulns,
		Status:   status,
	}
	if err := humanTmpl.Execute(w, data); err != nil {
		return fmt.Errorf("execute template summary: %w", err)
	}

	return nil
}
