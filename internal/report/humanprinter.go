// Copyright 2023 Adevinta

package report

import (
	_ "embed"
	"fmt"
	"io"
	"maps"
	"strings"
	"text/template"

	"github.com/fatih/color"

	"github.com/adevinta/lava/internal/config"
)

// humanPrinter represents a human-readable report printer.
type humanPrinter struct{}

// colorFuncs stores common function to colorize texts.
var colorFuncs = template.FuncMap{
	"magenta": color.New(color.FgMagenta).SprintfFunc(),
	"red":     color.New(color.FgRed).SprintfFunc(),
	"yellow":  color.New(color.FgYellow).SprintfFunc(),
	"cyan":    color.New(color.FgCyan).SprintfFunc(),
	"bold":    color.New(color.Bold).SprintfFunc(),
}

// Print renders the scan results in human-readable format.
func (prn humanPrinter) Print(w io.Writer, vulns []vulnerability, sum summary) error {
	if err := printSummary(w, sum); err != nil {
		return fmt.Errorf("print summary: %w", err)
	}
	if len(vulns) > 0 {
		_, err := fmt.Fprint(w, "\nVulnerabilities details:\n")
		if err != nil {
			return fmt.Errorf("print vulnerability details: %w", err)
		}
	}
	for _, v := range vulns {
		if err := printVulnerability(w, v); err != nil {
			return fmt.Errorf("print vulnerability: %w", err)
		}
	}
	return nil
}

//go:embed templates/humansum.tmpl
var humanSummary string

// printSummary renders the summary table with the vulnerability stats.
func printSummary(writer io.Writer, sum summary) error {
	var total int
	// count the total non-excluded vulnerabilities found.
	for _, ss := range sum.count {
		total += ss
	}

	type severityCount struct {
		Name  string
		Count int
	}

	var sevCounts []severityCount
	for sev := config.SeverityCritical; sev >= config.SeverityInfo; sev-- {
		sevCount := severityCount{
			Name:  sev.String(),
			Count: sum.count[sev],
		}
		sevCounts = append(sevCounts, sevCount)
	}

	data := struct {
		SevCounts []severityCount
		Total     int
		Excluded  int
	}{
		SevCounts: sevCounts,
		Total:     total,
		Excluded:  sum.excluded,
	}

	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
	}

	sumTmpl := template.New("summary")
	sumTmpl = sumTmpl.Funcs(funcMap).Funcs(colorFuncs)
	sumTmpl = template.Must(sumTmpl.Parse(humanSummary))
	if err := sumTmpl.Execute(writer, data); err != nil {
		return fmt.Errorf("execute template summary: %w", err)
	}
	return nil
}

//go:embed templates/humanvuln.tmpl
var humanVuln string

// printVulnerability renders a vulnerability in a human-readable format.
func printVulnerability(writer io.Writer, v vulnerability) error {
	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
	}
	maps.Copy(funcMap, colorFuncs)
	vulnTmpl := template.New("vulnerability")
	vulnTmpl = vulnTmpl.Funcs(funcMap).Funcs(colorFuncs)
	vulnTmpl = template.Must(vulnTmpl.Parse(humanVuln))
	if err := vulnTmpl.Execute(writer, v); err != nil {
		return fmt.Errorf("execute template vulnerability: %w", err)
	}
	return nil
}
