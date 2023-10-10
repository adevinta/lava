// Copyright 2023 Adevinta

package report

import (
	"fmt"
	"io"
	"strings"
	"text/template"

	"github.com/adevinta/lava/internal/config"
)

// userPrinter represents a user-friendly report printer.
type userPrinter struct{}

// Print renders the scan results in user-friendly format.
func (prn userPrinter) Print(w io.Writer, vulns []vulnerability, sum summary) error {
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

// printSummary renders the summary table with the vulnerabilities stats.
func printSummary(writer io.Writer, sum summary) error {
	var total int
	// count the total non-excluded vulnerabilities found.
	for _, ss := range sum.count {
		total = +ss
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

	sumT := template.New("summary")
	sumT, err := sumT.Parse(`
Summary of the last scan:
{{if not .Total}}
No vulnerabilities found during the Lava scan.{{end -}}
{{else}}
{{range .SevCounts}}
  {{- .Name}}: {{.Count}}
{{end}}
Number of excluded vulnerabilities not included in the summary table: {{.Excluded}}
{{end}}
`)
	if err != nil {
		return fmt.Errorf("parse template summary: %w", err)
	}
	if err = sumT.Execute(writer, data); err != nil {
		return fmt.Errorf("execute template summary: %w", err)
	}
	return nil
}

// printVulnerability renders a vulnerability in a user-friendly wat.
func printVulnerability(writer io.Writer, v vulnerability) error {
	funcMap := template.FuncMap{
		"ToUpper": strings.ToUpper,
		"Join":    strings.Join,
	}

	vulnT := template.New("vulnerability")
	vulnT, err := vulnT.Funcs(funcMap).Parse(`
=====================================================
{{.Severity.String | ToUpper}}
=====================================================
TARGET:
  {{.CheckData.Target }}
{{$affectedResource:= .AffectedResourceString -}}
{{if not $affectedResource -}}
{{$affectedResource = .AffectedResource -}}
{{end -}}
{{if $affectedResource}}
AFFECTED RESOURCE:
  {{$affectedResource}}
{{end}}
SUMMARY:
  {{.Summary}}

DESCRIPTION:
  {{.Description}}

{{if .Details -}}

DETAILS:
  {{.Details}}
{{end -}}
{{if .ImpactDetails}}
IMPACT:
  {{ .ImpactDetails}}
{{- end}}
{{if gt (len .Recommendations) 0}}
RECOMMENDATIONS:
{{range .Recommendations -}}
  - {{.}}
{{end -}}
{{end -}}
{{if gt (len .References) 0}}
REFERENCES:
{{range .References -}}
  - {{.}}
{{end -}}
{{end -}}
{{if gt (len .Resources) 0 -}}
{{range $resource := .Resources}}
{{.Name}}:
{{$headers := .Header -}}
{{range $row := .Rows}}
{{range $header := $headers -}}
  {{$header }}: {{index $row $header}}
{{end -}}
{{end -}}
{{end -}}
{{end -}}
`)
	if err != nil {
		return fmt.Errorf("parse template vulnerability: %w", err)
	}
	if err = vulnT.Execute(writer, v); err != nil {
		return fmt.Errorf("execute template vulnerability: %w", err)
	}
	return nil
}
