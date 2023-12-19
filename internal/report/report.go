// Copyright 2023 Adevinta

// Package report renders Lava reports in different formats using the
// results returned by the Vulcan checks.
package report

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"

	report "github.com/adevinta/vulcan-report"

	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/engine"
	"github.com/adevinta/lava/internal/metrics"
)

// Writer represents a Lava report writer.
type Writer struct {
	prn         printer
	w           io.WriteCloser
	isStdout    bool
	minSeverity config.Severity
	exclusions  []config.Exclusion
}

// NewWriter creates a new instance of a report writer.
func NewWriter(cfg config.ReportConfig) (Writer, error) {
	var prn printer
	switch cfg.Format {
	case config.OutputFormatHuman:
		prn = humanPrinter{}
	case config.OutputFormatJSON:
		prn = jsonPrinter{}
	default:
		return Writer{}, errors.New("unsupported output format")
	}

	w := os.Stdout
	isStdout := true
	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			return Writer{}, fmt.Errorf("create file: %w", err)
		}
		w = f
		isStdout = false
	}

	return Writer{
		prn:         prn,
		w:           w,
		isStdout:    isStdout,
		minSeverity: cfg.Severity,
		exclusions:  cfg.Exclusions,
	}, nil
}

// Write renders the provided [engine.Report]. The returned exit code
// is calculated by evaluating the report with the [config.ReportConfig]
// passed to [NewWriter]. If the returned error is not nil, the exit code
// will be zero and should be ignored.
func (writer Writer) Write(er engine.Report) (ExitCode, error) {
	vulns, err := writer.parseReport(er)
	if err != nil {
		return 0, fmt.Errorf("parse report: %w", err)
	}

	summ, err := mkSummary(vulns)
	if err != nil {
		return 0, fmt.Errorf("calculate summary: %w", err)
	}

	metrics.Collect("excluded_vulnerability_count", summ.excluded)
	metrics.Collect("vulnerability_count", summ.count)

	fvulns := writer.filterVulns(vulns)
	status := mkStatus(er)
	exitCode := writer.calculateExitCode(summ, status)

	if err = writer.prn.Print(writer.w, fvulns, summ, status); err != nil {
		return exitCode, fmt.Errorf("print report: %w", err)
	}

	return exitCode, nil
}

// Close closes the [Writer].
func (writer Writer) Close() error {
	if !writer.isStdout {
		if err := writer.w.Close(); err != nil {
			return fmt.Errorf("close writer: %w", err)
		}
	}
	return nil
}

// parseReport converts the provided [engine.Report] into a list of
// vulnerabilities. It calculates the severity of each vulnerability
// based on its score and determines if the vulnerability is excluded
// according to the [Writer] configuration.
func (writer Writer) parseReport(er engine.Report) ([]vulnerability, error) {
	var vulns []vulnerability
	for _, r := range er {
		for _, vuln := range r.ResultData.Vulnerabilities {
			severity := scoreToSeverity(vuln.Score)
			excluded, err := writer.isExcluded(vuln, r.Target)
			if err != nil {
				return nil, fmt.Errorf("vulnerability exlusion: %w", err)
			}
			v := vulnerability{
				CheckData:     r.CheckData,
				Vulnerability: vuln,
				Severity:      severity,
				excluded:      excluded,
			}
			vulns = append(vulns, v)
		}
	}
	return vulns, nil
}

// isExcluded returns whether the provided [report.Vulnerability] is
// excluded based on the [Writer] configuration and the affected target.
func (writer Writer) isExcluded(v report.Vulnerability, target string) (bool, error) {
	for _, excl := range writer.exclusions {
		if excl.Fingerprint != "" && v.Fingerprint != excl.Fingerprint {
			continue
		}

		if excl.Summary != "" {
			matched, err := regexp.MatchString(excl.Summary, v.Summary)
			if err != nil {
				return false, fmt.Errorf("match string: %w", err)
			}
			if !matched {
				continue
			}
		}

		if excl.Target != "" {
			matched, err := regexp.MatchString(excl.Target, target)
			if err != nil {
				return false, fmt.Errorf("match string: %w", err)
			}
			if !matched {
				continue
			}
		}

		if excl.Resource != "" {
			matchedResource, err := regexp.MatchString(excl.Resource, v.AffectedResource)
			if err != nil {
				return false, fmt.Errorf("match string: %w", err)
			}
			matchedResourceString, err := regexp.MatchString(excl.Resource, v.AffectedResourceString)
			if err != nil {
				return false, fmt.Errorf("match string: %w", err)
			}
			if !matchedResource && !matchedResourceString {
				continue
			}
		}
		return true, nil
	}
	return false, nil
}

// filterVulns takes a list of vulnerabilities and filters out those
// vulnerabilities that should be excluded based on the [Writer]
// configuration.
func (writer Writer) filterVulns(vulns []vulnerability) []vulnerability {
	// Sort the results by severity in reverse order.
	slices.SortFunc(vulns, func(a, b vulnerability) int {
		return cmp.Compare(b.Severity, a.Severity)
	})

	fvulns := make([]vulnerability, 0)
	for _, v := range vulns {
		if v.Severity < writer.minSeverity {
			break
		}
		if v.excluded {
			continue
		}
		fvulns = append(fvulns, v)
	}
	return fvulns
}

// calculateExitCode returns an error code depending on the vulnerabilities found,
// as long as the severity of the vulnerabilities is higher or equal than the
// min severity configured in the writer. For that it makes use of the summary.
//
// See [ExitCode] for more information about exit codes.
func (writer Writer) calculateExitCode(summ summary, status []checkStatus) ExitCode {
	for _, cs := range status {
		if cs.Status != "FINISHED" {
			return ExitCodeCheckError
		}
	}

	for sev := config.SeverityCritical; sev >= writer.minSeverity; sev-- {
		if summ.count[sev] > 0 {
			diff := sev - config.SeverityInfo
			return ExitCodeInfo + ExitCode(diff)
		}
	}
	return 0
}

// vulnerability represents a vulnerability found by a check.
type vulnerability struct {
	report.Vulnerability
	CheckData report.CheckData `json:"check_data"`
	Severity  config.Severity  `json:"severity"`
	excluded  bool
}

// A printer renders a Vulcan report in a specific format.
type printer interface {
	Print(w io.Writer, vulns []vulnerability, summ summary, status []checkStatus) error
}

// scoreToSeverity converts a CVSS score into a [config.Severity].
// To calculate the severity we are using the [severity ratings]
// provided by the NVD.
//
// [severity ratings]: https://nvd.nist.gov/vuln-metrics/cvss
func scoreToSeverity(score float32) config.Severity {
	switch {
	case score >= 9.0:
		return config.SeverityCritical
	case score >= 7.0:
		return config.SeverityHigh
	case score >= 4.0:
		return config.SeverityMedium
	case score >= 0.1:
		return config.SeverityLow
	default:
		return config.SeverityInfo
	}
}

// summary represents the statistics of the results.
type summary struct {
	count    map[config.Severity]int
	excluded int
}

// mkSummary counts the number vulnerabilities per severity and the
// number of excluded vulnerabilities. The excluded vulnerabilities are
// not considered in the count per severity.
func mkSummary(vulns []vulnerability) (summary, error) {
	if len(vulns) == 0 {
		return summary{}, nil
	}

	summ := summary{
		count: make(map[config.Severity]int),
	}
	for _, vuln := range vulns {
		if !vuln.Severity.IsValid() {
			return summary{}, fmt.Errorf("invalid severity: %v", vuln.Severity)
		}
		if vuln.excluded {
			summ.excluded++
		} else {
			summ.count[vuln.Severity]++
		}
	}
	return summ, nil
}

// checkStatus represents the status of a check after the scan has
// finished.
type checkStatus struct {
	Checktype string
	Target    string
	Status    string
}

// mkStatus returns the status of every check after the scan has
// finished.
func mkStatus(er engine.Report) []checkStatus {
	var status []checkStatus
	for _, r := range er {
		cs := checkStatus{
			Checktype: r.ChecktypeName,
			Target:    r.Target,
			Status:    r.Status,
		}
		status = append(status, cs)
	}
	return status
}

// ExitCode represents an exit code depending on the vulnerabilities found.
type ExitCode int

// Exit codes depending on the maximum severity found.
const (
	ExitCodeCheckError ExitCode = 3
	ExitCodeInfo       ExitCode = 100
	ExitCodeLow        ExitCode = 101
	ExitCodeMedium     ExitCode = 102
	ExitCodeHigh       ExitCode = 103
	ExitCodeCritical   ExitCode = 104
)
