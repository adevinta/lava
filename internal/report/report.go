// Copyright 2023 Adevinta

// Package report renders Lava reports in different formats using the
// results returned by the Vulcan checks.
package report

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"time"

	report "github.com/adevinta/vulcan-report"

	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/engine"
	"github.com/adevinta/lava/internal/metrics"
)

// WriterConfig contains the configuration parameters of a [Writer].
type WriterConfig struct {
	// ReportConfig is the configuration of the report.
	ReportConfig config.ReportConfig

	// FullReportFile is the path of the full report output
	// file. If empty, the full report file is not generated.
	FullReportFile string
}

// Writer represents a Lava report writer.
type Writer struct {
	prn            printer
	reportFile     *os.File
	minSeverity    config.Severity
	showSeverity   config.Severity
	exclusions     []config.Exclusion
	fullReportFile *os.File
}

// timeNow is set by tests to mock the current time.
var timeNow = time.Now

// NewWriter creates a new instance of a report writer.
func NewWriter(cfg WriterConfig) (Writer, error) {
	var prn printer
	switch cfg.ReportConfig.Format {
	case config.OutputFormatHuman:
		prn = humanPrinter{}
	case config.OutputFormatJSON:
		prn = jsonPrinter{}
	default:
		return Writer{}, errors.New("unsupported output format")
	}

	reportFile := os.Stdout
	if cfg.ReportConfig.OutputFile != "" {
		f, err := os.Create(cfg.ReportConfig.OutputFile)
		if err != nil {
			return Writer{}, fmt.Errorf("create output file: %w", err)
		}
		reportFile = f
	}

	var fullReportFile *os.File
	if cfg.FullReportFile != "" {
		f, err := os.Create(cfg.FullReportFile)
		if err != nil {
			return Writer{}, fmt.Errorf("create full report file: %w", err)
		}
		fullReportFile = f
	}

	var showSeverity config.Severity
	if cfg.ReportConfig.ShowSeverity != nil {
		showSeverity = *cfg.ReportConfig.ShowSeverity
	} else {
		showSeverity = cfg.ReportConfig.Severity
	}

	return Writer{
		prn:            prn,
		reportFile:     reportFile,
		fullReportFile: fullReportFile,
		minSeverity:    cfg.ReportConfig.Severity,
		showSeverity:   showSeverity,
		exclusions:     cfg.ReportConfig.Exclusions,
	}, nil
}

// Write renders the provided [engine.Report]. If a full report file
// has been specified, the internal data used to generate the report
// will be written to it. The returned exit code is calculated by
// evaluating the report with the [config.ReportConfig] passed to
// [NewWriter]. If the returned error is not nil, the exit code will
// be zero and should be ignored.
func (writer Writer) Write(er engine.Report) (ExitCode, error) {
	vulns, err := writer.parseReport(er)
	if err != nil {
		return 0, fmt.Errorf("parse report: %w", err)
	}

	summ, err := mkSummary(vulns)
	if err != nil {
		return 0, fmt.Errorf("calculate summary: %w", err)
	}

	metrics.Collect("excluded_vulnerability_count", summ.Excluded)
	metrics.Collect("vulnerability_count", summ.Count)

	fvulns := writer.filterVulns(vulns)
	status := mkStatus(er)
	exitCode := writer.calculateExitCode(summ, status)

	if err := writer.prn.Print(writer.reportFile, fvulns, summ, status); err != nil {
		return 0, fmt.Errorf("print report: %w", err)
	}

	if writer.fullReportFile != nil {
		if err := writeFullReport(writer.fullReportFile, vulns, summ, status); err != nil {
			return 0, fmt.Errorf("write full report: %w", err)
		}
	}

	return exitCode, nil
}

// Close closes the [Writer].
func (writer Writer) Close() error {
	if writer.reportFile != os.Stdout {
		if err := writer.reportFile.Close(); err != nil {
			return fmt.Errorf("close report file: %w", err)
		}
	}
	if writer.fullReportFile != nil {
		if err := writer.fullReportFile.Close(); err != nil {
			return fmt.Errorf("close full report file: %w", err)
		}
	}
	return nil
}

// parseReport converts the provided [engine.Report] into a list of
// vulnerabilities. It calculates the severity of each vulnerability
// based on its score and determines if the vulnerability is excluded
// according to the [Writer] configuration.
func (writer Writer) parseReport(er engine.Report) ([]metaVuln, error) {
	var vulns []metaVuln
	for _, r := range er {
		for _, vuln := range r.ResultData.Vulnerabilities {
			severity := scoreToSeverity(vuln.Score)
			excluded, ruleIdx, err := writer.isExcluded(vuln, r.Target)
			if err != nil {
				return nil, fmt.Errorf("vulnerability exlusion: %w", err)
			}
			var rule *config.Exclusion
			if excluded {
				rule = &writer.exclusions[ruleIdx]
			}
			shown := !excluded && severity >= writer.showSeverity
			v := metaVuln{
				repVuln: repVuln{
					CheckData:     r.CheckData,
					Vulnerability: vuln,
					Severity:      severity,
				},
				Shown:         shown,
				Excluded:      excluded,
				ExclusionRule: rule,
			}
			vulns = append(vulns, v)
		}
	}
	return vulns, nil
}

// isExcluded returns whether the provided [report.Vulnerability] is
// excluded based on the [Writer] configuration and the affected
// target. If the vulnerability is excluded, the index of the matching
// rule is returned.
func (writer Writer) isExcluded(v report.Vulnerability, target string) (excluded bool, rule int, err error) {
	for i, excl := range writer.exclusions {
		if excl.ExpirationDate != nil && excl.ExpirationDate.Before(timeNow()) {
			continue
		}

		if excl.Fingerprint != "" && v.Fingerprint != excl.Fingerprint {
			continue
		}

		if excl.Summary != "" {
			matched, err := regexp.MatchString(excl.Summary, v.Summary)
			if err != nil {
				return false, 0, fmt.Errorf("match string: %w", err)
			}
			if !matched {
				continue
			}
		}

		if excl.Target != "" {
			matched, err := regexp.MatchString(excl.Target, target)
			if err != nil {
				return false, 0, fmt.Errorf("match string: %w", err)
			}
			if !matched {
				continue
			}
		}

		if excl.Resource != "" {
			matchedResource, err := regexp.MatchString(excl.Resource, v.AffectedResource)
			if err != nil {
				return false, 0, fmt.Errorf("match string: %w", err)
			}
			matchedResourceString, err := regexp.MatchString(excl.Resource, v.AffectedResourceString)
			if err != nil {
				return false, 0, fmt.Errorf("match string: %w", err)
			}
			if !matchedResource && !matchedResourceString {
				continue
			}
		}
		return true, i, nil
	}
	return false, 0, nil
}

// filterVulns takes a list of vulnerabilities and filters out those
// vulnerabilities that should be excluded from the report based on
// the [Writer] configuration.
func (writer Writer) filterVulns(vulns []metaVuln) []repVuln {
	// Sort the results by severity in reverse order.
	vs := make([]metaVuln, len(vulns))
	copy(vs, vulns)
	slices.SortFunc(vs, func(a, b metaVuln) int {
		return cmp.Compare(b.Severity, a.Severity)
	})

	fvulns := make([]repVuln, 0)
	for _, v := range vs {
		if v.Severity < writer.showSeverity {
			break
		}
		if v.Excluded {
			continue
		}
		fvulns = append(fvulns, v.repVuln)
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
		if summ.Count[sev] > 0 {
			diff := sev - config.SeverityInfo
			return ExitCodeInfo + ExitCode(diff)
		}
	}
	return 0
}

// repVuln represents a vulnerability of the report.
type repVuln struct {
	report.Vulnerability
	CheckData report.CheckData `json:"check_data"`
	Severity  config.Severity  `json:"severity"`
}

// metaVuln adds metadata to [repVuln].
type metaVuln struct {
	repVuln

	// Shown specifies whether the vulnerability is shown in the
	// report.
	Shown bool `json:"shown"`

	// Excluded specifies whether the vulnerability is excluded
	// from the generated report.
	Excluded bool `json:"excluded"`

	// ExclusionRule is the matching exclusion rule in the case of
	// an excluded finding.
	ExclusionRule *config.Exclusion `json:"exclusion_rule,omitempty"`
}

// A printer renders a Vulcan report in a specific format.
type printer interface {
	Print(w io.Writer, vulns []repVuln, summ summary, status []checkStatus) error
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
	Count    map[config.Severity]int `json:"count"`
	Excluded int                     `json:"excluded"`
}

// mkSummary counts the number vulnerabilities per severity and the
// number of excluded vulnerabilities. The excluded vulnerabilities are
// not considered in the count per severity.
func mkSummary(vulns []metaVuln) (summary, error) {
	if len(vulns) == 0 {
		return summary{}, nil
	}

	summ := summary{
		Count: make(map[config.Severity]int),
	}
	for _, vuln := range vulns {
		if !vuln.Severity.IsValid() {
			return summary{}, fmt.Errorf("invalid severity: %v", vuln.Severity)
		}
		if vuln.Excluded {
			summ.Excluded++
		} else {
			summ.Count[vuln.Severity]++
		}
	}
	return summ, nil
}

// checkStatus represents the status of a check after the scan has
// finished.
type checkStatus struct {
	Checktype string `json:"checktype"`
	Target    string `json:"target"`
	Status    string `json:"status"`
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

// fullReportView represents a full report.
type fullReportView struct {
	Vulns  []metaVuln    `json:"vulnerabilities"`
	Summ   summary       `json:"summary"`
	Status []checkStatus `json:"status"`
}

// writeFullReport writes the full report.
func writeFullReport(fullReportFile io.Writer, vulns []metaVuln, summ summary, status []checkStatus) error {
	data := fullReportView{
		Vulns:  vulns,
		Summ:   summ,
		Status: status,
	}
	enc := json.NewEncoder(fullReportFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	return nil
}
