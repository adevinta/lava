// Copyright 2023 Adevinta

package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// jsonView represents the JSON view of the report.
type jsonView struct {
	Vulns  []repVuln     `json:"vulnerabilities"`
	Summ   summary       `json:"summary"`
	Status []checkStatus `json:"status"`
}

// jsonPrinter represents a JSON report printer.
type jsonPrinter struct{}

// Print renders the scan results in JSON format.
func (prn jsonPrinter) Print(w io.Writer, vulns []repVuln, summ summary, status []checkStatus) error {
	data := jsonView{
		Vulns:  vulns,
		Summ:   summ,
		Status: status,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}
