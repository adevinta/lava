// Copyright 2023 Adevinta

package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/adevinta/lava/internal/config"
)

// jsonPrinter represents a JSON report printer.
type jsonPrinter struct{}

// Print renders the scan results in JSON format.
func (prn jsonPrinter) Print(w io.Writer, vulns []vulnerability, _ summary, _ []checkStatus, _ []config.Exclusion) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vulns); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}
