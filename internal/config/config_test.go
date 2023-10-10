// Copyright 2023 Adevinta

package config

import (
	"errors"
	"io"
	"log/slog"
	"regexp"
	"testing"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	types "github.com/adevinta/vulcan-types"
	"github.com/google/go-cmp/cmp"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name          string
		file          string
		want          Config
		wantErr       error
		wantErrRegexp *regexp.Regexp
	}{
		{
			name: "valid",
			file: "testdata/valid.yaml",
			want: Config{
				LavaVersion: "v1.0.0",
				Targets: []Target{
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
				},
			},
		},
		{
			name:    "empty",
			file:    "testdata/empty.yaml",
			want:    Config{},
			wantErr: io.EOF,
		},
		{
			name:    "invalid lava version",
			file:    "testdata/invalid_lava_version.yaml",
			want:    Config{},
			wantErr: ErrInvalidLavaVersion,
		},
		{
			name:    "no targets",
			file:    "testdata/no_targets.yaml",
			want:    Config{},
			wantErr: ErrNoTargets,
		},
		{
			name:    "no target identifier",
			file:    "testdata/no_target_identifier.yaml",
			want:    Config{},
			wantErr: ErrNoTargetIdentifier,
		},
		{
			name:    "no target asset type",
			file:    "testdata/no_target_asset_type.yaml",
			want:    Config{},
			wantErr: ErrNoTargetAssetType,
		},
		{
			name: "critical severity",
			file: "testdata/critical_severity.yaml",
			want: Config{
				LavaVersion: "v1.0.0",
				ReportConfig: ReportConfig{
					Severity: SeverityCritical,
				},
				Targets: []Target{
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
				},
			},
		},
		{
			name:    "invalid severity",
			file:    "testdata/invalid_severity.yaml",
			want:    Config{},
			wantErr: ErrInvalidSeverity,
		},
		{
			name: "never pull policy",
			file: "testdata/never_pull_policy.yaml",
			want: Config{
				LavaVersion: "v1.0.0",
				AgentConfig: AgentConfig{
					PullPolicy: agentconfig.PullPolicyNever,
				},
				Targets: []Target{
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
				},
			},
		},
		{
			name:          "invalid pull policy",
			file:          "testdata/invalid_pull_policy.yaml",
			want:          Config{},
			wantErrRegexp: regexp.MustCompile(`value .* is not a valid PullPolicy value`),
		},
		{
			name:    "invalid target asset type",
			file:    "testdata/invalid_target_asset_type.yaml",
			want:    Config{},
			wantErr: ErrInvalidAssetType,
		},
		{
			name: "JSON output format",
			file: "testdata/json_output_format.yaml",
			want: Config{
				LavaVersion: "v1.0.0",
				Targets: []Target{
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
				},
				ReportConfig: ReportConfig{
					Format: OutputFormatJSON,
				},
			},
		},
		{
			name:    "invalid output format",
			file:    "testdata/invalid_output_format.yaml",
			want:    Config{},
			wantErr: ErrInvalidOutputFormat,
		},
		{
			name: "debug log level",
			file: "testdata/debug_log_level.yaml",
			want: Config{
				LavaVersion: "v1.0.0",
				Targets: []Target{
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
				},
				LogLevel: slog.LevelDebug,
			},
		},
		{
			name:          "invalid log level",
			file:          "testdata/invalid_log_level.yaml",
			want:          Config{},
			wantErrRegexp: regexp.MustCompile(`level string ".*": unknown name`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFile(tt.file)

			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("unexpected error: got: %v, want: %v", err, tt.wantErr)
				}
			case tt.wantErrRegexp != nil:
				if err == nil {
					t.Errorf("unexpected nil error: want: %v", tt.wantErrRegexp)
				} else if !tt.wantErrRegexp.MatchString(err.Error()) {
					t.Errorf("unexpected error: got: %v, want: %v", err, tt.wantErrRegexp)
				}
			default:
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("configs mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestSeverity_MarshalText(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     string
		wantErr  error
	}{
		{
			name:     "critical",
			severity: SeverityCritical,
			want:     "critical",
			wantErr:  nil,
		},
		{
			name:     "high",
			severity: SeverityHigh,
			want:     "high",
			wantErr:  nil,
		},
		{
			name:     "medium",
			severity: SeverityMedium,
			want:     "medium",
			wantErr:  nil,
		},
		{
			name:     "low",
			severity: SeverityLow,
			want:     "low",
			wantErr:  nil,
		},
		{
			name:     "info",
			severity: SeverityInfo,
			want:     "info",
			wantErr:  nil,
		},
		{
			name:     "invalid",
			severity: 7,
			want:     "",
			wantErr:  ErrInvalidSeverity,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.severity.MarshalText()
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("unexpected error: want: %v, got: %v", tt.wantErr, err)
			}
			if string(got) != tt.want {
				t.Errorf("unexpected severity string: want: %v, got: %v", tt.want, got)
			}
		})
	}
}
