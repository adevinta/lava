// Copyright 2023 Adevinta

package config

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"testing"
	"time"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	types "github.com/adevinta/vulcan-types"
	"github.com/google/go-cmp/cmp"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name          string
		file          string
		envs          map[string]string
		want          Config
		wantErr       error
		wantErrRegexp *regexp.Regexp
	}{
		{
			name: "valid",
			file: "testdata/valid.yaml",
			want: Config{
				LavaVersion: "v1.0.0",
				ChecktypeURLs: []string{
					"checktypes.json",
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
			name: "valid env",
			file: "testdata/valid_env.yaml",
			want: Config{
				LavaVersion: "v1.0.0",
				ChecktypeURLs: []string{
					"checktypes.json",
				},
				Targets: []Target{
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
				},
			},
			envs: map[string]string{
				"TARGET":           "example.com",
				"CHECK_types_URL1": "checktypes.json",
			},
		},
		{
			name: "invalid env",
			file: "testdata/invalid_env.yaml",
			want: Config{
				LavaVersion: "v1.0.0",
				ChecktypeURLs: []string{
					"checktypes.json",
				},
				Targets: []Target{
					{
						Identifier: "${1NVALID}",
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
			name:    "no checktypes URLs",
			file:    "testdata/no_checktypes_urls.yaml",
			want:    Config{},
			wantErr: ErrNoChecktypeURLs,
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
				ChecktypeURLs: []string{
					"checktypes.json",
				},
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
			name: "low show",
			file: "testdata/low_show.yaml",
			want: Config{
				LavaVersion: "v1.0.0",
				ChecktypeURLs: []string{
					"checktypes.json",
				},
				ReportConfig: ReportConfig{
					ShowSeverity: ptr(SeverityLow),
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
			name: "never pull policy",
			file: "testdata/never_pull_policy.yaml",
			want: Config{
				LavaVersion: "v1.0.0",
				ChecktypeURLs: []string{
					"checktypes.json",
				},
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
				ChecktypeURLs: []string{
					"checktypes.json",
				},
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
				ChecktypeURLs: []string{
					"checktypes.json",
				},
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
		{
			name: "valid expiration date",
			file: "testdata/valid_expiration_date.yaml",
			want: Config{
				LavaVersion: "v1.0.0",
				ChecktypeURLs: []string{
					"checktypes.json",
				},
				Targets: []Target{
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
				},
				ReportConfig: ReportConfig{
					Format:     OutputFormatHuman,
					OutputFile: "",
					Exclusions: []Exclusion{
						{
							Summary:        "Secret Leaked in Git Repository",
							Description:    "Ignore test certificates.",
							ExpirationDate: mustParseExpDate("2024/07/05"),
						},
					},
				},
			},
		},
		{
			name:    "invalid expiration date",
			file:    "testdata/invalid_expiration_date.yaml",
			want:    Config{},
			wantErr: ErrInvalidExpirationDate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envs {
				t.Setenv(k, v)
			}
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

func TestConfig_IsCompatible(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		v    string
		want bool
	}{
		{
			name: "same version",
			cfg:  Config{LavaVersion: "v1.0.0"},
			v:    "v1.0.0",
			want: true,
		},
		{
			name: "lower version",
			cfg:  Config{LavaVersion: "v1.1.0"},
			v:    "1.0.0",
			want: false,
		},
		{
			name: "higher version",
			cfg:  Config{LavaVersion: "v1.0.0"},
			v:    "v1.1.0",
			want: true,
		},
		{
			name: "pre-release",
			cfg:  Config{LavaVersion: "v0.0.0"},
			v:    "v0.0.0-20231216173526-1150d51c5272",
			want: false,
		},
		{
			name: "invalid version",
			cfg:  Config{LavaVersion: "v1.0.0"},
			v:    "invalid",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.IsCompatible(tt.v)
			if got != tt.want {
				t.Errorf("unexpected result: %v, minimum required version: %v, v: %v", got, tt.cfg.LavaVersion, tt.v)
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

func ptr[V any](v V) *V {
	return &v
}

func TestParseExpirationDate(t *testing.T) {
	tests := []struct {
		name    string
		date    string
		want    ExpirationDate
		wantErr error
	}{
		{
			name:    "valid date",
			date:    "2024/07/05",
			want:    mustParseExpDate("2024/07/05"),
			wantErr: nil,
		},
		{
			name:    "invalid date",
			date:    "2024-07-05",
			want:    ExpirationDate{},
			wantErr: ErrInvalidExpirationDate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseExpirationDate(tt.date)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("unexpected error: want: %v, got: %v", tt.wantErr, err)
			}
			if !got.Equal(tt.want.Time) {
				t.Errorf("unexpected date: want: %v, got: %v", tt.want, got)
			}
		})
	}
}

func TestExpirationDate_MarshalText(t *testing.T) {
	date := mustParseExpDate("2024/07/05")
	want := []byte("2024/07/05")

	got, err := date.MarshalText()
	if err != nil {
		t.Errorf("unexpected error: want: %v, got: %v", nil, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("unexpected expiration date string: want: %s, got: %s", want, got)
	}
}

func mustParseExpDate(date string) ExpirationDate {
	t, err := time.Parse(ExpirationDateLayout, date)
	if err != nil {
		panic(err)
	}
	return ExpirationDate{Time: t}
}
