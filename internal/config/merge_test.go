// Copyright 2024 Adevinta

package config

import (
	"testing"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	"github.com/google/go-cmp/cmp"
)

func TestLavaMerger_Merge(t *testing.T) {
	tests := []struct {
		name    string
		dst     Config
		src     Config
		want    Config
		wantErr bool
	}{
		{
			name:    "Two empty configurations",
			dst:     Config{},
			src:     Config{},
			want:    Config{},
			wantErr: false,
		},
		{
			name: "Simple case",
			dst:  Config{},
			src: Config{
				LavaVersion: ptr("v1.0.0"),
			},
			want: Config{
				LavaVersion: ptr("v1.0.0"),
			},
			wantErr: false,
		},
		{
			name: "Settings with default values won't override",
			dst: Config{
				LavaVersion: ptr("v1.0.0"),
				AgentConfig: AgentConfig{
					PullPolicy: ptr(agentconfig.PullPolicyAlways),
					Parallel:   ptr(4),
					Vars: map[string]string{
						"VAR1": "value1",
						"VAR2": "value2",
					},
					RegistryAuths: []RegistryAuth{
						{
							Server:   "server",
							Username: "username",
							Password: "password",
						},
					},
				},
				ReportConfig: ReportConfig{
					Severity:               ptr(SeverityCritical),
					ShowSeverity:           ptr(SeverityLow),
					Format:                 ptr(OutputFormatJSON),
					OutputFile:             ptr("outputfile.json"),
					ErrorOnStaleExclusions: ptr(true),
					Exclusions: []Exclusion{
						{Summary: "Summary 1"},
					},
					Metrics: ptr("metrics.json"),
				},
			},
			src: Config{},
			want: Config{
				LavaVersion: ptr("v1.0.0"),
				AgentConfig: AgentConfig{
					PullPolicy: ptr(agentconfig.PullPolicyAlways),
					Parallel:   ptr(4),
					Vars: map[string]string{
						"VAR1": "value1",
						"VAR2": "value2",
					},
					RegistryAuths: []RegistryAuth{
						{
							Server:   "server",
							Username: "username",
							Password: "password",
						},
					},
				},
				ReportConfig: ReportConfig{
					Severity:               ptr(SeverityCritical),
					ShowSeverity:           ptr(SeverityLow),
					Format:                 ptr(OutputFormatJSON),
					OutputFile:             ptr("outputfile.json"),
					ErrorOnStaleExclusions: ptr(true),
					Exclusions: []Exclusion{
						{
							Summary: "Summary 1",
						},
					},
					Metrics: ptr("metrics.json"),
				},
			},
			wantErr: false,
		},
		{
			name: "Override value",
			dst: Config{
				LavaVersion: ptr("v1.0.0"),
				AgentConfig: AgentConfig{
					PullPolicy: ptr(agentconfig.PullPolicyAlways),
					Parallel:   ptr(4),
					Vars: map[string]string{
						"VAR3": "value3",
						"VAR4": "value4",
					},
					RegistryAuths: []RegistryAuth{
						{
							Server:   "server2",
							Username: "username2",
							Password: "password2",
						},
					},
				},
				ReportConfig: ReportConfig{
					Severity:               ptr(SeverityCritical),
					ShowSeverity:           ptr(SeverityLow),
					Format:                 ptr(OutputFormatJSON),
					OutputFile:             ptr("outputfile2.json"),
					ErrorOnStaleExclusions: ptr(true),
					Exclusions: []Exclusion{
						{
							Summary: "Summary 2",
						},
					},
					Metrics: ptr("metrics2.json"),
				},
			},
			src: Config{
				LavaVersion: ptr("v1.0.1"),
				AgentConfig: AgentConfig{
					PullPolicy: ptr(agentconfig.PullPolicyNever),
					Parallel:   ptr(3),
					Vars: map[string]string{
						"VAR1": "value1",
						"VAR2": "value2",
					},
					RegistryAuths: []RegistryAuth{
						{
							Server:   "server",
							Username: "username",
							Password: "password",
						},
					},
				},
				ReportConfig: ReportConfig{
					Severity:               ptr(SeverityCritical),
					ShowSeverity:           ptr(SeverityLow),
					Format:                 ptr(OutputFormatJSON),
					OutputFile:             ptr("outputfile1.json"),
					ErrorOnStaleExclusions: ptr(false),
					Exclusions: []Exclusion{
						{
							Summary: "Summary 1",
						},
					},
					Metrics: ptr("metrics2.json"),
				},
			},
			want: Config{
				LavaVersion: ptr("v1.0.1"),
				AgentConfig: AgentConfig{
					PullPolicy: ptr(agentconfig.PullPolicyNever),
					Parallel:   ptr(3),
					Vars: map[string]string{
						"VAR1": "value1",
						"VAR2": "value2",
						"VAR3": "value3",
						"VAR4": "value4",
					},
					RegistryAuths: []RegistryAuth{
						{
							Server:   "server2",
							Username: "username2",
							Password: "password2",
						},
						{
							Server:   "server",
							Username: "username",
							Password: "password",
						},
					},
				},
				ReportConfig: ReportConfig{
					Severity:               ptr(SeverityCritical),
					ShowSeverity:           ptr(SeverityLow),
					Format:                 ptr(OutputFormatJSON),
					OutputFile:             ptr("outputfile1.json"),
					ErrorOnStaleExclusions: ptr(false),
					Exclusions: []Exclusion{
						{Summary: "Summary 2"},
						{Summary: "Summary 1"},
					},
					Metrics: ptr("metrics2.json"),
				},
			},
			wantErr: false,
		},
		{
			name: "Append Exclusions",
			dst: Config{
				ReportConfig: ReportConfig{
					Exclusions: []Exclusion{
						{
							Summary: "Summary 2",
						},
					},
				},
			},
			src: Config{
				ReportConfig: ReportConfig{
					Exclusions: []Exclusion{
						{
							Summary: "Summary 1",
						},
					},
				},
			},
			want: Config{
				ReportConfig: ReportConfig{
					Exclusions: []Exclusion{
						{
							Summary: "Summary 2",
						},
						{
							Summary: "Summary 1",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Duplicated Exclusions",
			dst: Config{
				ReportConfig: ReportConfig{
					Exclusions: []Exclusion{
						{
							Summary: "Summary 1",
						},
					},
				},
			},
			src: Config{
				ReportConfig: ReportConfig{
					Exclusions: []Exclusion{
						{
							Summary: "Summary 1",
						},
					},
				},
			},
			want: Config{
				ReportConfig: ReportConfig{
					Exclusions: []Exclusion{
						{Summary: "Summary 1"},
						{Summary: "Summary 1"},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := merge(tt.dst, tt.src)
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error value: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("configs mismatch (-want +got):\n%v", diff)
			}
		})
	}
}
