// Copyright 2023 Adevinta

// Package config implements parsing of Lava configurations.
package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	types "github.com/adevinta/vulcan-types"
	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"

	"github.com/adevinta/lava/internal/assettypes"
)

var (
	// ErrInvalidLavaVersion means that the Lava version does not
	// have a valid format according to the Semantic Versioning
	// Specification.
	ErrInvalidLavaVersion = errors.New("invalid Lava version")

	// ErrNoChecktypeURLs means that no checktypes URLs were
	// specified.
	ErrNoChecktypeURLs = errors.New("no checktype catalogs")

	// ErrNoTargets means that no targets were specified.
	ErrNoTargets = errors.New("no targets")

	// ErrNoTargetIdentifier means that the target does not have
	// an identifier.
	ErrNoTargetIdentifier = errors.New("no target identifier")

	// ErrNoTargetAssetType means that the target does not have an
	// asset type.
	ErrNoTargetAssetType = errors.New("no target asset type")

	// ErrInvalidAssetType means that the asset type is invalid.
	ErrInvalidAssetType = errors.New("invalid asset type")

	// ErrInvalidSeverity means that the severity is invalid.
	ErrInvalidSeverity = errors.New("invalid severity")

	// ErrInvalidOutputFormat means that the output format is
	// invalid.
	ErrInvalidOutputFormat = errors.New("invalid output format")
)

// Config represents a Lava configuration.
type Config struct {
	// LavaVersion is the minimum required version of Lava.
	LavaVersion string `yaml:"lava"`

	// AgentConfig is the configuration of the vulcan-agent.
	AgentConfig AgentConfig `yaml:"agent"`

	// ReportConfig is the configuration of the report.
	ReportConfig ReportConfig `yaml:"report"`

	// ChecktypeURLs is a list of URLs pointing to checktype
	// catalogs.
	ChecktypeURLs []string `yaml:"checktypes"`

	// Targets is the list of targets.
	Targets []Target `yaml:"targets"`

	// LogLevel is the logging level.
	LogLevel slog.Level `yaml:"log"`
}

// Parse returns a parsed Lava configuration given an [io.Reader].
func Parse(r io.Reader) (Config, error) {
	dec := yaml.NewDecoder(r)

	// Ensure that the keys in the read data exist as fields in
	// the struct being decoded into.
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("validate config: %w", err)
	}
	return cfg, nil
}

// ParseFile returns a parsed Lava configuration given a path to a
// file.
func ParseFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()
	return Parse(f)
}

// validate validates the Lava configuration.
func (c Config) validate() error {
	// Lava version validation.
	if !semver.IsValid(c.LavaVersion) {
		return ErrInvalidLavaVersion
	}

	// Checktype URLs validation.
	if len(c.ChecktypeURLs) == 0 {
		return ErrNoChecktypeURLs
	}

	// Targets validation.
	if len(c.Targets) == 0 {
		return ErrNoTargets
	}
	for _, t := range c.Targets {
		if err := t.validate(); err != nil {
			return err
		}
	}
	return nil
}

// IsCompatible reports whether the configuration is compatible with
// the specified version. An invalid semantic version string is
// considered incompatible.
func (c Config) IsCompatible(v string) bool {
	return semver.Compare(v, c.LavaVersion) >= 0
}

// AgentConfig is the configuration passed to the vulcan-agent.
type AgentConfig struct {
	// PullPolicy is the pull policy passed to vulcan-agent.
	PullPolicy agentconfig.PullPolicy `yaml:"pullPolicy"`

	// Parallel is the maximum number of checks that can run in
	// parallel.
	Parallel int `yaml:"parallel"`

	// Vars is the environment variables required by the Vulcan
	// checktypes.
	Vars map[string]string `yaml:"vars"`

	// RegistryAuths contains the credentials for a set of
	// container registries.
	RegistryAuths []RegistryAuth `yaml:"registries"`
}

// ReportConfig is the configuration of the report.
type ReportConfig struct {
	// Severity is the minimum severity required to report a
	// finding.
	Severity Severity `yaml:"severity"`

	// Format is the output format.
	Format OutputFormat `yaml:"format"`

	// OutputFile is the path of the output file.
	OutputFile string `yaml:"output"`

	// Exclusions is a list of findings that will be ignored. For
	// instance, accepted risks, false positives, etc.
	Exclusions []Exclusion `yaml:"exclusions"`

	// Metrics is the file where the metrics will be written.
	// If Metrics is an empty string or not specified in the yaml file, then
	// the metrics report is not saved.
	Metrics string `yaml:"metrics"`
}

// Target represents the target of a scan.
type Target struct {
	// Identifier is a string that identifies the target. For
	// instance, a path, a URL, a container image, etc.
	Identifier string `yaml:"identifier"`

	// AssetType is the asset type of the target.
	AssetType types.AssetType `yaml:"type"`

	// Options is a list of specific options for the target.
	Options map[string]any `yaml:"options"`
}

// validate reports whether the target is a valid configuration value.
func (t Target) validate() error {
	if t.Identifier == "" {
		return ErrNoTargetIdentifier
	}
	if t.AssetType == "" {
		return ErrNoTargetAssetType
	}
	if !t.AssetType.IsValid() && !assettypes.IsValid(t.AssetType) {
		return fmt.Errorf("%w: %v", ErrInvalidAssetType, t.AssetType)
	}
	return nil
}

// RegistryAuth contains the credentials for a container registry.
type RegistryAuth struct {
	// Server is the URL of the registry.
	Server string `yaml:"server"`

	// Username is the username used to log into the registry.
	Username string `yaml:"username"`

	// Password is the password used to log into the registry.
	Password string `yaml:"password"`
}

// Severity is the severity of a given finding.
type Severity int

// Severity levels.
const (
	SeverityCritical Severity = 1
	SeverityHigh     Severity = 0
	SeverityMedium   Severity = -1
	SeverityLow      Severity = -2
	SeverityInfo     Severity = -3
)

// severityNames maps each severity name with its level.
var severityNames = map[string]Severity{
	"critical": SeverityCritical,
	"high":     SeverityHigh,
	"medium":   SeverityMedium,
	"low":      SeverityLow,
	"info":     SeverityInfo,
}

// parseSeverity converts a string into a [Severity] value.
func parseSeverity(severity string) (Severity, error) {
	if val, ok := severityNames[severity]; ok {
		return val, nil
	}
	return Severity(0), fmt.Errorf("%w: %v", ErrInvalidSeverity, severity)
}

// IsValid checks if a severity is valid.
func (s Severity) IsValid() bool {
	return s >= SeverityInfo && s <= SeverityCritical
}

// String returns value of a severity.
func (s Severity) String() string {
	for k, v := range severityNames {
		if v == s {
			return k
		}
	}
	return ""
}

// MarshalText encode a [Severity] as a text.
func (s Severity) MarshalText() (text []byte, err error) {
	if !s.IsValid() {
		return nil, ErrInvalidSeverity
	}
	return []byte(s.String()), nil
}

// UnmarshalText decodes a Severity text into a
// [Severity] value. It returns error if the provided
// string does not match any known severity.
func (s *Severity) UnmarshalText(text []byte) error {
	severity, err := parseSeverity(string(text))
	if err != nil {
		return err
	}
	*s = severity
	return nil
}

// OutputFormat is the format of the generated report.
type OutputFormat int

// Output formats available for the report.
const (
	OutputFormatHuman OutputFormat = iota
	OutputFormatJSON
)

var outputFormatNames = map[string]OutputFormat{
	"human": OutputFormatHuman,
	"json":  OutputFormatJSON,
}

// parseOutputFormat converts a string into an [OutputFormat] value.
func parseOutputFormat(format string) (OutputFormat, error) {
	if val, ok := outputFormatNames[strings.ToLower(format)]; ok {
		return val, nil
	}
	return OutputFormat(0), fmt.Errorf("%w: %v", ErrInvalidOutputFormat, format)
}

// UnmarshalYAML decodes an OutputFormat yaml node containing a string
// into an [OutputFormat] value. It returns error if the provided
// string does not match any known output format.
func (f *OutputFormat) UnmarshalYAML(value *yaml.Node) error {
	format, err := parseOutputFormat(value.Value)
	if err != nil {
		return err
	}
	*f = format
	return nil
}

// Exclusion represents the criteria to exclude a given finding.
type Exclusion struct {
	// Target is a regular expression that matches the name of the
	// affected target.
	Target string `yaml:"target"`

	// Resource is a regular expression that matches the name of
	// the affected resource.
	Resource string `yaml:"resource"`

	// Fingerprint defines the context in where the vulnerability
	// has been found. It includes the checktype image, the
	// affected target, the asset type and the checktype options.
	Fingerprint string `yaml:"fingerprint"`

	// Summary is a regular expression that matches the summary of
	// the vulnerability.
	Summary string `yaml:"summary"`

	// Description describes the exclusion.
	Description string `yaml:"description"`
}
