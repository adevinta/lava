// Copyright 2024 Adevinta

// Package run implements the run command.
package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"time"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	checkcatalog "github.com/adevinta/vulcan-check-catalog/pkg/model"
	types "github.com/adevinta/vulcan-types"

	"github.com/adevinta/lava/cmd/lava/internal/base"
	"github.com/adevinta/lava/internal/assettypes"
	"github.com/adevinta/lava/internal/checktypes"
	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/engine"
	"github.com/adevinta/lava/internal/metrics"
	"github.com/adevinta/lava/internal/report"
)

// CmdRun represents the run command.
var CmdRun = &base.Command{
	UsageLine: "run [flags] checktype target",
	Short:     "run scan",
	Long: `
Run a checktype against a target.

Run accepts two arguments: the checktype to run and the target of the
scan. The checktype is a container image reference (e.g.
"vulcansec/vulcan-trivy:edge"). The target is any of the targets
supported by the -type flag.

The -type flag determines the type of the provided target. Valid
values are "AWSAccount", "DockerImage", "GitRepository", "IP",
"IPRange", "DomainName", "Hostname", "WebAddress" and "Path". If not
specified, "Path" is used. For more details, use "lava help
lava.yaml".

The -timeout flag sets the timeout of the checktype execution. This
flag accepts a value acceptable to time.ParseDuration. If not
specified, "600s" is used.

The -opt and -optfile flags specify the checktype options. The -opt
flag accepts a string with the options. The -optfile flag accepts a
path to an options file. The options must be provided in JSON format
and follow the checktype manifest.

The -var flag sets the environment variables passed to the
checktype. The environment variables must be provided using the format
"name[=value]". If there is no equal sign, the value of the variable
is got from the environment. This flag can be specified multiple
times.

The -pull flag determines the pull policy for container images. Valid
values are "Always" (always download the image), "IfNotPresent" (pull
the image if it not present in the local cache) and "Never" (never
pull the image). If not specified, "IfNotPresent" is used.

The -registry flag specifies the container registry. If the registry
requires authentication, the credentials are provided using the -user
flag. The -user flag accepts the credentials with the format
"username[:[password]]". The username and password are split around
the first instance of the colon. So the username cannot contain a
colon. If there is no colon, the password is read from the standard
input.

The -severity flag determines the minimum severity required to report
a finding. Valid values are "critical", "high", "medium", "low" and
"info". If not specified, "high" is used.

The -o flag specifies the output file to write the results of the
scan. If not specified, the standard output is used. The format of the
output is defined by the -fmt flag. The -fmt flag accepts the values
"human" for human-readable output and "json" for JSON-encoded
output. If not specified, "human" is used.

The -metrics flag specifies the file to write the security,
operational and configuration metrics of the scan. For more details,
use "lava help metrics".

The -log flag defines the logging level. Valid values are "debug",
"info", "warn" and "error". If not specified, "info" is used.
	`}

// Command-line flags.
var (
	runType     typeFlag               = "Path" // -type flag
	runTimeout  time.Duration                   // -timeout flag
	runOpt      string                          // -opt flag
	runOptfile  string                          // -optfile flag
	runVar      varFlag                         // -var flag
	runPull     agentconfig.PullPolicy          // -pull flag
	runRegistry string                          // -registry flag
	runUser     userFlag                        // -user flag
	runSeverity config.Severity                 // -severity flag
	runO        string                          // -o flag
	runFmt      config.OutputFormat             // -fmt flag
	runMetrics  string                          // -metrics flag
	runLog      slog.Level                      // -log flag
)

func init() {
	CmdRun.Run = runRun // Break initialization cycle.
}

// osExit is used by tests to capture the exit code.
var osExit = os.Exit

// runRun is the entry point of the CmdRun command.
func runRun(args []string) error {
	exitCode, err := run(args)
	if err != nil {
		return err
	}
	osExit(exitCode)
	return nil
}

// run contains the logic of the [CmdRun] command. It is wrapped by
// the run function, so the deferred functions can be executed before
// calling [os.Exit]. It returns the exit code that must be passed to
// [os.Exit].
func run(args []string) (int, error) {
	if len(args) != 2 {
		return 0, errors.New("invalid number of arguments")
	}
	checktype := args[0]
	targetIdentifier := args[1]

	startTime := time.Now()
	metrics.Collect("start_time", startTime)

	base.LogLevel.Set(runLog)

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return 0, errors.New("could not read build info")
	}
	metrics.Collect("lava_version", bi.Main.Version)

	target, err := mkTarget(targetIdentifier)
	if err != nil {
		return 0, fmt.Errorf("generate target: %w", err)
	}
	metrics.Collect("targets", []config.Target{target})

	agentConfig := mkAgentConfig()
	checktypeCatalog := mkChecktypeCatalog(checktype)
	eng, err := engine.NewWithCatalog(agentConfig, checktypeCatalog)
	if err != nil {
		return 0, fmt.Errorf("engine initialization: %w", err)
	}
	defer eng.Close()

	er, err := eng.Run([]config.Target{target})
	if err != nil {
		return 0, fmt.Errorf("engine run: %w", err)
	}

	reportConfig := mkReportConfig()
	metrics.Collect("severity", reportConfig.Severity)

	rw, err := report.NewWriter(reportConfig)
	if err != nil {
		return 0, fmt.Errorf("new writer: %w", err)
	}
	defer rw.Close()

	exitCode, err := rw.Write(er)
	if err != nil {
		return 0, fmt.Errorf("render report: %w", err)
	}

	metrics.Collect("exit_code", exitCode)
	metrics.Collect("duration", time.Since(startTime).Seconds())

	if reportConfig.Metrics != "" {
		if err = metrics.WriteFile(reportConfig.Metrics); err != nil {
			return 0, fmt.Errorf("write metrics: %w", err)
		}
	}

	return int(exitCode), nil
}

// mkTarget generates a target from the provided flags and positional
// arguments.
func mkTarget(targetIdentifier string) (target config.Target, err error) {
	if runOpt != "" && runOptfile != "" {
		return config.Target{}, errors.New("-opt and -optfile cannot be set simultaneously")
	}

	optbytes := []byte(runOpt)
	if runOptfile != "" {
		if optbytes, err = os.ReadFile(runOptfile); err != nil {
			return config.Target{}, fmt.Errorf("read file: %w", err)
		}
	}

	var opts map[string]any
	if len(optbytes) > 0 {
		if err := json.Unmarshal(optbytes, &opts); err != nil {
			return config.Target{}, fmt.Errorf("JSON unmarshal: %w", err)
		}
	}

	target = config.Target{
		Identifier: targetIdentifier,
		AssetType:  types.AssetType(runType),
		Options:    opts,
	}
	return target, nil
}

// mkReportConfig generates a report configuration from the provided
// flags.
func mkReportConfig() config.ReportConfig {
	return config.ReportConfig{
		Severity:   runSeverity,
		Format:     runFmt,
		OutputFile: runO,
		Metrics:    runMetrics,
	}
}

// mkAgentConfig generates an agent configuration from the provided
// flags.
func mkAgentConfig() config.AgentConfig {
	var auths []config.RegistryAuth
	if runRegistry != "" {
		auths = []config.RegistryAuth{
			{
				Server:   runRegistry,
				Username: runUser.Username,
				Password: runUser.Password,
			},
		}
	}

	return config.AgentConfig{
		PullPolicy:    runPull,
		Vars:          runVar,
		RegistryAuths: auths,
	}
}

// mkChecktypeCatalog generates a checktype catalog from the provided
// flags and positional arguments.
func mkChecktypeCatalog(checktype string) checktypes.Catalog {
	vulcanAssetType := assettypes.ToVulcan(types.AssetType(runType))
	ct := checkcatalog.Checktype{
		Name:    checktype,
		Image:   checktype,
		Timeout: int(runTimeout.Seconds()),
		Assets:  []string{vulcanAssetType.String()},
	}
	return checktypes.Catalog{checktype: ct}
}
