// Copyright 2024 Adevinta

// Package run implements the run command.
package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"time"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	checkcatalog "github.com/adevinta/vulcan-check-catalog/pkg/model"
	types "github.com/adevinta/vulcan-types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"

	"github.com/adevinta/lava/cmd/lava/internal/base"
	"github.com/adevinta/lava/internal/assettypes"
	"github.com/adevinta/lava/internal/checktypes"
	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/containers"
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
"vulcansec/vulcan-trivy:edge") or a path pointing to a directory with
the source code of a checktype. The target is any of the targets
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
pull the image). If not specified, "IfNotPresent" is used. If the
checktype is a path, only "IfNotPresent" and "Never" are allowed.

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

# Path checktype

When the specified checktype is a path that points to a directory,
Lava assumes that the directory contains the source code of the
checktype.

The directory must contains at least the following files:

  - Dockerfile
  - Go source code (*.go)

Lava will build the Go source code and then it will create a Docker
image based on the Dockerfile file found in the directory. The
reference of the generated image has the format "name:lava-run". Where
name is the name of the directory pointed by the specified path. If
the path is "/", the string "lava-checktype" is used. If the path is
".", the name of the current directory is used.

Thus, the following command:

	lava run /path/to/vulcan-trivy .

would generate a Docker image with the reference
"vulcan-trivy:lava-run".

Finally, the generated Docker image is used as checktype to run a scan
against the provided target with the specified options.

This mode requires a working Go toolchain in PATH.

# Examples

Run the checktype "vulcansec/vulcan-trivy:edge" against the current
directory:

	lava run vulcansec/vulcan-trivy:edge .

Run the checktype "vulcansec/vulcan-trivy:edge" against the current
directory with the options stored in the "options.json" file:

	lava run -optfile=options.json vulcansec/vulcan-trivy:edge .

Build and run the checktype in the path "/path/to/vulcan-trivy"
against the current directory:

	lava run /path/to/vulcan-trivy .

Run the checktype "vulcansec/vulcan-nuclei:edge" against the remote
"WebAddress" target "https://example.com":

	lava run -type=WebAddress vulcansec/vulcan-nuclei:edge https://example.com

Run the checktype "vulcansec/vulcan-nuclei:edge" against the local
"WebAddress" target "http://localhost:1234". Write the results in JSON
format to the "output.json" file. Also write security, operational and
configuration metrics to the "metrics.json" file:

	lava run -o output.json -fmt=json -metrics=metrics.json \
	         -type=WebAddress vulcansec/vulcan-nuclei:edge http://localhost:1234
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
	targetIdent := args[1]

	startTime := time.Now()
	metrics.Collect("start_time", startTime)

	base.LogLevel.Set(runLog)

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return 0, errors.New("could not read build info")
	}
	metrics.Collect("lava_version", bi.Main.Version)

	rep, err := engineRun(targetIdent, checktype)
	if err != nil {
		return 0, fmt.Errorf("engine run: %w", err)
	}

	exitCode, err := writeOutputs(rep)
	if err != nil {
		return 0, fmt.Errorf("write report: %w", err)
	}

	metrics.Collect("exit_code", exitCode)
	metrics.Collect("duration", time.Since(startTime).Seconds())

	return int(exitCode), nil
}

// engineRun runs a check against the specified targetIdent with the
// specified checktype. It gets the configuration from the provided
// flags.
func engineRun(targetIdent string, checktype string) (engine.Report, error) {
	target, err := mkTarget(targetIdent)
	if err != nil {
		return nil, fmt.Errorf("generate target: %w", err)
	}
	metrics.Collect("targets", []config.Target{target})

	agentConfig := mkAgentConfig()
	info, err := os.Stat(checktype)
	switch {
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, err
	case err == nil && info.IsDir():
		if agentConfig.PullPolicy != agentconfig.PullPolicyIfNotPresent && agentConfig.PullPolicy != agentconfig.PullPolicyNever {
			return nil, errors.New("path checktypes only allow IfNotPresent and Never pull policies")
		}

		ct, err := buildChecktype(checktype)
		if err != nil {
			return nil, fmt.Errorf("build checktype: %w", err)
		}
		checktype = ct
	}

	checktypeCatalog := mkChecktypeCatalog(checktype)
	eng, err := engine.NewWithCatalog(agentConfig, checktypeCatalog)
	if err != nil {
		return nil, fmt.Errorf("engine initialization: %w", err)
	}
	defer eng.Close()

	rep, err := eng.Run([]config.Target{target})
	if err != nil {
		return nil, fmt.Errorf("engine run: %w", err)
	}
	return rep, nil
}

// buildChecktype builds the checktype in path. It returns the
// reference of the new Docker image.
func buildChecktype(path string) (string, error) {
	slog.Info("building Go source code", "path", path)

	cmd := exec.Command("go", "build")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	cmd.Dir = path
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go build: %w", err)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("absolute path: %w", err)
	}
	dirname := filepath.Base(abs)
	if dirname == "/" {
		dirname = "lava-checktype"
	}

	rt, err := containers.GetenvRuntime()
	if err != nil {
		return "", fmt.Errorf("get env runtime: %w", err)
	}

	cli, err := containers.NewDockerdClient(rt)
	if err != nil {
		return "", fmt.Errorf("new dockerd client: %w", err)
	}

	ref := dirname + ":lava-run"

	summ, err := cli.ImageList(context.Background(), image.ListOptions{
		Filters: filters.NewArgs(filters.Arg("reference", ref)),
	})
	if err != nil {
		return "", fmt.Errorf("image list: %w", err)
	}

	slog.Info("building Docker image", "ref", ref)

	newID, err := cli.ImageBuild(context.Background(), path, "Dockerfile", ref)
	if err != nil {
		return "", fmt.Errorf("image build: %w", err)
	}

	switch n := len(summ); n {
	case 0:
		// No image found. Nothing to do.
	case 1:
		if newID == summ[0].ID {
			// The new image has the same ID. So, do not
			// delete it.
			break
		}
		rmOpts := image.RemoveOptions{Force: true, PruneChildren: true}
		if _, err := cli.ImageRemove(context.Background(), summ[0].ID, rmOpts); err != nil {
			return "", fmt.Errorf("image remove: %w", err)
		}
	default:
		return "", fmt.Errorf("image list: unexpected number of images: %v", n)
	}

	return ref, nil
}

// mkTarget generates a target from the provided flags and positional
// arguments.
func mkTarget(targetIdent string) (target config.Target, err error) {
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
		Identifier: targetIdent,
		AssetType:  types.AssetType(runType),
		Options:    opts,
	}
	return target, nil
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

// writeOutputs writes the provided report and the metrics file. It
// returns the exit code of the run command based on the
// report. writeOutputs gets the configuration from the provided
// flags.
func writeOutputs(rep engine.Report) (report.ExitCode, error) {
	reportConfig := config.ReportConfig{
		Severity:   runSeverity,
		Format:     runFmt,
		OutputFile: runO,
		Metrics:    runMetrics,
	}
	metrics.Collect("severity", reportConfig.Severity)

	rw, err := report.NewWriter(reportConfig)
	if err != nil {
		return 0, fmt.Errorf("new writer: %w", err)
	}
	defer rw.Close()

	exitCode, err := rw.Write(rep)
	if err != nil {
		return 0, fmt.Errorf("render report: %w", err)
	}

	if reportConfig.Metrics != "" {
		if err = metrics.WriteFile(reportConfig.Metrics); err != nil {
			return 0, fmt.Errorf("write metrics: %w", err)
		}
	}

	return exitCode, err
}
