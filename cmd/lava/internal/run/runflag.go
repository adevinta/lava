// Copyright 2024 Adevinta

package run

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	types "github.com/adevinta/vulcan-types"

	"github.com/adevinta/lava/internal/assettypes"
	"github.com/adevinta/lava/internal/config"
)

// typeFlag represents the asset type provided with the -type flag.
type typeFlag types.AssetType

// Set parses the value provided with the -type flag. It returns error
// if it is not a know asset type.
func (typ *typeFlag) Set(s string) error {
	if s == "" {
		return errors.New("empty asset type")
	}

	at := types.AssetType(s)
	if !at.IsValid() && !assettypes.IsValid(at) {
		return fmt.Errorf("invalid asset type: %v", s)
	}
	*typ = typeFlag(at)
	return nil
}

// String returns the string representation of a -type flag value.
func (typ typeFlag) String() string {
	return types.AssetType(typ).String()
}

// varFlag represents the environment variables provided with the -var
// flag.
type varFlag map[string]string

// Set parses the values provided with the -var flag. The environment
// variable must follow the format "name[=value]". If there is no
// equal sign, the value of the variable is got from the environment.
func (envvar *varFlag) Set(s string) error {
	if *envvar == nil {
		*envvar = make(map[string]string)
	}

	if s == "" {
		return errors.New("empty environment variable")
	}

	name, value, found := strings.Cut(s, "=")
	if !found {
		value = os.Getenv(name)
	}

	if name == "" {
		return errors.New("empty envvar name")
	}

	(*envvar)[name] = value
	return nil
}

// String returns the string representation of the provided
// environment variables.
func (envvar varFlag) String() string {
	var vars []string
	for k, v := range envvar {
		vars = append(vars, fmt.Sprintf("%v=%v", k, v))
	}
	return strings.Join(vars, ":")
}

// authFlag represents the container registry credentials provided
// with the -user flag.
type userFlag struct {
	Username string
	Password string
}

// osStdin is used to read the container registry password. It is used
// by tests.
var osStdin io.Reader = os.Stdin

// Set parses the values provided with the -user flag. The container
// registry credentials must follow the format
// "username[:[password]]". The username and password are split around
// the first instance of the colon. So the username cannot contain a
// colon. If there is no colon, the password is read from the standard
// input.
func (userinfo *userFlag) Set(s string) error {
	if s == "" {
		return errors.New("empty registry credentials")
	}

	username, password, found := strings.Cut(s, ":")
	if !found {
		b, err := io.ReadAll(osStdin)
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		password = string(b)
	}

	*userinfo = userFlag{
		Username: username,
		Password: password,
	}
	return nil
}

// String returns the string representation of the provided container
// registry credentials. The password is masked.
func (userinfo userFlag) String() string {
	return userinfo.Username + ":****"
}

func init() {
	CmdRun.Flag.Var(&runType, "type", "target type")
	CmdRun.Flag.DurationVar(&runTimeout, "timeout", 600*time.Second, "checktype timeout")
	CmdRun.Flag.StringVar(&runOpt, "opt", "", "checktype options")
	CmdRun.Flag.StringVar(&runOptfile, "optfile", "", "checktype options file")
	CmdRun.Flag.Var(&runVar, "var", "checktype environment variable")
	CmdRun.Flag.TextVar(&runPull, "pull", agentconfig.PullPolicyIfNotPresent, "container image pull policy")
	CmdRun.Flag.StringVar(&runRegistry, "registry", "", "container registry")
	CmdRun.Flag.Var(&runUser, "user", "container registry credentials")
	CmdRun.Flag.TextVar(&runSeverity, "severity", config.SeverityHigh, "minimum severity required to report a finding")
	CmdRun.Flag.StringVar(&runO, "o", "", "output file")
	CmdRun.Flag.TextVar(&runFmt, "fmt", config.OutputFormatHuman, "output format")
	CmdRun.Flag.StringVar(&runMetrics, "metrics", "", "metrics file")
	CmdRun.Flag.TextVar(&runLog, "log", slog.LevelInfo, "log level")
}
