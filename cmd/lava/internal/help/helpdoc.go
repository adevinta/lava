// Copyright 2023 Adevinta

package help

import "github.com/adevinta/lava/cmd/lava/internal/base"

// HelpLavaYAML documents the configuration file format.
var HelpLavaYAML = &base.Command{
	UsageLine: "lava.yaml",
	Short:     "configuration file format",
	Long: `
Each Lava project is defined by a configuration file (usually named
lava.yaml) that defines the parameters of the security scan.

# Example

A Lava configuration file is a YAML document with the following
fields. These are described elsewhere in this topic.

	lava: v1.0.0
	checktypesURLs:
	  - checktypes.json
	targets:
	  - identifier: .
	    assetType: GitRepository
	  - identifier: image
	    assetType: DockerImage
	agent:
	  parallel: 4
	report:
	  severity: high
	  exclusions:
	    - description: Ignore test certificates.
	      summary: 'Secret Leaked in Git Repository'
	      resource: '/testdata/certs/'
	logLevel: error

# lava

The "lava" field describes the minimum required version of the Lava
command. For instance,

	lava: v1.0.0

Using a Lava command whose version is lower than the minimum version
required by the configuration file returns an error.

This field is mandatory.

# checktypesURLs

The "checktypesURLs" field contains a list of URLs that point to
checktype catalogs.

If the URL omits the scheme, it is considered a file path relative to
the current working directory of the Lava command. For instance,

	checktypesURLs:
	  - checktypes.json

HTTP and HTTPS URLs are supported. For instance,

	checktypesURLs:
	  - https://example.com/checktypes.json

At least one catalog must be specified.

# targets

The "targets" field contains the list of targets to scan. Every target
is defined by the following properties:

  - identifier: string that identifies the target. For instance, a
    path, a URL, a Docker image, etc. It is mandatory.
  - assetType: the asset type of the target. Valid values are
    "AWSAccount", "DockerImage", "GitRepository", "IP", "IPRange",
    "DomainName", "Hostname", "WebAddress" and "Path". It is
    mandatory.
  - options: map of target-specific options. These options are merged
    with the options coming from the checktype catalog.

For instance,

	targets:
	  - identifier: .
	    assetType: GitRepository
	    options:
	      branch: master

At least one target must be specified.

# agent

The "agent" field contains the configuration passed to the Vulcan
agent that Lava runs internally. The agent accepts the following
properties:

  - pullPolicy: policy used to decide when to pull a required Docker
    image. Valid values are "Always", "IfNotPresent" and "Never". If
    not specified, "IfNotPresent" is used.
  - parallel: maximum number of checks that can run in parallel. If
    not specified, this limit is set to one.
  - vars: map with the environment variables passed to the executed
    checktypes.
  - registriesAuth: credentials for a set of container registries. It
    requires the following properties "server", "username" and
    "password".

The sample below is a full agent configuration:

	agent:
	  pullPolicy: Always
	  parallel: 4
	  vars:
	    DEBUG: true
	  registriesAuth:
	    - server: example.com
	      username: user
	      password: p4ssw0rd

It is important to note that Lava is able to use the credentials
configured for the Docker CLI. So, if Docker is already logged in, it
is not necessary to configure the credentials of the registry in the
configuration file.

# report

The "report" field describes how to report the findings. It supports
the following properties.

  - severity: minimum severity required to report a finding. Valid
    values are "critical", "high", "medium", "low" and "info". If not
    specified, "high" is used.
  - format: output format. Valid values are "human" and "json". If not
    specified, "human" is used.
  - outputFile: path of the output file. If not specified, stdout is
    used.
  - metrics: path of the file where the metrics report will be
    written. If not specified, then the metrics report is not
    generated.
  - exclusions: list of rules that define what findings should be
    excluded from the report. It allows to ignore findings because of
    accepted risks, false positives, etc.

The sample below is a full report configuration:

	report:
	  severity: high
	  format: json
	  outputFile: findings.json
	  metrics: metrics.json
	  exclusions:
	    - description: Ignore test certificates.
	      summary: 'Secret Leaked in Git Repository'
	      resource: '/testdata/certs/'

The exclusion rules support the following filters:

  - target: regular expression that matches the name of the affected
    target.
  - resource: regular expression that matches the name of the affected
    resource.
  - fingerprint: context in where the vulnerability has been found. It
    includes the checktype image, the affected target, the asset type
    and the checktype options.
  - summary: regular expression that matches the summary of the
    vulnerability.

A finding is excluded if it matches all the filters of an exclusion
rule.

It is possible to provide a human-friendly description of an exclusion
rule using its "description" property.

# logLevel

The "logLevel" field describes the logging level of the Lava command.
Valid values are "debug", "info", "warn" and "error". If not
specified, "info" is used. For instance,

	logLevel: error
	`,
}
