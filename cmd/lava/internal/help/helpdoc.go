// Copyright 2023 Adevinta

package help

import "github.com/adevinta/lava/cmd/lava/internal/base"

// HelpChecktypes documents the Lava checktype catalog format.
var HelpChecktypes = &base.Command{
	UsageLine: "checktypes",
	Short:     "checktype catalog format",
	Long: `
A checktype is a program that integrates a third-party tool
(e.g. Trivy, Semgrep, etc.) or implements a custom detection for a
given vulnerability. A check is a concrete instance of a checktype
that is run against a specific target with a specific set of
options.

Checktypes are organized in catalogs. A checktype catalog is a
collection of checktypes with their metadata and default options. This
help topic describes the checktype catalog format in detail.

The list of enabled checktype catalogs is specified in the Lava
configuration file. For more details, use "lava help lava.yaml".

A checktype can cover one or multiple security controls like DAST
(Dynamic Application Security Testing), SAST (Static Application
Security Testing), SCA (Software Composition Analysis), secret
detection, etc. For instance, the vulcan-trivy checktype covers SAST
for IaC, SCA and secret detection.

For more details about the security controls covered by Lava, visit
https://adevinta.github.io/lava-docs/controls.html.

The "lava init" command generates a configuration file that points to
a remote catalog curated by the Adevinta Security Team to provide a
balanced configuration. This catalog is continuously updated to improve
the quality of the results, support new types of projects, etc. By
default, the configuration file pins the "v0" version, which means
that every Lava execution benefits from these updates.

A checktype catalog is a JSON document as shown in the following
example:

	{
	    "checktypes": [
	        {
	            "name": "vulcan-example",
	            "description": "Description of the checktype",
	            "image": "vulcan-example:latest",
	            "timeout": 600,
	            "options": {
	                "branch": "example",
	                "depth": 1,
	                "check_option_1": "value_option_1",
	                "check_option_2": ["item1, item2"],
	            },
	            "required_vars": [
	                "REQUIRED_VARIABLE_1",
	                "REQUIRED_VARIABLE_2"
	            ],
	            "assets": [
	                "GitRepository"
	            ]
	        }
	    ]
	}

A checktype catalog entry specifies the following parameters:

  - name: Name of the checktype.
  - description: Description of the checktype.
  - image: Name of the image needed to run the check.
  - timeout: Timeout of the check.
  - required_vars: Environment variables passed to the check. They
    are defined in the checktype's manifest.toml file.
  - assets: Asset types accepted as target by the check. They are
    defined in the checktype's manifest.toml file.
  - options:
    - depth: Number of commits to fetch when the asset type is a git
      repository.
    - branch: Branch to check out when the asset type is a git
      repository.
    - Others options defined in the checktype's manifest.toml file of
      the check.

Users may provide a custom catalog if it complies with the JSON Schema
defined at https://adevinta.github.io/lava-docs/specs/checktype_catalog.json.

A public collection of checktypes is maintained at
https://github.com/adevinta/vulcan-checks and their corresponding
Docker images are pushed to https://hub.docker.com/u/vulcansec. Every
checktype includes a manifest.toml file, which contains all the
information required to configure a check.

Users may also develop their own checktypes. For more details, visit
https://adevinta.github.io/vulcan-docs/developing-checks.
	`,
}

// HelpEnvironment documents the Lava environment variables.
var HelpEnvironment = &base.Command{
	UsageLine: "environment",
	Short:     "environment variables",
	Long: `
The lava command consults environment variables for configuration. If
an environment variable is unset or empty, the lava command uses a
sensible default setting.

General-purpose environment variables:

	LAVA_FORCECOLOR
		Forces colorized output. By default, colorized output
		is disabled if the lava command is not executed from a
		terminal, it is executed from a "dumb" terminal or the
		NO_COLOR environment variable is set.
	LAVA_RUNTIME
		Controls the container runtime used by the lava
		command. Valid values are "Dockerd" and
		"DockerdDockerDesktop". If not specified, "Dockerd" is
		used. The values "DockerdRancherDesktop" and
		"DockerdPodmanDesktop" are also valid, but they are
		considered experimental.
	`,
}

// HelpFullReport documents the full report file format.
var HelpFullReport = &base.Command{
	UsageLine: "fullreport",
	Short:     "full report file format",
	Long: `
After a security scan has finished, Lava can dump the internal data
used to generate the report into a file. This file contains the issues
included in the report and those excluded because of a exclusion
rule. This data is serialized as JSON.

For more details about how to enable this functionality, use "lava
help scan" and "lava help run".

# Example

A Lava full report file is a JSON document as shown in the following
example.

	{
	  "vulnerabilities": [
	    {
	      "id": "58cf04ac-8a5c-48c8-b999-8f83f1d6f185",
	      "summary": "Vulnerability title",
	      "score": 6.9,
	      "affected_resource": "golang.org/x/net:0.19.0",
	      "affected_resource_string": "",
	      "fingerprint": "51b4b93663ed7c4d97ad5d9f1f29df109a2b7d272963d0b25d1ae9d387a44d29",
	      "cwe_id": 937,
	      "description": "Vulnerability description.",
	      "details": "Details generated when running the checktype against the target.",
	      "impact_details": "Details about the impact of the vulnerability.",
	      "labels": [
	        "label1",
	        "label2"
	      ],
	      "recommendations": [
	        "Recommendation to fix the issue."
	      ],
	      "references": [
	        "https://example.org"
	      ],
	      "resources": [
	        {
	          "Name": "Resource name",
	          "Header": [
	            "header1",
	            "header2"
	          ],
	          "Rows": [
	            {
	              "header1": "value2",
	              "header2": "value1"
	            }
	          ]
	        }
	      ],
	      "attachments": [
	        {
	          "name": "Attachment name",
	          "content_type": "image/png",
	          "data": "YmFzZTY0LWVuY29kZWQgZGF0YQ=="
	        }
	      ],
	      "vulnerabilities": null,
	      "check_data": {
	        "check_id": "d9a8d860-0fa9-4caa-ae0b-139b81acc94c",
	        "checktype_name": "vulcansec/vulcan-example",
	        "checktype_version": "edge",
	        "status": "FINISHED",
	        "target": ".",
	        "options": "{\"option1\":\"value1\"}",
	        "tag": "",
	        "start_time": "2024-07-25T18:26:03Z",
	        "end_time": "2024-07-25T18:26:07Z"
	      },
	      "severity": "medium",
	      "shown": false,
	      "excluded": false,
	      "rule": {
	        "target": "",
	        "resource": "",
	        "fingerprint": "",
	        "summary": "",
	        "expiration": "0001-01-01T00:00:00Z",
	        "description": ""
	      }
	    }
	  ],
	  "summary": {
	    "count": {
	      "medium": 1
	    },
	    "excluded": 0
	  },
	  "status": [
	    {
	      "checktype": "vulcansec/vulcan-example",
	      "target": ".",
	      "status": "FINISHED"
	    }
	  ]
	}

# vulnerabilities

Every item of the array represents a finding. It includes information
about the issue, the check that detected the issue and it indicates if
it was included in the report generated by Lava.

  - id: random UUID that uniquely identifies the vulnerability in
    every scan.
  - summary: title of the finding.
  - score: vulnerability severity score according to CVSSv3 base
    score.
  - affected_resource: concrete resource affected by the
    vulnerability.
  - affected_resource_string: human-readable version of
    affected_resource.
  - fingerprint: context in where the vulnerability has been found.
  - cwe_id: CWE associated with the vulnerability.
  - description: description of the vulnerability.
  - details: details generated when running the checktype against the
    target.
  - impact_details": details about the impact of the vulnerability.
  - labels: list of labels that tipify the vulnerability.
  - recommendations: list of suggestions to remediate the
    vulnerability.
  - references: list of URLs with additional information.
  - resources: list of self-defined tables for resources sharing the
    same attributes.
  - attachments: list of attachments found when running the check.
  - vulnerabilities: child vulnerabilities.
  - check_data: data about the execution of the checktype that
    generated the report.
  - severity: severity associated with the numeric score.
  - shown: whether the vulnerability is shown in the report.
  - excluded: whether the vulnerability is excluded from the generated
    report because of an exclusion rule.
  - rule: in the case of an excluded finding, which is the matching
    exclusion rule.

# check_data

The check_data field describes the check that detected the finding.

  - check_id: random UUID that uniquely identifies the check.
  - checktype_name: name of the checktype.
  - checktype_version: version of the checktype.
  - status: status of the check. Valid values are:
    - RUNNING: state of a check when running.
    - FINISHED: state of a check after it has finished.
    - ABORTED: state of a check after it has been aborted.
    - FAILED: state of a check when its execution has failed.
    - INCONCLUSIVE: state of a check when it could not be executed.
  - target: target asset of the check.
  - options: check options.
  - tag: not used.
  - start_time: time when the check started.
  - end_time: time when the check finished.

# rule

If a finding is excluded, the rule field contains the matching
exclusion rule.

  - target: regular expression that matches the name of the affected
    target.
  - resource: regular expression that matches the name of the affected
    resource.
  - fingerprint: defines the context in where the vulnerability has
    been found. It includes the checktype image, the affected target,
    the asset type and the checktype options.
  - summary: regular expression that matches the summary of the
    vulnerability.
  - expiration: date on which the exclusion becomes inactive.
  - description: describes the exclusion rule.

# summary

The summary field contains the statistics of the report.

  - count: vulnerability count by severity.
  - excluded: number of excluded vulnerabilities.

# status

The status field contains the status of the checks at the end of the
scan.

  - checktype: name of the checktype.
  - target: target asset of the check.
  - status: status at the end of the scan.
	`,
}

// HelpLavaYAML documents the configuration file format.
var HelpLavaYAML = &base.Command{
	UsageLine: "lava.yaml",
	Short:     "configuration file format",
	Long: `
Each Lava project is defined by a configuration file (usually named
lava.yaml) that defines the parameters of the security scan.

A Lava configuration file is a YAML document that supports environment
variable substitution with ${ENVVAR_NAME} notation.

# Example

A Lava configuration file is a YAML document as shown in the following
example.

	lava: v0.0.0
	checktypes:
	  - checktypes.json
	targets:
	  - identifier: .
	    type: GitRepository
	  - identifier: ${DOCKER_IMAGE}
	    type: DockerImage
	agent:
	  parallel: 4
	report:
	  severity: high
	  exclusions:
	    - description: Ignore test certificates.
	      summary: 'Secret Leaked in Git Repository'
	      resource: '/testdata/certs/'
	log: error

This help topic describes every configuration parameter in detail.

# lava

The "lava" field describes the minimum required version of the Lava
command. For instance,

	lava: v0.0.0

Using a Lava command whose version is lower than the minimum version
required by the configuration file returns an error.

This field is mandatory.

# checktypes

The "checktypes" field contains a list of URLs that point to checktype
catalogs.

If the URL omits the scheme, it is considered a file path relative to
the current working directory of the Lava command. For instance,

	checktypes:
	  - checktypes.json

HTTP and HTTPS URLs are supported. For instance,

	checktypes:
	  - https://example.com/checktypes.json

At least one catalog must be specified.

# targets

The "targets" field contains the list of targets to scan. Every target
is defined by the following properties:

  - identifier: string that identifies the target. For instance, a
    path, a URL, a container image, etc. It is mandatory.
  - type: the asset type of the target. Valid values are "AWSAccount",
    "DockerImage", "GitRepository", "IP", "IPRange", "DomainName",
    "Hostname", "WebAddress" and "Path". It is mandatory.
  - options: map of target-specific options. These options are merged
    with the options coming from the checktype catalog.

For instance,

	targets:
	  - identifier: .
	    type: GitRepository
	    options:
	      branch: master

At least one target must be specified.

# agent

The "agent" field contains the configuration passed to the Vulcan
agent that Lava runs internally. The agent accepts the following
properties:

  - pullPolicy: policy used to decide when to pull a required
    container image. Valid values are "Always", "IfNotPresent" and
    "Never". If not specified, "IfNotPresent" is used.
  - parallel: maximum number of checks that can run in parallel. If
    not specified, this limit is set to one.
  - vars: map with the environment variables passed to the executed
    checktypes.
  - registries: configuration of the required container registries. It
    requires the following properties: "server", "username" and
    "password".

The sample below is a full agent configuration:

	agent:
	  pullPolicy: Always
	  parallel: 4
	  vars:
	    DEBUG: true
	  registries:
	    - server: example.com
	      username: user
	      password: ${REGISTRY_PASSWORD}

It is important to note that Lava is able to use the credentials from
the container runtime CLIs installed in the system. So, if these CLIs
are already logged in, it is not necessary to configure the registry
in the configuration file.

# report

The "report" field describes how to report the findings. It supports
the following properties.

  - severity: minimum severity required to exit with error. Valid
    values are "critical", "high", "medium", "low" and "info". If not
    specified, "high" is used.
  - show: minimum severity required to show a finding. Valid values
    are "critical", "high", "medium", "low" and "info". If not
    specified, the severity value is used.
  - format: output format. Valid values are "human" and "json". If not
    specified, "human" is used.
  - output: path of the output file. If not specified, stdout is used.
  - exclusions: list of rules that define what findings should be
    excluded from the report. It allows to ignore findings because of
    accepted risks, false positives, etc.

The sample below is a full report configuration:

	report:
	  severity: high
	  show: low
	  format: json
	  output: output.json
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
  - expiration: is the date on which the exclusion becomes inactive.
    The format is YYYY/MM/DD.

A finding is excluded if it matches all the filters of an exclusion
rule.

It is possible to provide a human-friendly description of an exclusion
rule using its "description" property.

# log

The "log" field describes the logging level of the Lava command. Valid
values are "debug", "info", "warn" and "error". If not specified,
"info" is used. For instance,

	log: error
	`,
}

// HelpMetrics documents metrics collection.
var HelpMetrics = &base.Command{
	UsageLine: "metrics",
	Short:     "metrics collection",
	Long: `
After a security scan has finished, Lava can generate a metrics file
with security, operational and configuration information. This data is
serialized as JSON.

For more details about how to enable this functionality, use "lava
help scan" and "lava help run".

# Example

A Lava metrics file is a JSON document as shown in the following
example.

	{
	  "checktype_urls": [
	    "https://example.com/checktypes.json"
	  ],
	  "checktypes": {
	    "vulcan-example": {
	      "name": "vulcan-example",
	      "description": "Example Vulcan checktype",
	      "image": "vulcan-example:latest",
	      "assets": ["GitRepository"]
	    }
	  },
	  "lava_version": "v0.4.2",
	  "config_version": "v0.0.0",
	  "duration": 10.986237086,
	  "excluded_vulnerability_count": 3,
	  "exclusion_count": 2,
	  "exit_code": 0,
	  "severity": "high",
	  "start_time": "2023-12-14T14:45:31.925307331+01:00",
	  "targets": [
	    {
	      "Identifier": ".",
	      "AssetType": "GitRepository",
	      "Options": null
	    }
	  ],
	  "vulnerability_count": {
	    "low": 1
	  }
	}

# Collected data

A Lava metrics file contains the following data:

  - checktype_urls: List of URLs pointing to checktype catalogs.
  - checktypes: Checktype catalog used during the scan. It is computed
    by merging all the checktype catalogs specified in checktype_urls.
  - lava_version: Version of the Lava command.
  - config_version: Minimum version of Lava required by the
    configuration file.
  - duration: Duration of the scan.
  - excluded_vulnerability_count: Number of vulnerabilities excluded
    due to matching one or more exclusion rules.
  - exclusion_count: Number of exclusion rules.
  - exit_code: Exit code returned by the Lava command.
  - severity: Minimum severity required to report a finding.
  - start_time: When the scan started.
  - targets: List of targets to scan.
  - vulnerability_count: Number of vulnerabilities grouped by
    severity.
	`,
}
