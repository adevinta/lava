# Lava

Lava is an open source vulnerability scanner that makes it easy to run
security checks in your local and CI/CD environments.

<p align="center"><img width="128" alt="Lava logo" src="https://github.com/adevinta/lava-resources/releases/download/logo/v0.1.0/lava_512px.png"></p>

Lava is part of the [Vulcan ecosystem] and it is built on top of the
same components that power Vulcan.
Thus, Lava continuously benefits from Vulcan improvements.
In fact, Lava is compatible with the [vulcan-checks] catalog shipped
with Vulcan.

## Install

### Binary distributions

Official binary distributions are available at
https://github.com/adevinta/lava/releases.

### Install from source

Install the Lava command with `go install`.

```
go install github.com/adevinta/lava/cmd/lava@latest
```

### GitHub Actions

GitHub Actions are provided to make it easy to run Lava from a GitHub
Actions workflow.
Visit https://adevinta.github.io/lava-docs/github_actions.html for
more details.

## Documentation

The user documentation is available at
https://adevinta.github.io/lava-docs.

Also, the Lava command is self-documented.
Run `lava help` to get more information about the available commands
and other related topics.

## Contributing

**This project is in an early stage, we are not accepting external
contributions yet.**

To contribute, please read the [contribution
guidelines].


[Vulcan ecosystem]: https://adevinta.github.io/vulcan-docs
[vulcan-checks]: https://github.com/adevinta/vulcan-checks
[contribution guidelines]: /CONTRIBUTING.md
