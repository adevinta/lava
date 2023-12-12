# Lava

Lava is an open source vulnerability scanner that makes it easy to run
security checks in your local and CI/CD environments.

<p align="center"><img width="128" alt="Lava logo" src="https://github.com/adevinta/lava-resources/releases/download/logo/v0.1.0/lava_512px.png"></p>

Lava is part of the [Vulcan ecosystem][vulcan-docs] and it is built on
top of the same components that power Vulcan.
Thus, Lava continuously benefits from Vulcan improvements.
In fact, Lava is compatible with the [vulcan-checks][vulcan-checks]
catalog shipped with Vulcan.

## Install

### Install From Source

Install the Lava command with `go install`.

```
go install github.com/adevinta/lava/cmd/lava@latest
```

### GitHub Actions

Lava is also available as an action that can be used from GitHub
Actions workflows.
Visit [adevinta/lava-action][lava-action] for usage instructions.

## Documentation

Lava is self-documented.
Please run `lava help` to get more information about the available
commands and other related topics.

## Contributing

**This project is in an early stage, we are not accepting external
contributions yet.**

To contribute, please read the [contribution
guidelines][contributing].


[vulcan-docs]: https://adevinta.github.io/vulcan-docs
[vulcan-checks]: https://github.com/adevinta/vulcan-checks
[lava-action]: https://github.com/adevinta/lava-action
[contributing]: /CONTRIBUTING.md
