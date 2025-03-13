# Contributing to Containers Projects: Rust Language Guidelines

This is an appendix to the main [Contributing Guide](./CONTRIBUTING.md) and is intended to be read after that document.
It contains guidelines and general rules for contributing to projects under the Containers org that are written in the Rust language.
At present, this means the following repositories:

- [netavark](https://github.com/containers/netavark)
- [aardvark](https://github.com/containers/aardvark-dns/)

## Topics

* [Rust Dependency updates](#rust-dependency-updates)
* [Test Changes with Podman](#test-changes-with-podman)

## Rust Dependency updates

To automatically keep dependencies up to date we use the [renovate](https://github.com/renovatebot/renovate) bot.
The bot automatically opens new PRs with updates that should be merged by maintainers.

However sometimes, especially during development, it can be the case that you like to update a dependency.

To do this, you can either run `cargo update` (to update all dependencies) or change the version of the specific dependency you want to update in `Cargo.toml`.

Please run `make` after this to ensure the project still builds after your dependency updates.
It may be necessary to make code changes to address the updates dependencies.

Then commit the changes and open a PR. If you want to add other changes it is recommended to keep the
dependency updates in their own commit as this makes reviewing them much easier.

## Test Changes with Podman

While Netavark and Aardvark have their own test suites, to fully test the tools, it is important to verify they function with Podman.
The easiest way to do this is to place them in the `/usr/libexec/podman` folder, replacing the existing `netavark` and `aardvark-dns` binaries.
It is recommended to move the system `netavark` and `aardvark-dns` instead of removing them (e.g. `mv /usr/libexec/podman/netavark /usr/libexec/podman/netavark-old`) so you can easily revert to the packaged version of Netavark once testing is complete.
On systems with SELinux enabled, `netavark` and `aardvark-dns` should have their SELinux labels set to match the packaged versions (e.g. `chcon --reference=/usr/libexec/podman/netavark-old /usr/libexec/podman/netavark`) to ensure correct function.
Once this is complete, the system Podman will use your locally-build Netavark and Aardvark binaries, allowing you to test all Podman networking functionality.
