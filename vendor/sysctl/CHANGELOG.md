# Changelog
All notable changes to this project will be documented in this file.

## [0.4.3] - 2021-11-01
### Changed
- Remove a leftover debug println.

## [0.4.2] - 2021-08-03
### Changed
- Add Cirrus CI for FreeBSD, macOS and Linux.
- Bump thiserror crate.
- Use sysctlnametomib(3) where available.
- Use sysctlbyname(3) on FreeBSD.
- Tell docs.rs to build docs for FreeBSD too.
- Don't include docs in package to reduce size.

## [0.4.1] - 2021-04-23
### Changed
- Replace deprecated failure crate with thiserror.
- Fix clippy lints.

## [0.4.0] - 2019-07-24
### Changed
- Add Linux support.
- Huge refactor.
- Improve BSD code to provide a cross platform compatible API.
- [BREAKING] Make static functions private, all calls now go through the Ctl object.

## [0.3.0] - 2019-01-07
### Changed
- Improve error handling.
- Publish CtlInfo struct.
- Add Cirrus CI script.

## [0.2.0] - 2018-05-28
### Changed
- Add iterator support (thanks to Fabian Freyer!).
- Add struct interface for control.
- Add documentation for macOS.
- Use failure create for error handling.

## [0.1.4] - 2018-01-04
### Changed
- Fix documentation link
- Fix test on FreeBSD

## [0.1.3] - 2018-01-04
### Added
- Macos support.

## [0.1.2] - 2017-05-23
### Added
- This changelog.
- API to get values by OID.
- Example value\_oid\_as.rs
- Node types can also contain data so treat Nodes same as Struct/Opaque.
