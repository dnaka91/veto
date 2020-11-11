<!-- markdownlint-disable MD024 -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - ReleaseDate

## [0.2.0]

### Added

- Add analyze command to test settings ([#2](https://github.com/dnaka91/veto/issues/2)).
- Add benchmarks for the matcher logic.

### Changed

- Don't try to remove old IPs from the firewall ([#5](https://github.com/dnaka91/veto/issues/5)).
- Remove the connection state filter ([#6](https://github.com/dnaka91/veto/issues/6)).
- Apply iptables filters to the FORWARD chain ([#10](https://github.com/dnaka91/veto/issues/10)).
- Several smaller improvements to the docs, readme and so on.
- Add ipset as dependency to the deb package.
- Don't fail on already added or deleted IP.

## [0.1.0]

### Added

- Initial release.

[Unreleased]: https://github.com/dnaka91/veto/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/dnaka91/veto/releases/tag/v0.2.0
[0.1.0]: https://github.com/dnaka91/veto/releases/tag/v0.1.0
