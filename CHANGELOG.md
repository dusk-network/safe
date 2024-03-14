# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add authenticated encryption and decryption [#6]

### Changed

- Let `Sponge::start` take the io-pattern as `impl Into<Vec<Call>>` [#4]

## [0.1.0] - 2024-03-07

### Added

- Add initial implementation of the SAFE framework [#3]
  - Add `Safe` trait
  - Add `Sponge` struct
  - Add `Error` enum
  - Add README
  - Add Changelog
  - Add documentation

<!-- ISSUES -->
[#6]: https://github.com/dusk-network/safe/issues/6
[#4]: https://github.com/dusk-network/safe/issues/4
[#3]: https://github.com/dusk-network/safe/issues/3

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/safe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dusk-network/safe/releases/tag/v0.1.0
