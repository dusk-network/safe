# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Wipe old output allocations before growth, including when continuing cloned sponges [#37]
- Return an error and invalidate the sponge when output allocation fails [#37]
- Wipe encryption/decryption temporary vectors on error and unwinding [#37]
- Permanently invalidate sponges after operation errors or explicit zeroization [#37]
- Reject IO patterns whose aggregated runs exceed the 31-bit encoding limit [#37]
- Reject sponge widths below two at construction [#37]
- Redact permutation state, buffered output and backend data from sponge debugging [#37]
- Reject empty ciphertext consistently in `decrypt` [#35]

### Changed

- Simplify sponge finalization and IO-pattern validation
- Raise the MSRV to Rust 1.96.1 [#32]

### Removed

- Remove `PartialEq` from `Sponge` [#39]

## [0.3.0] - 2025-02-06

### Changed

- Update dependency `dusk-bls12_381` to 0.14
- Update dependency `dusk-jubjub` to 0.15
- Change rust toolchain version to `nightly-2023-11-10` (1.75.0) [#26]

## [0.2.1] - 2024-05-08

### Changed

- Omit unnecessary check on `message_len` in `decrypt` [#21]

## [0.2.0] - 2024-03-27

### Added

- Add authenticated encryption and decryption [#6]
- Add check for `cipher.len == message.len + 1` in `encrypt` and `decrypt` [#9]
- Add check for max squeeze and absorb len [#17]

### Changed

- Let `Sponge::start` take the io-pattern as `impl Into<Vec<Call>>` [#4]
- Change `nonce` to be `&T` instead of `T` in `encrypt` and `decrypt` [#9]
- Improve crate documentation [#13]
- Rename `Encryption::assert_equal` to `Encryption::is_equal` [#15]

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
[#39]: https://github.com/dusk-network/safe/issues/39
[#37]: https://github.com/dusk-network/safe/issues/37
[#35]: https://github.com/dusk-network/safe/issues/35
[#32]: https://github.com/dusk-network/safe/issues/32
[#26]: https://github.com/dusk-network/safe/issues/26
[#21]: https://github.com/dusk-network/safe/issues/21
[#17]: https://github.com/dusk-network/safe/issues/17
[#15]: https://github.com/dusk-network/safe/issues/15
[#13]: https://github.com/dusk-network/safe/issues/13
[#9]: https://github.com/dusk-network/safe/issues/9
[#6]: https://github.com/dusk-network/safe/issues/6
[#4]: https://github.com/dusk-network/safe/issues/4
[#3]: https://github.com/dusk-network/safe/issues/3

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/safe/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/dusk-network/safe/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/dusk-network/safe/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dusk-network/safe/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dusk-network/safe/releases/tag/v0.1.0
