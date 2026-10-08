# Safe

Sponge API framework for field elements with IO-pattern validation. Underpins Poseidon hashing and authenticated encryption across the Dusk network. Single `no_std` crate with `alloc`.

## Repository Map

```
safe/
├── src/
│   ├── lib.rs          # Call enum, IO-pattern encoding and validation
│   ├── sponge.rs       # Safe<T, W> trait and Sponge<S, T, W> struct
│   ├── encryption.rs   # encrypt()/decrypt() via sponge (encryption feature)
│   └── error.rs        # Error types
├── tests/              # Integration tests
├── Cargo.toml
└── Makefile
```

## Commands

Run `make help` to see all available targets.

## Feature Flags

| Feature      | Description                          | Default |
|--------------|--------------------------------------|---------|
| `encryption` | Authenticated encrypt/decrypt functions | No      |

## Architecture

### Sponge API

The core abstraction is the **SAFE (Sponge API for Field Elements)** framework:

- **`Safe<T, W>` trait** — defines the sponge permutation, tag creation, and field addition. Parameterized by element type `T` and state width `W`. The trait's `add` method enables usage within zero-knowledge circuits.
- **`Sponge<S, T, W>` struct** — stateful sponge that enforces an IO-pattern (sequence of `Absorb(n)` / `Squeeze(n)` calls). Violations zeroize the state and return an error.
- **IO-pattern validation** — patterns are encoded into a tag input that binds the sponge instance to its expected call sequence and domain separator. Consecutive same-type calls are aggregated.

### Encryption

Behind the `encryption` feature:

- **`Encryption<T, W>` trait** — extends `Safe` with subtraction and equality (also circuit-compatible).
- **`encrypt` / `decrypt`** — authenticated encryption using the sponge. Absorbs a shared secret and nonce, then uses field addition/subtraction to combine the message and squeezed keystream. A final squeeze element serves as an authentication tag.

### Key Dependencies

- `zeroize` — memory safety for sponge state on drop and on error

## Conventions

- **`no_std`** with `alloc`. Do not add `std` dependencies.
- **`zeroize`** — sponge state is zeroized on drop and on any IO-pattern violation.
- **No PLONK dependency** — debug mode tests are fine here.
- **Edition 2021**.

## Elevated Care Zones

This is a **cryptographic primitive** — bugs here propagate to all Poseidon hash and encryption operations across the Dusk stack. Treat every change as elevated care:

- Run the full test suite with `make test`
- Verify both `--features=encryption` and `--no-default-features` configurations
- Do not introduce branches or early returns on secret data
- Verify edge cases (zero-length patterns, boundary lengths)

## Change Propagation

| Changed | Also verify |
|---------|-------------|
| `safe`  | `Poseidon252`, then its dependents (`merkle`, `phoenix`, `rusk`) |

## Git Conventions

- Default branch: `main`
- License: MPL-2.0

### Commit messages

Format: `<Description>` — imperative mood, capitalize first word. Single-crate repo, no scope prefix needed.

Cross-cutting prefixes for non-code changes: `ci`, `docs`, `chore`.

Examples:
- `Add IO-pattern length validation`
- `Fix sponge state leak on absorb error`
- `ci: Update workflow to use Makefile targets`

### Changelog

Add an entry to `CHANGELOG.md` under `[Unreleased]` only for a change that users of the crate can see. Tests, CI, tooling and internal refactors get no entry.

- Write one fact per entry, in one sentence. Two facts get two entries.
- Name what changed at the crate's surface: the public item and its new behavior. Do not describe how the code does it.
- Name the released item that a breaking change breaks.
- Keep the reason, the consequences and the migration steps in the linked issue, not in the entry.
- Choose the section by the effect on users: new things go under `Added`, changed behavior goes under `Changed`, and removed things go under `Removed`. Use `Fixed` only for a bug that a release had. For a bug in unreleased code, correct the entry that added that code.
- Link the tracking GitHub issue, not the PR, and no other tracking identifier. Use the link format that the file already uses. A reference link needs its definition in the block at the bottom.
- Add to the existing section headings, and leave the other entries as they are.
- Use the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.
- Follow standard markdown formatting: separate headings from surrounding content with blank lines, leave a blank line before and after lists, and never have two headings back-to-back without a blank line between them.
