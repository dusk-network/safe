// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Check: cargo run --example generate_encryption_fixtures
//! Regenerate explicitly: append -- --write.
//!
//! Original vectors used Python integer arithmetic and hashlib:
//! https://github.com/dusk-network/safe/blob/d4802e77f65e0163fcfdf7d54275e572b718724c/tests/fixtures/generate.py
//! Retained by the archival (non-release) tag
//! `provenance/encryption-fixtures-python`.
//! Source SHA-256:
//! f623540c62aa17997b53a8eaa82b19423075e1662ecfae3520c3989a8c9bd075
//! This reference calls no dusk-safe code, but shares field arithmetic/hashing
//! with the Rust tests. The hash-expanded backend is NOT a cryptographic
//! permutation. Fixed parameters: width 7, key [7, 8], nonce 9, domain 2^31,
//! message [1, ..., n]; this is not a general-purpose encryption
//! implementation.

use std::fmt::Write;
use std::path::Path;
use std::{env, fs};

use dusk_bls12_381::BlsScalar;

const RATE: usize = 6;

fn permute(state: &mut [BlsScalar; RATE + 1]) {
    let mut bytes: Vec<_> = state.iter().flat_map(|s| s.to_bytes()).collect();
    for (i, value) in state.iter_mut().enumerate() {
        bytes.push(i as u8);
        *value = BlsScalar::hash_to_scalar(&bytes);
        bytes.pop();
    }
}

fn reference_cipher(n: usize) -> Vec<BlsScalar> {
    // Canonical A(3), S(n), A(n), S(1), then the big-endian domain.
    let mut tag: Vec<_> = [0x8000_0003, n as u32, 0x8000_0000 | n as u32, 1]
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .collect();
    tag.extend_from_slice(&(1u64 << 31).to_be_bytes());
    let mut state = [BlsScalar::zero(); RATE + 1];
    state[0] = BlsScalar::hash_to_scalar(&tag);
    for (i, value) in [7u64, 8, 9].into_iter().enumerate() {
        state[i + 1] = BlsScalar::from(value);
    }

    let mut cipher = vec![BlsScalar::zero(); n];
    for block in cipher.chunks_mut(RATE) {
        permute(&mut state);
        block.copy_from_slice(&state[1..=block.len()]);
    }
    // Absorb plaintext from position zero, adding it to the saved masks too.
    for (block_index, block) in cipher.chunks_mut(RATE).enumerate() {
        if block_index != 0 {
            permute(&mut state);
        }
        for (i, value) in block.iter_mut().enumerate() {
            let message = BlsScalar::from((block_index * RATE + i + 1) as u64);
            state[i + 1] += message;
            *value += message;
        }
    }
    permute(&mut state);
    cipher.push(state[1]);
    cipher
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut content = String::from(
        "# Originally Python stdlib; see examples/generate_encryption_fixtures.rs for provenance.\n",
    );
    for n in [1, 6, 7, 13] {
        write!(content, "{n} ")?;
        for byte in reference_cipher(n).iter().flat_map(|s| s.to_bytes()) {
            write!(content, "{byte:02x}")?;
        }
        content.push('\n');
    }
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/encryption.txt");
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => {
            assert_eq!(fs::read_to_string(path)?, content, "frozen vectors differ");
            println!("four frozen AE mechanics vectors match");
        }
        [flag] if flag == "--write" => fs::write(path, content)?,
        _ => return Err("usage: cargo run --example generate_encryption_fixtures [-- --write]".into()),
    }
    Ok(())
}
