// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "encryption")]

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{GENERATOR_EXTENDED, JubJubExtended, JubJubScalar};
use dusk_safe::{Encryption, Error, Safe, decrypt, encrypt};
use ff::Field;
use rand::SeedableRng;
use rand::rngs::StdRng;

const W: usize = 7;
const DOMAIN: u64 = 1 << 31;

#[derive(Default, Debug, Clone, Copy, PartialEq)]
struct HashState();

impl Safe<BlsScalar, W> for HashState {
    // the permuted state is the previous state hashed with the index of each
    // element
    fn permute(&mut self, state: &mut [BlsScalar; W]) {
        let mut state_bytes: Vec<u8> =
            state.iter().flat_map(|s| s.to_bytes()).collect();

        state.iter_mut().enumerate().for_each(|(i, s)| {
            state_bytes.push(i as u8);
            *s = BlsScalar::hash_to_scalar(&state_bytes[..]);
            state_bytes.pop();
        });
    }

    // Bind the mechanics fixture to the encoded pattern and domain.
    fn tag(&mut self, input: &[u8]) -> BlsScalar {
        BlsScalar::hash_to_scalar(input)
    }

    fn add(&mut self, right: &BlsScalar, left: &BlsScalar) -> BlsScalar {
        right + left
    }
}

impl Encryption<BlsScalar, W> for HashState {
    fn subtract(
        &mut self,
        minuend: &BlsScalar,
        subtrahend: &BlsScalar,
    ) -> BlsScalar {
        minuend - subtrahend
    }

    fn is_equal(&mut self, lhs: &BlsScalar, rhs: &BlsScalar) -> bool {
        lhs == rhs
    }
}

impl HashState {
    pub fn new() -> Self {
        Self()
    }
}

fn encryption_variables(
    rng: &mut StdRng,
    message_len: usize,
) -> (Vec<BlsScalar>, JubJubExtended, BlsScalar) {
    let mut message = Vec::with_capacity(message_len);
    for _ in 0..message_len {
        message.push(BlsScalar::random(&mut *rng));
    }
    let shared_secret = GENERATOR_EXTENDED * &JubJubScalar::random(&mut *rng);
    let nonce = BlsScalar::random(&mut *rng);

    (message, shared_secret, nonce)
}

#[test]
fn encrypt_decrypt() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    let message_len = 42usize;

    let (message, shared_secret, nonce) =
        encryption_variables(&mut rng, message_len);

    let cipher = encrypt(
        HashState::new(),
        DOMAIN,
        &message,
        &shared_secret.to_hash_inputs(),
        &nonce,
    )?;

    let decrypted_message = decrypt(
        HashState::new(),
        DOMAIN,
        &cipher,
        &shared_secret.to_hash_inputs(),
        &nonce,
    )?;

    assert_eq!(decrypted_message, message);

    Ok(())
}

#[test]
fn empty_message_and_short_ciphers_fail() {
    let shared_secret = [BlsScalar::from(1), BlsScalar::from(2)];
    let nonce = BlsScalar::from(3);

    for cipher in [&[][..], &[BlsScalar::from(4)][..]] {
        assert_eq!(
            decrypt(HashState::new(), DOMAIN, cipher, &shared_secret, &nonce),
            Err(Error::InvalidIOPattern)
        );
    }
    assert_eq!(
        encrypt(HashState::new(), DOMAIN, [], &shared_secret, &nonce),
        Err(Error::InvalidIOPattern)
    );
}

#[test]
fn incorrect_shared_secret_fails() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    let message_len = 21usize;

    let (message, shared_secret, nonce) =
        encryption_variables(&mut rng, message_len);

    let cipher = encrypt(
        HashState::new(),
        DOMAIN,
        &message,
        &shared_secret.to_hash_inputs(),
        &nonce,
    )?;

    let wrong_shared_secret =
        GENERATOR_EXTENDED * &JubJubScalar::random(&mut rng);
    assert_ne!(shared_secret, wrong_shared_secret);

    assert_eq!(
        decrypt(
            HashState::new(),
            DOMAIN,
            &cipher,
            &wrong_shared_secret.to_hash_inputs(),
            &nonce,
        )
        .unwrap_err(),
        Error::DecryptionFailed
    );

    Ok(())
}

#[test]
fn incorrect_nonce_fails() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    let message_len = 21usize;

    let (message, shared_secret, nonce) =
        encryption_variables(&mut rng, message_len);

    let cipher = encrypt(
        HashState::new(),
        DOMAIN,
        &message,
        &shared_secret.to_hash_inputs(),
        &nonce,
    )?;

    let wrong_nonce = BlsScalar::random(&mut rng);
    assert_ne!(nonce, wrong_nonce);

    assert_eq!(
        decrypt(
            HashState::new(),
            DOMAIN,
            &cipher,
            &shared_secret.to_hash_inputs(),
            &wrong_nonce,
        )
        .unwrap_err(),
        Error::DecryptionFailed
    );

    Ok(())
}

#[test]
fn incorrect_domain_fails() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    let message_len = 21usize;

    let (message, shared_secret, nonce) =
        encryption_variables(&mut rng, message_len);

    let cipher = encrypt(
        HashState::new(),
        DOMAIN,
        &message,
        &shared_secret.to_hash_inputs(),
        &nonce,
    )?;

    assert_eq!(
        decrypt(
            HashState::new(),
            1u64,
            &cipher,
            &shared_secret.to_hash_inputs(),
            &nonce,
        )
        .unwrap_err(),
        Error::DecryptionFailed
    );

    Ok(())
}

#[test]
fn independent_encryption_vectors() {
    // Generated independently with Python integer arithmetic/hashlib, not with
    // this crate. This is a SAFE mechanics KAT, not a production backend KAT.
    for line in include_str!("fixtures/encryption.txt").lines().skip(1) {
        let (length, hex) = line.split_once(' ').unwrap();
        let n = length.parse::<usize>().unwrap();
        let expected: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let message: Vec<_> =
            (1..=n).map(|i| BlsScalar::from(i as u64)).collect();
        let key = [BlsScalar::from(7), BlsScalar::from(8)];
        let nonce = BlsScalar::from(9);
        let cipher =
            encrypt(HashState::new(), DOMAIN, &message, &key, &nonce).unwrap();
        assert_eq!(
            cipher.iter().flat_map(|s| s.to_bytes()).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            decrypt(HashState::new(), DOMAIN, &cipher, &key, &nonce).unwrap(),
            message
        );
    }
}

#[test]
fn incorrect_cipher_fails() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    let rate = W - 1;
    for message_len in [
        1,
        rate - 1,
        rate,
        rate + 1,
        2 * rate - 1,
        2 * rate,
        2 * rate + 1,
        21,
    ] {
        let (message, shared_secret, nonce) =
            encryption_variables(&mut rng, message_len);
        let key = shared_secret.to_hash_inputs();
        let cipher = encrypt(HashState::new(), DOMAIN, &message, &key, &nonce)?;
        assert_eq!(
            decrypt(HashState::new(), DOMAIN, &cipher, &key, &nonce)?,
            message
        );
        // Change only one ciphertext element, including every position and the
        // tag.
        for position in 0..cipher.len() {
            let mut wrong_cipher = cipher.clone();
            wrong_cipher[position] += BlsScalar::from(42);
            assert_eq!(
                decrypt(HashState::new(), DOMAIN, &wrong_cipher, &key, &nonce),
                Err(Error::DecryptionFailed),
                "length {message_len}, position {position}"
            );
        }
    }
    Ok(())
}
