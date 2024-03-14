// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use crate::{Call, Error, Safe, Sponge};
use zeroize::Zeroize;

/// Trait that together with the [`Safe`] trait, implements everything that is
/// needed for encryption using the SAFE framework.
///
/// The specific implementation of subtraction and equality is needed for being
/// able to use the trait in a zero-knowledge circuit.
pub trait Encryption<T, const W: usize> {
    /// Specifically implement subtraction for the type `T`:
    /// minuend - subtrahend = difference
    fn subtract(&mut self, minuend: &T, subtrahend: &T) -> T;

    /// Implement equality over the type `T`.
    fn assert_equal(&mut self, lhs: &T, rhs: &T) -> bool;
}

fn prepare_sponge<E, T, const W: usize>(
    safe: E,
    domain_sep: u64,
    message_len: usize,
    shared_secret: &[T; 2],
    nonce: &T,
) -> Result<Sponge<E, T, W>, Error>
where
    E: Safe<T, W> + Encryption<T, W>,
    T: Default + Copy + Zeroize,
{
    // start sponge
    let mut sponge = Sponge::start(safe, io_pattern(message_len), domain_sep)?;

    // absorb shared secret
    // absorb nonce
    sponge.absorb(2, shared_secret)?;
    sponge.absorb(1, [*nonce])?;

    // squeeze message_len elements
    sponge.squeeze(message_len)?;

    Ok(sponge)
}

/// This function encrypts a message using a shared secret and nonce, and
/// returns the cipher-text.
pub fn encrypt<E, T, const W: usize>(
    safe: E,
    domain_sep: impl Into<u64>,
    message: impl AsRef<[T]>,
    shared_secret: &[T; 2],
    nonce: T,
) -> Result<Vec<T>, Error>
where
    E: Safe<T, W> + Encryption<T, W>,
    T: Default + Copy + Zeroize,
{
    let message = message.as_ref();
    let message_len = message.len();

    let mut sponge = prepare_sponge(
        safe,
        domain_sep.into(),
        message_len,
        shared_secret,
        &nonce,
    )?;

    // absorb message
    sponge.absorb(message_len, message)?;

    // squeeze one last element
    sponge.squeeze(1)?;

    // encryption cipher is the sponge.output with the message elements added to
    // the first message_len elements
    let mut cipher = Vec::from(&sponge.output[..]);
    for i in 0..message_len {
        cipher[i] = sponge.safe.add(&cipher[i], &message[i]);
    }

    // finish the sponge, erase cipher upon error
    match sponge.finish() {
        Ok(mut output) => {
            output.zeroize();
            Ok(cipher)
        }
        Err(e) => {
            cipher.zeroize();
            Err(e.into())
        }
    }
}

/// This function decrypts a cipher-text, using a shared secret and nonce, and
/// returns the decrypted message upon success.
pub fn decrypt<E, T, const W: usize>(
    safe: E,
    domain_sep: impl Into<u64>,
    cipher: impl AsRef<[T]>,
    shared_secret: &[T; 2],
    nonce: T,
) -> Result<Vec<T>, Error>
where
    E: Safe<T, W> + Encryption<T, W>,
    T: Default + Copy + Zeroize,
{
    let cipher = cipher.as_ref();
    let message_len = cipher.len() - 1;

    let mut sponge = prepare_sponge(
        safe,
        domain_sep.into(),
        message_len,
        &shared_secret,
        &nonce,
    )?;

    // construct the message by subtracting sponge.output from the cipher
    let mut message = Vec::from(&sponge.output[..]);
    for i in 0..message_len {
        message[i] = sponge.safe.subtract(&cipher[i], &message[i]);
    }

    // absorb the obtained message
    sponge.absorb(message_len, &message)?;

    // squeeze 1 element
    sponge.squeeze(1)?;

    // assert that the last element of the cipher is equal to the last element
    // of the sponge output
    let s = sponge.output[message_len];
    if !sponge.safe.assert_equal(&s, &cipher[message_len]) {
        message.zeroize();
        sponge.zeroize();
        return Err(Error::DecryptionFailed);
    };

    // finish sponge, erase message upon error
    match sponge.finish() {
        Ok(mut output) => {
            output.zeroize();
            Ok(message)
        }
        Err(e) => {
            message.zeroize();
            Err(e.into())
        }
    }
}

const fn io_pattern(message_len: usize) -> [Call; 5] {
    [
        Call::Absorb(2),
        Call::Absorb(1),
        Call::Squeeze(message_len),
        Call::Absorb(message_len),
        Call::Squeeze(1),
    ]
}
