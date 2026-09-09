// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![no_std]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

extern crate alloc;
use alloc::vec::Vec;

mod error;
mod sponge;

pub use error::Error;
pub use sponge::{Safe, Sponge};

#[cfg(feature = "encryption")]
mod encryption;
#[cfg(feature = "encryption")]
pub use encryption::{Encryption, decrypt, encrypt};

/// Enum to encode the calls to [`Sponge::absorb`] and [`Sponge::squeeze`] that
/// make the IO-pattern.
///
/// An implementation must forbid any further usage of the sponge and any of
/// its internal data if this pattern is not followed. In particular, the output
/// from any previous calls to [`Sponge::squeeze`] must not be used.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Call {
    /// Absorb the specified amount of elements into the state.
    Absorb(usize),
    /// Squeeze the specified amount of elements from the state.
    Squeeze(usize),
}

impl Call {
    /// Returns the length of the call.
    pub fn call_len(&self) -> &usize {
        match self {
            Call::Absorb(len) | Call::Squeeze(len) => len,
        }
    }
}

/// Encode the input for the tag for the sponge instance, using the
/// domain-separator and IO-pattern.
///
/// This function returns an error if the IO-pattern is not sensible.
///
/// # Parameters
///
/// - `iopattern`: A slice of `Call` enum representing the IO-pattern.
/// - `domain_sep`: The domain separator to be used for encoding.
///
/// # Returns
///
/// A `Result` containing a vector of `u8` on success, or an `Error` if the
/// IO-pattern is not valid.
fn tag_input(
    iopattern: impl AsRef<[Call]>,
    domain_sep: u64,
) -> Result<Vec<u8>, Error> {
    // make sure the IO-pattern is valid: start with absorb, end with squeeze
    // and none of the calls have a len == 0
    validate_io_pattern(iopattern.as_ref())?;

    // ABSORB_MASK = 0b10000000_00000000_00000000_00000000
    const ABSORB_MASK: u32 = 0x8000_0000;

    let mut input = Vec::new();
    // Validation guarantees that the first operation is absorb.
    let mut kind = ABSORB_MASK;
    let mut length = 0u32;

    // Aggregate lengths separately from the operation bit. Every encoded run,
    // not just every individual call, must fit in the low 31 bits. Emit each
    // completed run directly instead of updating an intermediate word vector.
    for call in iopattern.as_ref() {
        let (next_kind, len) = match call {
            Call::Absorb(len) => (ABSORB_MASK, *len as u32),
            Call::Squeeze(len) => (0, *len as u32),
        };
        if next_kind != kind {
            input.extend((kind | length).to_be_bytes());
            kind = next_kind;
            length = 0;
        }
        length = length
            .checked_add(len)
            .filter(|length| *length < ABSORB_MASK)
            .ok_or(Error::InvalidIOPattern)?;
    }
    input.extend((kind | length).to_be_bytes());

    // Add the domain separator to the hash input
    input.extend(domain_sep.to_be_bytes());

    Ok(input)
}

/// Check that the IO-pattern is sensible. This means that:
/// - It doesn't start with a call to squeeze
/// - It doesn't end with a call to absorb
/// - Every call to absorb or squeeze has a length between 0 < len < 2^31
///
/// # Parameters
///
/// - `iopattern`: A slice of `Call` enum representing the IO-pattern.
///
/// # Returns
///
/// A `Result` indicating success if the IO-pattern is valid, otherwise an
/// `Error`.
fn validate_io_pattern(iopattern: impl AsRef<[Call]>) -> Result<(), Error> {
    // make sure the IO-pattern starts with a call to absorb and ends with a
    // call to squeeze
    match (iopattern.as_ref().first(), iopattern.as_ref().last()) {
        (Some(Call::Absorb(_)), Some(Call::Squeeze(_))) => {}
        _ => return Err(Error::InvalidIOPattern),
    }

    // check that every call to absorb or squeeze has a length between:
    // 0 < len < 2^31
    const MAX_LEN: usize = u32::MAX as usize >> 1;
    if iopattern.as_ref().iter().any(|call| {
        let call_len = *call.call_len();
        call_len == 0 || call_len > MAX_LEN
    }) {
        Err(Error::InvalidIOPattern)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec;

    use super::*;

    #[test]
    fn aggregate_lengths_fit_the_encoding() {
        const MAX: usize = (1 << 31) - 1;
        for pattern in [
            vec![Call::Absorb(MAX), Call::Absorb(1), Call::Squeeze(1)],
            vec![Call::Absorb(1), Call::Squeeze(MAX), Call::Squeeze(1)],
            vec![
                Call::Absorb(1),
                Call::Squeeze(MAX),
                Call::Squeeze(2),
                Call::Absorb(1),
                Call::Squeeze(1),
            ],
            vec![
                Call::Absorb(1),
                Call::Squeeze(MAX),
                Call::Squeeze(1),
                Call::Absorb(2),
                Call::Squeeze(1),
            ],
        ] {
            assert_eq!(tag_input(pattern, 42), Err(Error::InvalidIOPattern));
        }
        let pattern = [
            Call::Absorb(MAX - 1),
            Call::Absorb(1),
            Call::Squeeze(MAX - 1),
            Call::Squeeze(1),
        ];
        let mut expected = vec![0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff];
        expected.extend(42u64.to_be_bytes());
        assert_eq!(tag_input(pattern, 42).unwrap(), expected);
        assert_eq!(
            tag_input([Call::Absorb(4), Call::Absorb(1), Call::Squeeze(3)], 42)
                .unwrap(),
            [0x80, 0, 0, 5, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 42]
        );
        // Switching back to absorb must flush the squeeze run and reset its
        // length; this literal is independent of the encoder implementation.
        assert_eq!(
            tag_input(
                [
                    Call::Absorb(2),
                    Call::Absorb(3),
                    Call::Squeeze(4),
                    Call::Squeeze(5),
                    Call::Absorb(6),
                    Call::Squeeze(7),
                    Call::Squeeze(8),
                ],
                42,
            )
            .unwrap(),
            [
                0x80, 0, 0, 5, 0, 0, 0, 9, 0x80, 0, 0, 6, 0, 0, 0, 15, 0, 0, 0,
                0, 0, 0, 0, 42,
            ]
        );
    }

    #[test]
    fn test_validate_io_pattern() {
        // test valid
        let iopattern = vec![Call::Absorb(42), Call::Squeeze(3)];
        assert!(validate_io_pattern(&iopattern).is_ok());

        let iopattern = vec![
            Call::Absorb(42),
            Call::Absorb(5),
            Call::Squeeze(4),
            Call::Squeeze(3),
        ];
        assert!(validate_io_pattern(&iopattern).is_ok());

        let iopattern = vec![
            Call::Absorb(42),
            Call::Absorb(5),
            Call::Squeeze(4),
            Call::Absorb(5),
            Call::Squeeze(3),
            Call::Squeeze(3),
        ];
        assert!(validate_io_pattern(&iopattern).is_ok());

        let iopattern = vec![
            Call::Absorb(42),
            Call::Squeeze(4),
            Call::Absorb(5),
            Call::Squeeze(4),
            Call::Absorb(5),
            Call::Squeeze(3),
            Call::Absorb(5),
            Call::Squeeze(3),
        ];
        assert!(validate_io_pattern(&iopattern).is_ok());

        // test invalid
        let iopattern = vec![];
        assert!(validate_io_pattern(&iopattern).is_err());

        let iopattern = vec![Call::Absorb(2)];
        assert!(validate_io_pattern(&iopattern).is_err());

        let iopattern = vec![Call::Squeeze(2)];
        assert!(validate_io_pattern(&iopattern).is_err());

        let iopattern = vec![Call::Absorb(0), Call::Squeeze(2)];
        assert!(validate_io_pattern(&iopattern).is_err());

        let iopattern = vec![Call::Absorb(42), Call::Squeeze(0)];
        assert!(validate_io_pattern(&iopattern).is_err());

        let iopattern =
            vec![Call::Squeeze(42), Call::Absorb(3), Call::Squeeze(4)];
        assert!(validate_io_pattern(&iopattern).is_err());

        let iopattern = vec![
            Call::Absorb(42),
            Call::Absorb(3),
            Call::Squeeze(4),
            Call::Absorb(3),
        ];
        assert!(validate_io_pattern(&iopattern).is_err());

        let iopattern = vec![
            Call::Absorb(42),
            Call::Absorb(3),
            Call::Squeeze(0),
            Call::Absorb(3),
            Call::Squeeze(4),
        ];
        assert!(validate_io_pattern(&iopattern).is_err());

        let iopattern =
            vec![Call::Absorb(3), Call::Absorb(1 << 31), Call::Squeeze(1)];
        assert!(validate_io_pattern(&iopattern).is_err());
    }

    #[test]
    fn test_tag_input() -> Result<(), Error> {
        let domain_sep = 42;

        // check unequal patterns fail
        let pattern1 = vec![Call::Absorb(2), Call::Squeeze(10)];
        let pattern2 = vec![Call::Absorb(2), Call::Squeeze(1)];
        assert_ne!(
            tag_input(&pattern1, domain_sep)?,
            tag_input(&pattern2, domain_sep)?
        );

        // check patterns whose aggregate are equal
        let pattern1 = vec![Call::Absorb(1), Call::Absorb(1), Call::Squeeze(1)];
        let pattern2 = vec![Call::Absorb(2), Call::Squeeze(1)];
        assert_eq!(
            tag_input(&pattern1, domain_sep)?,
            tag_input(&pattern2, domain_sep)?
        );

        let pattern1 = vec![Call::Absorb(2), Call::Squeeze(10)];
        let pattern2 = vec![
            Call::Absorb(2),
            Call::Squeeze(1),
            Call::Squeeze(1),
            Call::Squeeze(8),
        ];
        assert_eq!(
            tag_input(&pattern1, domain_sep)?,
            tag_input(&pattern2, domain_sep)?
        );

        let pattern1 = vec![
            Call::Absorb(2),
            Call::Absorb(2),
            Call::Squeeze(1),
            Call::Squeeze(1),
            Call::Squeeze(1),
            Call::Absorb(2),
            Call::Absorb(2),
            Call::Squeeze(1),
            Call::Squeeze(8),
        ];
        let pattern2 = vec![
            Call::Absorb(3),
            Call::Absorb(1),
            Call::Squeeze(2),
            Call::Squeeze(1),
            Call::Absorb(1),
            Call::Absorb(3),
            Call::Squeeze(5),
            Call::Squeeze(4),
        ];
        assert_eq!(
            tag_input(&pattern1, domain_sep)?,
            tag_input(&pattern2, domain_sep)?
        );

        Ok(())
    }
}
