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

/// Enum to encode the calls to [`Sponge::absorb`] and [`Sponge::squeeze`] that
/// make the io-pattern.
///
/// An implementation must forbid to any further usage of the sponge and any of
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
    /// Return the internal call length
    pub fn call_len(&self) -> &usize {
        match self {
            Call::Absorb(len) => len,
            Call::Squeeze(len) => len,
        }
    }
}

/// Encode the input for the tag for the sponge instance, using the
/// domain-separator and IO-pattern.
///
/// This function returns an error if the io-pattern is not sensible.
fn tag_input(
    iopattern: impl AsRef<[Call]>,
    domain_sep: u64,
) -> Result<Vec<u8>, Error> {
    // make sure the io-pattern is valid: start with absorb, end with squeeze
    // and none of the calls have a len == 0
    validate_io_pattern(iopattern.as_ref())?;

    // ABSORB_MASK = 0b10000000_00000000_00000000_00000000
    const ABSORB_MASK: u32 = 0x8000_0000;

    // we know that the first call needs to be to absorb so we can initialize
    // the vec
    let mut input_u32 = Vec::new();
    input_u32.push(ABSORB_MASK);

    // Aggregate and encode calls to absorb and squeeze
    iopattern.as_ref().iter().for_each(|call| {
        // get a mutable ref to the previously encoded call
        // Note: This is safe since we initialized the vector with one element
        let l = input_u32.len();
        let prev = &mut input_u32[l - 1];
        match call {
            // if both this and the previous calls are to absorb, aggregate them
            Call::Absorb(len) if *prev & ABSORB_MASK != 0 => {
                *prev += *len as u32
            }
            // else add an encoded call to absorb
            Call::Absorb(len) => input_u32.push(ABSORB_MASK + *len as u32),
            // if both this and the previous calls are to squeeze, aggregate
            // them
            Call::Squeeze(len) if *prev & ABSORB_MASK == 0 => {
                *prev += *len as u32
            }
            // else add an encoded call to squeeze
            Call::Squeeze(len) => input_u32.push(*len as u32),
        }
    });

    // Convert hash input to an array of u8, using big endian conversion
    let mut input: Vec<u8> = input_u32
        .iter()
        .flat_map(|u32_int| u32_int.to_be_bytes().into_iter())
        .collect();

    // Add the domain separator to the hash input
    input.extend(domain_sep.to_be_bytes());

    Ok(input)
}

/// Check that the io-pattern is sensible:
/// - It doesn't start with a call to squeeze.
/// - It doesn't end with a call to absorb.
/// - Every call to absorb or squeeze has a positive length.
fn validate_io_pattern(iopattern: impl AsRef<[Call]>) -> Result<(), Error> {
    // make sure the io-pattern starts with a call to absorb and ends with a
    // call to squeeze
    match (iopattern.as_ref().first(), iopattern.as_ref().last()) {
        (Some(Call::Absorb(_)), Some(Call::Squeeze(_))) => {}
        _ => return Err(Error::InvalidIOPattern),
    }

    // check that every call to absorb or squeeze has a positive length
    if iopattern.as_ref().iter().any(|call| *call.call_len() == 0) {
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
        let pattern1 = vec![Call::Absorb(2), Call::Squeeze(1)];
        let pattern2 = vec![Call::Absorb(2), Call::Squeeze(1)];
        assert_eq!(
            tag_input(&pattern1, domain_sep)?,
            tag_input(&pattern2, domain_sep)?
        );

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
