// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![no_std]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

extern crate alloc;
use alloc::vec::Vec;

mod error;
mod sponge;

pub use error::Error;
pub use sponge::{Permutation, Sponge};

/// A DomainSeparator together with the [`IOPattern`] is used to create a tag to
/// initialize a [`Sponge`] [`State`].
/// This way a [`DomainSeparator`] can be used to create different [`Sponge`]
/// instances for a same IO pattern.
#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct DomainSeparator(u64);

impl From<u64> for DomainSeparator {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<&DomainSeparator> for u64 {
    fn from(value: &DomainSeparator) -> Self {
        value.0
    }
}

/// Enum to encode the [`Sponge::absorb`] and [`Sponge::squeeze`] calls and the
/// amount of elements absorbed/squeezed during the sponge lifetime. An
/// implementation must forbid to finish the sponge usage if this pattern is
/// violated.
///
/// In particular, the output from SQUEEZE calls must not be used if the IO
/// pattern is not followed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IOCall {
    /// Absorb `len: u32` elements into the state.
    Absorb(u32),
    /// Squeeze `len: u32` elements from the state.
    Squeeze(u32),
}

/// Encode the input for the tag for the sponge instance, using the
/// domain-separator and IO-pattern.
///
/// This function returns an error if the io-pattern is not sensible.
fn tag_input(
    iopattern: &[IOCall],
    domain_sep: &DomainSeparator,
) -> Result<Vec<u8>, Error> {
    // make sure the io-pattern is valid: start with absorb, end with squeeze
    // and none of the calls have a len == 0
    validate_io_pattern(iopattern)?;

    let mut input_u32 = Vec::new();
    input_u32.push(0x8000_0000);

    // Encode calls to absorb and squeeze
    let mut i = 0;
    for io_call in iopattern.iter() {
        match io_call {
            IOCall::Absorb(len) => {
                match input_u32[i] & 0x8000_0000 == 0x8000_0000 {
                    true => input_u32[i] += len,
                    false => {
                        input_u32.push(0x8000_0000 + len);
                        i += 1;
                    }
                }
            }
            IOCall::Squeeze(len) => match input_u32[i] & 0x8000_0000 == 0 {
                true => input_u32[i] += len,
                false => {
                    input_u32.push(*len);
                    i += 1;
                }
            },
        }
    }
    // Convert hash input to an array of u8, using big endian conversion
    let mut input: Vec<u8> = input_u32
        .iter()
        .flat_map(|u32_int| u32_int.to_be_bytes().into_iter())
        .collect();

    // Add the domain separator to the hash input
    input.extend(domain_sep.0.to_be_bytes());

    Ok(input)
}

/// Check that the io-pattern is sensible:
/// - It doesn't start with a call to squeeze.
/// - It doesn't end with a call to absorb.
/// - Every call to absorb or squeeze has a positive length.
fn validate_io_pattern(iopattern: &[IOCall]) -> Result<(), Error> {
    // make sure we have at least two items in our io-pattern, after this check
    // we can safely unwrap in the next two checks
    if iopattern.len() < 2 {
        return Err(Error::InvalidIOPattern);
    }
    // check that the io-pattern doesn't start with a call to squeeze
    if let IOCall::Squeeze(_) = iopattern.first().unwrap() {
        return Err(Error::InvalidIOPattern);
    }
    // check that the io-pattern doesn't end with a call to absorb
    if let IOCall::Absorb(_) = iopattern.last().unwrap() {
        return Err(Error::InvalidIOPattern);
    }

    // check that every call to absorb or squeeze has a positive length
    for op in iopattern {
        let len = match op {
            IOCall::Absorb(len) => len,
            IOCall::Squeeze(len) => len,
        };
        if *len == 0 {
            return Err(Error::InvalidIOPattern);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregation_and_tag_input() {
        let mut iopattern = Vec::new();
        let mut aggregated = Vec::new();
        let domain_sep = DomainSeparator::from(42);
        validate_io_pattern(&mut iopattern)
            .expect_err("IO-pattern should not validate");

        iopattern.push(IOCall::Absorb(2));
        aggregated.push(IOCall::Absorb(2));
        // check io-pattern
        validate_io_pattern(&iopattern)
            .expect_err("IO-pattern should not validate");

        iopattern.push(IOCall::Squeeze(1));
        aggregated.push(IOCall::Squeeze(1));
        // check io-pattern
        validate_io_pattern(&iopattern).expect("IO-Pattern should validate");
        let result = tag_input(&iopattern, &domain_sep)
            .expect("IO-Pattern should validate");
        let result_aggregated = tag_input(&aggregated, &domain_sep)
            .expect("IO-Pattern should validate");
        assert_eq!(result, result_aggregated);

        iopattern.push(IOCall::Squeeze(0));
        // check io-pattern
        validate_io_pattern(&iopattern)
            .expect_err("IO-pattern should not validate");
        iopattern.pop();

        iopattern.push(IOCall::Absorb(0));
        iopattern.push(IOCall::Squeeze(1));
        // check io-pattern
        validate_io_pattern(&iopattern)
            .expect_err("IO-pattern should not validate");
        iopattern.pop();
        iopattern.pop();

        iopattern.push(IOCall::Absorb(2));
        iopattern.push(IOCall::Absorb(2));
        iopattern.push(IOCall::Absorb(2));
        iopattern.push(IOCall::Squeeze(1));
        iopattern.push(IOCall::Squeeze(1));
        aggregated.push(IOCall::Absorb(6));
        aggregated.push(IOCall::Squeeze(2));
        // check io-pattern
        validate_io_pattern(&iopattern).expect("IO-Pattern should validate");
        let result = tag_input(&iopattern, &domain_sep)
            .expect("IO-Pattern should validate");
        let result_aggregated = tag_input(&aggregated, &domain_sep)
            .expect("IO-Pattern should validate");
        assert_eq!(result, result_aggregated);
    }
}
