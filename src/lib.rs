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
pub struct DomainSeparator(u32);

impl From<u32> for DomainSeparator {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl Into<u32> for &DomainSeparator {
    fn into(self) -> u32 {
        self.0
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

/// Aggregate contiguous calls to absorb or squeeze into a single call,
/// e.g.:
/// `[Absorb(3), Absorb(3), Squeeze(1)] -> [Absorb(6), Squeeze(1)]`
fn aggregate_io_pattern(iopattern: &mut Vec<IOCall>) {
    // NOTE: Should the io pattern be checked more thoroughly here, e.g.:
    //   - start with absorb
    //   - end with squeeze
    let mut i = 0;
    loop {
        // Since we remove items from the vector within this loop, we need
        // to check for an overflow at each iteration.
        if iopattern.len() == 0
            || iopattern.len() == 1
            || i >= iopattern.len() - 1
        {
            return;
        }
        // Compare iopattern[i] and iopattern[i + 1].
        match (iopattern[i], iopattern[i + 1]) {
            // Aggregate two subsequent calls to absorb.
            (IOCall::Absorb(len1), IOCall::Absorb(len2)) => {
                iopattern[i] = IOCall::Absorb(len1 + len2);
                iopattern.remove(i + 1);
            }
            // Aggregate two subsequent calls to squeeze.
            (IOCall::Squeeze(len1), IOCall::Squeeze(len2)) => {
                iopattern[i] = IOCall::Squeeze(len1 + len2);
                iopattern.remove(i + 1);
            }
            // When the i-th call is different from the (i + 1)-th call, we
            // look at the next index.
            _ => i += 1,
        }
    }
}

/// Encode the input for the tag for the sponge instance, using the
/// domain-separator and IO-pattern.
///
/// Note: The IO-pattern is expected to be aggregated *before* creating the tag
/// input.
pub fn tag_input(
    iopattern: &Vec<IOCall>,
    domain_sep: &DomainSeparator,
) -> Vec<u8> {
    let mut input_u32 = Vec::new();

    // Encode calls to absorb and squeeze
    for io_call in iopattern.iter() {
        match io_call {
            IOCall::Absorb(len) => input_u32.push(0x8000_0000 + *len),
            IOCall::Squeeze(len) => input_u32.push(*len),
        }
    }
    // Add the domain separator to the hash input
    input_u32.push(domain_sep.into());

    // Convert hash input to an array of u8, using big endian conversion
    input_u32
        .iter()
        .map(|u32_int| u32_int.to_be_bytes().into_iter())
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify_tag_input(iopattern: &Vec<IOCall>, tag: u32) {
        // Check tag input encoding is correct
        let tag_input = tag_input(iopattern, &DomainSeparator::from(tag));

        let input_chunks = &mut tag_input.chunks(4);
        // Check length
        assert_eq!(input_chunks.len(), iopattern.len() + 1);

        // Check io pattern encoding
        iopattern.iter().for_each(|io| {
            let io_encoded = input_chunks.next().unwrap();
            match io {
                IOCall::Absorb(len) => {
                    assert_eq!(io_encoded, [0x80, 0x00, 0x00, *len as u8]);
                }
                IOCall::Squeeze(len) => {
                    assert_eq!(io_encoded, [0x00, 0x00, 0x00, *len as u8]);
                }
            }
        });

        // Check domain separator encoding
        let domain_encoded = input_chunks.next().unwrap();
        assert_eq!(domain_encoded, tag.to_be_bytes());
    }

    #[test]
    fn aggregation_and_tag_input() {
        let mut iopattern = Vec::new();
        let mut aggregated = Vec::new();
        // Check aggregation
        aggregate_io_pattern(&mut iopattern);
        assert_eq!(iopattern, aggregated);
        // Check tag input
        verify_tag_input(&iopattern, 0);

        iopattern.push(IOCall::Absorb(2));
        aggregated.push(IOCall::Absorb(2));
        // Check aggregation
        aggregate_io_pattern(&mut iopattern);
        assert_eq!(iopattern, aggregated);
        // Check tag input
        verify_tag_input(&iopattern, 42);

        iopattern.push(IOCall::Absorb(3));
        aggregated[0] = IOCall::Absorb(5);
        // Check aggregation
        aggregate_io_pattern(&mut iopattern);
        assert_eq!(iopattern, aggregated);
        // Check tag input
        verify_tag_input(&iopattern, 1);

        iopattern.push(IOCall::Absorb(2));
        iopattern.push(IOCall::Absorb(2));
        iopattern.push(IOCall::Absorb(2));
        iopattern.push(IOCall::Squeeze(1));
        aggregated[0] = IOCall::Absorb(11);
        aggregated.push(IOCall::Squeeze(1));
        // Check aggregation
        aggregate_io_pattern(&mut iopattern);
        assert_eq!(iopattern, aggregated);
        // Check tag input
        verify_tag_input(&iopattern, 50);

        iopattern.push(IOCall::Squeeze(1));
        aggregated[1] = IOCall::Squeeze(1 + 1);
        // Check aggregation
        aggregate_io_pattern(&mut iopattern);
        assert_eq!(iopattern, aggregated);
        // Check tag input
        verify_tag_input(&iopattern, 42);

        iopattern.push(IOCall::Absorb(2));
        iopattern.push(IOCall::Squeeze(1));
        aggregated.push(IOCall::Absorb(2));
        aggregated.push(IOCall::Squeeze(1));
        // Check aggregation
        aggregate_io_pattern(&mut iopattern);
        assert_eq!(iopattern, aggregated);
        // Check tag input
        verify_tag_input(&iopattern, 243452880);
    }
}
