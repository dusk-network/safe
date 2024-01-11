// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
// use core::ops::AddAssign;

use dusk_bls12_381::BlsScalar;

use crate::Error;

/// Trait to define the behavior of the state permutation
pub trait Permutation<T, const N: usize>
where
    T: Default + Copy,
{
    /// Create a new state for the permutation
    fn new(state: [T; N]) -> Self;

    /// Return the inner state of the permutation
    fn inner_mut(&mut self) -> &mut [T; N];

    /// Permute the state of the permutation
    fn permute(&mut self);

    /// Create the tag by hashing the tag input
    fn tag(input: &[u8]) -> T;

    /// Initialize the state of the permutation
    fn initialize_state(tag_input: &[u8]) -> [T; N] {
        let mut state = [T::default(); N];
        state[0] = Self::tag(tag_input);
        state
    }
}

/// Sponge over [`BlsScalar`], generic over `N`, the width of the inner
/// permutation container. The capacity is fixed to the size of one
/// [`BlsScalar`] and the rate is fixed to the size of `N - 1` [`BlsScalar`].
#[derive(Debug, Clone, PartialEq)]
pub struct Sponge<P, const N: usize>
where
    P: Permutation<BlsScalar, N>,
    // T: AddAssign,
{
    state: P,
    pos_absorb: usize,
    pos_sqeeze: usize,
    pos_io: usize,
    iopattern: Vec<IOCall>,
    domain_sep: DomainSeparator,
}

impl<P, const N: usize> Sponge<P, N>
where
    P: Permutation<BlsScalar, N>,
    // T: AddAssign,
{
    /// This initializes the inner state of the sponge, modifying up to c/2
    /// [`BlsScalar`] of the state.
    /// It’s done once in the lifetime of a sponge.
    pub fn start(iopattern: Vec<IOCall>, domain_sep: DomainSeparator) -> Self {
        let mut iopattern = iopattern;
        aggregate_io_pattern(&mut iopattern);
        let tag_input = tag_input(&iopattern, &domain_sep);
        let state = P::initialize_state(&tag_input);

        Self {
            state: P::new(state),
            pos_absorb: 0,
            pos_sqeeze: 0,
            pos_io: 0,
            iopattern,
            domain_sep,
        }
    }

    /// This injects `len` [`BlsScalar`] to the state from the scalar array,
    /// interleaving calls to the permutation.
    /// It also checks if the current call matches the IO pattern.
    pub fn absorb(
        &mut self,
        len: usize,
        input: &[BlsScalar],
    ) -> Result<(), Error> {
        // Check that the io-pattern is not violated
        if self.pos_io >= self.iopattern.len() {
            return Err(Error::IOPatternViolation);
        }
        match self.iopattern[self.pos_io] {
            IOCall::Squeeze(_) => {
                return Err(Error::IOPatternViolation);
            }
            IOCall::Absorb(absorb_len) => {
                if absorb_len as usize != len {
                    return Err(Error::InvalidAbsorbLen(absorb_len, len));
                } else if absorb_len == 0 {
                    return Ok(());
                }
            }
        }

        // Absorb `len` elements into the state, calling `permute` when the
        // absorb-position reached the rate.
        for scalar in input {
            self.absorb_scalar(scalar);
        }
        Ok(())
    }

    fn absorb_scalar(&mut self, scalar: &BlsScalar) {
        if self.pos_absorb == Self::rate() {
            // TODO: permute the state with a trait object

            self.pos_absorb = 0;
        }
        // NOTE: In the paper it says that the scalar at `pos_absorb` is used,
        // but as I understand sponges, we need to add the capacity to the
        // position.
        self.state.inner_mut()[self.pos_absorb + Self::capacity()] += scalar;
        self.pos_absorb += 1;
    }

    /// This extracts `len` [`BlsScalar`] from the state, interleaving calls to
    /// the permutation.
    /// It also checks if the current call matches the IO pattern.
    pub fn squeeze(&mut self, len: usize) -> Result<Vec<BlsScalar>, Error> {
        // Check that the io-pattern is not violated
        if self.pos_io >= self.iopattern.len() {
            return Err(Error::IOPatternViolation);
        }
        match self.iopattern[self.pos_io] {
            IOCall::Absorb(_) => {
                return Err(Error::IOPatternViolation);
            }
            IOCall::Squeeze(squeeze_len) => {
                if squeeze_len as usize != len {
                    return Err(Error::InvalidSqueezeLen(squeeze_len, len));
                } else if squeeze_len == 0 {
                    return Ok(Vec::new());
                }
            }
        };

        // Squeeze 'len` scalar from the state, calling `permute` when the
        // squeeze-position reached the rate.
        let output = (0..len).map(|_| self.squeeze_scalar()).collect();
        Ok(output)
    }

    fn squeeze_scalar(&mut self) -> BlsScalar {
        if self.pos_sqeeze == Self::rate() {
            // TODO: permuts the state with a trait oject

            self.pos_sqeeze = 0;
            self.pos_absorb = 0;
        }
        // NOTE: In the paper it says that the scalar at `pos_squeeze` is
        // returned, but as I understand sponges, we need to add the
        // capacity to the position.
        self.state.inner_mut()[self.pos_sqeeze + Self::capacity()]
    }

    /// The capacity of the sponge instance.
    pub const fn capacity() -> usize {
        1
    }

    /// The rate of the sponge instance.
    pub const fn rate() -> usize {
        N - Self::capacity()
    }
}

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
