// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;

use crate::Error;

/// Sponge over [`BlsScalar`], generic over `N`, the width of the inner
/// permutation container. The capacity is fixed to the size of one
/// [`BlsScalar`] and the rate is fixed to the size of `N - 1` [`BlsScalar`].
#[derive(Debug, Clone, PartialEq)]
pub struct Sponge<const N: usize> {
    state: [BlsScalar; N],
    pos_absorb: usize,
    pos_sqeeze: usize,
    pos_io: usize,
    iopattern: Vec<IOCall>,
    domain_sep: DomainSeparator,
}

impl<const N: usize> Sponge<N> {
    /// This initializes the inner state of the sponge, modifying up to c/2
    /// [`BlsScalar`] of the state.
    /// It’s done once in the lifetime of a sponge.
    pub fn start(iopattern: Vec<IOCall>, domain_sep: DomainSeparator) -> Self {
        let mut instance = Self {
            state: [BlsScalar::zero(); N],
            pos_absorb: 0,
            pos_sqeeze: 0,
            pos_io: 0,
            iopattern,
            domain_sep,
        };

        // Aggregate the io-pattern
        instance.aggregate_io_pattern();
        // Initialize the state with a tag calculated from the io-pattern and
        // domain-separator.
        instance.initialize_state();
        instance
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
        self.state[self.pos_absorb + Self::capacity()] += scalar;
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
        self.state[self.pos_sqeeze + Self::capacity()]
    }

    /// The capacity of the sponge instance.
    pub const fn capacity() -> usize {
        1
    }

    /// The rate of the sponge instance.
    pub const fn rate() -> usize {
        N - Self::capacity()
    }

    /// Aggregate contiguous calls to absorb or squeeze into a single call,
    /// e.g.:
    /// `[Absorb(3), Absorb(3), Squeeze(1)] -> [Absorb(6), Squeeze(1)]`
    fn aggregate_io_pattern(&mut self) {
        // NOTE: Should the io pattern be checked more thoroughly here, e.g.:
        //   - start with absorb
        //   - end with squeeze
        let mut i = 0;
        loop {
            // Since we remove items from the vector within this loop, we need
            // to check for an overflow at each iteration.
            if self.iopattern.len() == 0
                || self.iopattern.len() == 1
                || i >= self.iopattern.len() - 1
            {
                return;
            }
            // Compare iopattern[i] and iopattern[i + 1].
            match (self.iopattern[i], self.iopattern[i + 1]) {
                // Aggregate two subsequent calls to absorb.
                (IOCall::Absorb(len1), IOCall::Absorb(len2)) => {
                    self.iopattern[i] = IOCall::Absorb(len1 + len2);
                    self.iopattern.remove(i + 1);
                }
                // Aggregate two subsequent calls to squeeze.
                (IOCall::Squeeze(len1), IOCall::Squeeze(len2)) => {
                    self.iopattern[i] = IOCall::Squeeze(len1 + len2);
                    self.iopattern.remove(i + 1);
                }
                // When the i-th call is different from the (i + 1)-th call, we
                // look at the next index.
                _ => i += 1,
            }
        }
    }

    fn initialize_state(&mut self) {
        // FIXME: insert tag method from permutation trait
        // let tag = self.tag();
        self.state.iter_mut().enumerate().for_each(|(i, s)| {
            if i == 0 {
                // *s = tag;
            } else {
                *s = BlsScalar::zero()
            }
        });
    }

    /// Encode the input for the tag for the sponge instance, using the
    /// domain-separator and IO-pattern.
    ///
    /// Note: The IO-pattern is expected to be aggregated.
    pub fn tag_input(&self) -> Vec<u8> {
        let mut input_u32 = Vec::new();

        // Encode calls to absorb and squeeze
        for io_call in self.iopattern.iter() {
            match io_call {
                IOCall::Absorb(len) => input_u32.push(0x8000_0000 + *len),
                IOCall::Squeeze(len) => input_u32.push(*len),
            }
        }
        // Add the domain separator to the hash input
        input_u32.push((&self.domain_sep).into());

        // Convert hash input to an array of u8, using big endian conversion
        input_u32
            .iter()
            .map(|u32_int| u32_int.to_be_bytes().into_iter())
            .flatten()
            .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn verify_initialization(
        iopattern: Vec<IOCall>,
        aggregated: Vec<IOCall>,
        tag: u32,
    ) {
        // Create an initialized sponge instance
        let instance: Sponge<5> =
            Sponge::start(iopattern, DomainSeparator::from(tag));

        // Check aggregation is as expected
        assert_eq!(instance.iopattern, aggregated);

        // Check tag input encoding is correct
        let tag_input = instance.tag_input();
        let mut input_chunks = tag_input.chunks(4);
        // Check length
        assert_eq!(input_chunks.len(), aggregated.len() + 1);
        // Check io pattern encoding
        aggregated.iter().for_each(|io| {
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
        assert_eq!(domain_encoded, [0x00, 0x00, 0x00, tag as u8]);
    }

    #[test]
    fn initialization() {
        let mut iopattern = Vec::new();
        let mut aggregated = Vec::new();
        let tag = 0;
        verify_initialization(iopattern.clone(), aggregated.clone(), tag);

        iopattern.push(IOCall::Absorb(2));
        aggregated.push(IOCall::Absorb(2));
        verify_initialization(iopattern.clone(), aggregated.clone(), tag);

        iopattern.push(IOCall::Absorb(3));
        aggregated[0] = IOCall::Absorb(5);
        verify_initialization(iopattern.clone(), aggregated.clone(), tag);

        iopattern.push(IOCall::Absorb(2));
        iopattern.push(IOCall::Absorb(2));
        iopattern.push(IOCall::Absorb(2));
        iopattern.push(IOCall::Squeeze(1));
        aggregated[0] = IOCall::Absorb(11);
        aggregated.push(IOCall::Squeeze(1));
        verify_initialization(iopattern.clone(), aggregated.clone(), tag);

        iopattern.push(IOCall::Squeeze(1));
        aggregated[1] = IOCall::Squeeze(1 + 1);
        verify_initialization(iopattern.clone(), aggregated.clone(), tag);

        iopattern.push(IOCall::Absorb(2));
        iopattern.push(IOCall::Squeeze(1));
        aggregated.push(IOCall::Absorb(2));
        aggregated.push(IOCall::Squeeze(1));
        let tag = 1;
        verify_initialization(iopattern.clone(), aggregated.clone(), tag);
    }
}
