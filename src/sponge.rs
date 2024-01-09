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
    iopattern: IOPattern,
    domain_sep: DomainSeparator,
}

impl<const N: usize> Sponge<N> {
    /// This initializes the inner state of the sponge, modifying up to c/2
    /// [`BlsScalar`] of the state.
    /// It’s done once in the lifetime of a sponge.
    pub fn start(
        mut iopattern: IOPattern,
        domain_sep: DomainSeparator,
    ) -> Self {
        iopattern.aggregate();

        let mut instance = Self {
            state: [BlsScalar::zero(); N],
            pos_absorb: 0,
            pos_sqeeze: 0,
            pos_io: 0,
            iopattern,
            domain_sep,
        };

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
        if self.pos_io >= self.iopattern.0.len() {
            return Err(Error::IOPatternViolation);
        }
        match self.iopattern.0[self.pos_io] {
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
            self.absorb_scalar_unchecked(scalar);
        }
        Ok(())
    }

    fn absorb_scalar_unchecked(&mut self, scalar: &BlsScalar) {
        if self.pos_absorb == Self::rate() {
            // TODO: permute the state with a trait object

            self.pos_absorb = 0;
        }
        self.state[self.pos_absorb + Self::capacity()] += scalar;
        self.pos_absorb += 1;
    }

    /// This extracts `len` [`BlsScalar`] from the state, interleaving calls to
    /// the permutation.
    /// It also checks if the current call matches the IO pattern.
    pub fn squeeze(&mut self, len: usize) -> Result<Vec<BlsScalar>, Error> {
        // Check that the io-pattern is not violated
        if self.pos_io >= self.iopattern.0.len() {
            return Err(Error::IOPatternViolation);
        }
        match self.iopattern.0[self.pos_io] {
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
        let output =
            (0..len).map(|_| self.squeeze_scalar_unchecked()).collect();
        Ok(output)
    }

    fn squeeze_scalar_unchecked(&mut self) -> BlsScalar {
        if self.pos_sqeeze == Self::rate() {
            // TODO: permuts the state with a trait oject

            self.pos_sqeeze = 0;
            self.pos_absorb = 0;
        }
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

    fn initialize_state(&mut self) {
        self.state[0] = self.tag();
    }

    fn tag(&self) -> BlsScalar {
        let mut encoded_input = Vec::new();
        for io_call in self.iopattern.0.iter() {
            match io_call {
                IOCall::Absorb(len) => {
                    encoded_input.push(0x8000_0000 + len.to_be())
                }
                IOCall::Squeeze(len) => encoded_input.push(len.to_be()),
            }
        }
        encoded_input.push((&self.domain_sep).into());

        // Hash the string obtained with the hasher H to a 256-bit tag T
        // (truncating the hash if needed).
        unimplemented!()
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

/// A compact encoding of the pattern of [`Sponge::absorb`] and
/// [`Sponge::squeeze`] calls during the sponge lifetime. An implementation must
/// forbid to finish the sponge usage if this pattern is violated.
/// In particular, the output from SQUEEZE calls must not be used if the IO
/// pattern is not followed.
#[derive(Debug, Clone, PartialEq)]
pub struct IOPattern(pub(crate) Vec<IOCall>);

/// Enum to encode the calls to [`absorb`] and [`squeeze`] and the amount of
/// elements to be absorbed or squeezed in each call.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IOCall {
    /// Absorb `len: u32` elements into the state.
    Absorb(u32),
    /// Squeeze `len: u32` elements from the state.
    Squeeze(u32),
}

impl IOPattern {
    /// Aggregate contiguous calls to absorb or squeeze into a single call,
    /// e.g.:
    /// `[Absorb(3), Absorb(3), Squeeze(1)] -> [Absorb(6), Squeeze(1)]`
    pub(crate) fn aggregate(&mut self) {
        unimplemented!();
    }
}
