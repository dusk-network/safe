// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use core::ops::AddAssign;

// use dusk_bls12_381::BlsScalar;

use crate::{DomainSeparator, Error, IOCall};

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
    fn initialize_state(tag: T) -> [T; N] {
        let mut state = [T::default(); N];
        state[0] = tag;
        state
    }
}

/// Sponge generic over: `T` the type of the field elements and `N` the width of
/// the inner permutation container. The capacity is fixed to the size of one
/// field element and the rate is fixed to the size of `N - 1` field elements.
#[derive(Debug, Clone, PartialEq)]
pub struct Sponge<P, T, const N: usize>
where
    P: Permutation<T, N>,
    T: Default + Copy,
    // T: AddAssign + Default + Copy,
{
    state: P,
    pos_absorb: usize,
    pos_sqeeze: usize,
    pos_io: usize,
    iopattern: Vec<IOCall>,
    domain_sep: DomainSeparator,
    tag: T,
}

impl<P, T, const N: usize> Sponge<P, T, N>
where
    P: Permutation<T, N>,
    T: AddAssign + Default + Copy,
{
    /// This initializes the inner state of the sponge, modifying up to c/2
    /// field elements of the state.
    /// It’s done once in the lifetime of a sponge.
    pub fn start(iopattern: Vec<IOCall>, domain_sep: DomainSeparator) -> Self {
        let mut iopattern = iopattern;
        crate::aggregate_io_pattern(&mut iopattern);
        let tag = P::tag(&crate::tag_input(&iopattern, &domain_sep));
        let state = P::initialize_state(tag);

        Self {
            state: P::new(state),
            pos_absorb: 0,
            pos_sqeeze: 0,
            pos_io: 0,
            iopattern,
            domain_sep,
            tag,
        }
    }

    /// This injects `len` field elements to the state from the field elements
    /// array, interleaving calls to the permutation.
    /// It also checks if the current call matches the IO pattern.
    pub fn absorb(&mut self, len: usize, input: &[T]) -> Result<(), Error> {
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
        for element in input {
            self.absorb_element(element);
        }

        // Set squeeze position to rate to trigger a permutation at the next
        // call to squeeze
        self.pos_sqeeze = Self::rate();

        // Increase the position for the io pattern
        self.pos_io += 1;

        Ok(())
    }

    fn absorb_element(&mut self, element: &T) {
        if self.pos_absorb == Self::rate() {
            // TODO: permute the state with a trait object
            self.state.permute();

            self.pos_absorb = 0;
        }
        // NOTE: In the paper it says that the field element at `pos_absorb` is
        // used, but as I understand sponges, we need to add the
        // capacity to that position (provided we start counting at 0).
        self.state.inner_mut()[self.pos_absorb + Self::capacity()] += *element;
        self.pos_absorb += 1;
    }

    /// This extracts `len` field elements from the state, interleaving calls to
    /// the permutation.
    /// It also checks if the current call matches the IO pattern.
    pub fn squeeze(&mut self, len: usize) -> Result<Vec<T>, Error> {
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

        // Squeeze 'len` field elements from the state, calling `permute` when
        // the squeeze-position reached the rate.
        let output = (0..len).map(|_| self.squeeze_element()).collect();

        // Increase the position for the io pattern
        self.pos_io += 1;

        Ok(output)
    }

    fn squeeze_element(&mut self) -> T {
        if self.pos_sqeeze == Self::rate() {
            // TODO: permuts the state with a trait oject
            self.state.permute();

            self.pos_sqeeze = 0;
            self.pos_absorb = 0;
        }
        // NOTE: In the paper it says that the field element at `pos_squeeze` is
        // returned, but as I understand sponges, we need to add the
        // capacity to that position (provided we start counting at 0).
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
