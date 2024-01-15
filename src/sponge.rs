// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use core::ops::AddAssign;

#[cfg(features = "zk")]
use dusk_plonk::prelude::Composer;

use crate::{DomainSeparator, Error, IOCall};

/// Trait to define the behavior of the sponge permutation
pub trait Permutation<T, const N: usize>
where
    T: Default + Copy,
{
    /// Create a new state for the permutation
    #[cfg(not(featues = "zk"))]
    fn new(state: [T; N]) -> Self;

    /// Create a new state for the permutation
    #[cfg(featues = "zk")]
    fn new(composer: &mut Composer, state: [T; N]) -> Self;

    /// Return the inner state of the permutation
    fn state_mut(&mut self) -> &mut [T; N];

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
    permutation: P,
    pos_absorb: usize,
    pos_sqeeze: usize,
    pos_io: usize,
    iopattern: Vec<IOCall>,
    domain_sep: DomainSeparator,
    tag: T,
    output: Vec<T>,
}

impl<P, T, const N: usize> Sponge<P, T, N>
where
    P: Permutation<T, N>,
    T: AddAssign + Default + Copy,
{
    /// This initializes the inner state of the sponge permutation, modifying up
    /// to c/2 field elements of the state.
    /// It’s done once in the lifetime of a sponge.
    #[cfg(not(featues = "zk"))]
    pub fn start(iopattern: Vec<IOCall>, domain_sep: DomainSeparator) -> Self {
        let mut iopattern = iopattern;
        crate::aggregate_io_pattern(&mut iopattern);
        let tag = P::tag(&crate::tag_input(&iopattern, &domain_sep));
        let state = P::initialize_state(tag);

        Self {
            permutation: P::new(state),
            pos_absorb: 0,
            pos_sqeeze: 0,
            pos_io: 0,
            iopattern,
            domain_sep,
            tag,
            output: Vec::new(),
        }
    }

    /// This initializes the inner state of the sponge permutation, modifying up
    /// to c/2 field elements of the state.
    /// It’s done once in the lifetime of a sponge.
    #[cfg(featues = "zk")]
    pub fn start(
        composer: &mut Composer,
        iopattern: Vec<IOCall>,
        domain_sep: DomainSeparator,
    ) -> Self {
        let mut iopattern = iopattern;
        crate::aggregate_io_pattern(&mut iopattern);
        let tag = P::tag(&crate::tag_input(&iopattern, &domain_sep));
        let state = P::initialize_state(tag);

        Self {
            permutation: P::new(composer, state),
            pos_absorb: 0,
            pos_sqeeze: 0,
            pos_io: 0,
            iopattern,
            domain_sep,
            tag,
            output: Vec::new(),
        }
    }

    /// This marks the end of the sponge life, preventing any further operation.
    /// In particular, the state is erased from memory. The result is ‘OK’, or
    /// an error
    // NOTE: in the specs a length is given as a parameter but I don't
    // understand what for
    pub fn finish(mut self) -> Result<Vec<T>, Error> {
        if self.pos_io != self.iopattern.len() {
            return Err(Error::IOPatternViolation);
        } else {
            self.permutation
                .state_mut()
                .iter_mut()
                .for_each(|s| *s = T::default());
            self.pos_absorb = 0;
            self.pos_sqeeze = 0;
            return Ok(self.output);
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
            IOCall::Absorb(expected_len) => {
                // TODO: check what to do when the given absorb len is 0
                if len == 0 {
                    self.pos_io += 1;
                    return Ok(());
                }
                // Return error if we try to absorb more elements than expected
                // by the io-pattern, or if the given input doesn't yield enough
                // elements.
                else if (expected_len as usize) < len || input.len() < len {
                    return Err(Error::InvalidAbsorbLen(len));
                }
                // Modify the internal io-pattern if we absorb less elements
                // than expected by the io-pattern.
                else if (expected_len as usize) > len {
                    let remaining_len = expected_len - len as u32;
                    self.iopattern[self.pos_io] = IOCall::Absorb(len as u32);
                    self.iopattern
                        .insert(self.pos_io + 1, IOCall::Absorb(remaining_len));
                }
            }
        }

        // Absorb `len` elements into the state, calling [`permute`] when the
        // absorb-position reached the rate.
        for element in input.iter().take(len) {
            if self.pos_absorb == Self::rate() {
                self.permutation.permute();

                self.pos_absorb = 0;
            }
            // NOTE: In the paper it says that the field element at `pos_absorb`
            // is used, but as I understand sponges, we need to add
            // the capacity to that position (provided we start
            // counting at 0).
            self.permutation.state_mut()[self.pos_absorb + Self::capacity()] +=
                *element;
            self.pos_absorb += 1;
        }

        // Set squeeze position to rate to force a permutation at the next
        // call to squeeze
        self.pos_sqeeze = Self::rate();

        // Increase the position for the io pattern
        self.pos_io += 1;

        Ok(())
    }

    /// This extracts `len` field elements from the state, interleaving calls to
    /// the permutation.
    /// It also checks if the current call matches the IO pattern.
    pub fn squeeze(&mut self, len: usize) -> Result<(), Error> {
        // Check that the io-pattern is not violated
        if self.pos_io >= self.iopattern.len() {
            return Err(Error::IOPatternViolation);
        }
        match self.iopattern[self.pos_io] {
            IOCall::Absorb(_) => {
                return Err(Error::IOPatternViolation);
            }
            IOCall::Squeeze(expected_len) => {
                // TODO: check what to do when the given squeeze len is 0
                if len == 0 {
                    self.pos_io += 1;
                    return Ok(());
                }
                // Return error if we try to squeeze more elements than expected
                // by the io-pattern.
                else if (expected_len as usize) < len {
                    return Err(Error::InvalidSqueezeLen(len));
                }
            }
        };

        // Squeeze 'len` field elements from the state, calling [`permute`] when
        // the squeeze-position reached the rate.
        for _ in 0..len {
            if self.pos_sqeeze == Self::rate() {
                self.permutation.permute();

                self.pos_sqeeze = 0;
                self.pos_absorb = 0;
            }
            // NOTE: In the paper it says that the field element at
            // `pos_squeeze` is returned, but as I understand
            // sponges, we need to add the capacity to that position
            // (provided we start counting at 0).
            self.output.push(
                self.permutation.state_mut()
                    [self.pos_sqeeze + Self::capacity()],
            );
        }

        // Increase the position for the io pattern
        self.pos_io += 1;

        Ok(())
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
