// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use crate::{tag_input, DomainSeparator, Error, IOCall};

/// Trait to define the behavior of the sponge permutation.
pub trait Permutation<T, const N: usize>
where
    T: Copy,
{
    /// Return the inner state of the permutation.
    fn state_mut(&mut self) -> &mut [T; N];

    /// Apply one permutation to the state.
    fn permute(&mut self);

    /// Create the tag by hashing the tag input.
    fn tag(&mut self, input: &[u8]) -> T;

    /// Return the zero value of type `T`.
    fn zero_value() -> T;

    /// Add two values of type `T` and return the result.
    /// This is a trade-off for being able to apply the `Permutation` trait to
    /// a state gadget, where `T` is of type `Witness`.
    fn add(&mut self, right: T, left: T) -> T;

    /// Initialize the state of the permutation.
    fn initialize_state(&mut self, tag: T) {
        self.state_mut().iter_mut().enumerate().for_each(|(i, s)| {
            *s = match i {
                0 => tag,
                _ => Self::zero_value(),
            }
        });
    }
}

/// Sponge generic over: `T` the type of the field elements and `N` the width of
/// the inner permutation container. The capacity is fixed to the size of one
/// field element and the rate is fixed to the size of `N - 1` field elements.
#[derive(Debug, Clone, PartialEq)]
pub struct Sponge<P, T, const N: usize>
where
    P: Permutation<T, N>,
    T: Copy,
{
    permutation: P,
    pos_absorb: usize,
    pos_sqeeze: usize,
    io_count: usize,
    iopattern: Vec<IOCall>,
    domain_sep: DomainSeparator,
    tag: T,
    output: Vec<T>,
}

impl<P, T, const N: usize> Sponge<P, T, N>
where
    P: Permutation<T, N>,
    T: Copy,
{
    /// This initializes the inner state of the sponge permutation, modifying up
    /// to c/2 field elements of the state.
    /// It’s done once in the lifetime of a sponge.
    pub fn start(
        permutation: P,
        iopattern: Vec<IOCall>,
        domain_sep: DomainSeparator,
    ) -> Result<Self, Error> {
        // Compute the tag and initialize the state.
        // Note: This will return an error if the io-pattern is invalid.
        let mut permutation = permutation;
        let tag = permutation.tag(&tag_input(&iopattern, &domain_sep)?);
        permutation.initialize_state(tag);

        Ok(Self {
            permutation,
            pos_absorb: 0,
            pos_sqeeze: 0,
            io_count: 0,
            iopattern,
            domain_sep,
            tag,
            output: Vec::new(),
        })
    }

    /// This marks the end of the sponge life, preventing any further operation.
    /// In particular, the state is erased from memory. The result is ‘OK’, or
    /// an error
    pub fn finish(mut self) -> Result<Vec<T>, Error> {
        // Erase state and its variables except for the io-pattern and the
        // io-count.
        self.permutation
            .state_mut()
            .iter_mut()
            .for_each(|s| *s = P::zero_value());
        self.pos_absorb = 0;
        self.pos_sqeeze = 0;
        self.tag = P::zero_value();
        self.domain_sep = DomainSeparator::from(0);

        match self.io_count == self.iopattern.len() {
            true => Ok(self.output),
            false => Err(Error::IOPatternViolation),
        }
    }

    /// This injects `len` field elements to the state from the field elements
    /// array, interleaving calls to the permutation.
    /// It also checks if the current call matches the IO pattern.
    pub fn absorb(&mut self, len: usize, input: &[T]) -> Result<(), Error> {
        // Check that the io-pattern is not violated
        if self.io_count >= self.iopattern.len() {
            return Err(Error::IOPatternViolation);
        }
        match self.iopattern[self.io_count] {
            IOCall::Squeeze(_) => {
                return Err(Error::IOPatternViolation);
            }
            IOCall::Absorb(expected_len) => {
                // Return error if the absorb length doesn't match the
                // io-pattern, or if the given input doesn't yield enough
                // elements.
                if len != expected_len as usize || len > input.len() {
                    return Err(Error::InvalidAbsorbLen(len));
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
            // add the input to the state using `Permutation::add`
            let pos = self.pos_absorb + Self::capacity();
            let previous_value = self.permutation.state_mut()[pos];
            let sum = self.permutation.add(previous_value, *element);
            self.permutation.state_mut()[pos] = sum;
            self.pos_absorb += 1;
        }

        // Set squeeze position to rate to force a permutation at the next
        // call to squeeze
        self.pos_sqeeze = Self::rate();

        // Increase the position for the io pattern
        self.io_count += 1;

        Ok(())
    }

    /// This extracts `len` field elements from the state, interleaving calls to
    /// the permutation.
    /// It also checks if the current call matches the IO pattern.
    pub fn squeeze(&mut self, len: usize) -> Result<(), Error> {
        // Check that the io-pattern is not violated
        if self.io_count >= self.iopattern.len() {
            return Err(Error::IOPatternViolation);
        }
        match self.iopattern[self.io_count] {
            IOCall::Absorb(_) => {
                return Err(Error::IOPatternViolation);
            }
            IOCall::Squeeze(expected_len) => {
                // Return error if the squeeze length doesn't match the
                // io-pattern.
                if len != expected_len as usize {
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
            self.output.push(
                self.permutation.state_mut()
                    [self.pos_sqeeze + Self::capacity()],
            );
            self.pos_sqeeze += 1;
        }

        // Increase the position for the io pattern
        self.io_count += 1;

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
