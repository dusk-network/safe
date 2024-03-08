// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::{tag_input, Call, Error};

/// Trait to implement the Sponge API
pub trait Safe<T, const W: usize>
where
    T: Default + Copy,
{
    /// Apply one permutation to the state.
    fn permute(&mut self, state: &mut [T; W]);

    /// Create the tag by hashing the tag input to an element of type `T`.
    fn tag(&mut self, input: &[u8]) -> T;

    /// Add two values of type `T` and return the result.
    /// Needing to explicitly implement this (as opposed to using field element
    /// addition) is a trade-off for being able to build a circuit with the
    /// `Safe` trait (in which `T` refers to field elements appended to the
    /// circuit).
    fn add(&mut self, right: &T, left: &T) -> T;

    /// Create a state and initialize it with the tag and default values of `T`.
    fn initialized_state(tag: T) -> [T; W] {
        let mut state = [T::default(); W];
        state[0] = tag;
        state
    }
}

/// Struct that implements the Sponge API over field elements.
///
/// The capacity is fixed to one field element and the rate are `W - 1` field
/// elements.
#[derive(Debug, Clone, PartialEq)]
pub struct Sponge<S, T, const W: usize>
where
    S: Safe<T, W>,
    T: Default + Copy,
{
    state: [T; W],
    safe: S,
    pos_absorb: usize,
    pos_squeeze: usize,
    io_count: usize,
    iopattern: Vec<Call>,
    domain_sep: u64,
    output: Vec<T>,
}

impl<S, T, const W: usize> Sponge<S, T, W>
where
    S: Safe<T, W>,
    T: Default + Copy,
{
    /// The capacity of the sponge.
    const CAPACITY: usize = 1;

    /// The rate of the sponge.
    const RATE: usize = W - Self::CAPACITY;

    /// This initializes the sponge, setting the first element of the state to
    /// the [`Safe::tag()`] and the other elements to the default value of
    /// `T`. It’s done once in the lifetime of a sponge.
    pub fn start(
        safe: S,
        iopattern: impl Into<Vec<Call>>,
        domain_sep: u64,
    ) -> Result<Self, Error> {
        // Compute the tag and initialize the state.
        // Note: This will return an error if the io-pattern is invalid.
        let iopattern: Vec<Call> = iopattern.into();
        let mut safe = safe;
        let tag = safe.tag(&tag_input(&iopattern, domain_sep)?);
        let state = S::initialized_state(tag);

        Ok(Self {
            state,
            safe,
            pos_absorb: 0,
            pos_squeeze: 0,
            io_count: 0,
            iopattern,
            domain_sep,
            output: Vec::new(),
        })
    }

    /// This marks the end of the sponge life, preventing any further operation.
    /// In particular, the state is erased from memory.
    pub fn finish(mut self) -> Result<Vec<T>, Error> {
        let ret = match self.io_count == self.iopattern.len() {
            true => Ok(self.output.clone()),
            false => Err(Error::IOPatternViolation),
        };
        // no matter the return, we erase the internal state of the sponge
        self.zeroize();
        ret
    }

    /// This absorbs `len` field elements from the input into the state with
    /// interleaving calls to the permutation function. It also checks if the
    /// call matches the IO pattern.
    pub fn absorb(
        &mut self,
        len: usize,
        input: impl AsRef<[T]>,
    ) -> Result<(), Error> {
        // Check that input yields enough elements
        if input.as_ref().len() < len {
            self.zeroize();
            return Err(Error::TooFewInputElements);
        }
        // Check that the io-pattern is followed
        match self.iopattern.get(self.io_count) {
            // only proceed if we expect a call to absorb with the correct
            // length as per the io-pattern
            Some(Call::Absorb(call_len)) if *call_len == len => {}
            Some(Call::Absorb(_)) => {
                self.zeroize();
                return Err(Error::IOPatternViolation);
            }
            _ => {
                self.zeroize();
                return Err(Error::IOPatternViolation);
            }
        }

        // Absorb `len` elements into the state, calling [`permute`] when the
        // absorb-position reached the rate.
        for element in input.as_ref().iter().take(len) {
            if self.pos_absorb == Self::RATE {
                self.safe.permute(&mut self.state);

                self.pos_absorb = 0;
            }
            // add the input to the state using `Safe::add`
            let pos = self.pos_absorb + Self::CAPACITY;
            let previous_value = self.state[pos];
            let sum = self.safe.add(&previous_value, element);
            self.state[pos] = sum;
            self.pos_absorb += 1;
        }

        // Set squeeze position to rate to force a permutation at the next
        // call to squeeze
        self.pos_squeeze = Self::RATE;

        // Increase the position for the io pattern
        self.io_count += 1;

        Ok(())
    }

    /// This extracts `len` field elements from the state with interleaving
    /// calls to the permutation function. It also checks if the call matches
    /// the IO pattern.
    pub fn squeeze(&mut self, len: usize) -> Result<(), Error> {
        // Check that the io-pattern is followed
        match self.iopattern.get(self.io_count) {
            // only proceed if we expect a call to squeeze with the correct
            // length as per the io-pattern
            Some(Call::Squeeze(call_len)) if *call_len == len => {}
            Some(Call::Squeeze(_)) => {
                self.zeroize();
                return Err(Error::IOPatternViolation);
            }
            _ => {
                self.zeroize();
                return Err(Error::IOPatternViolation);
            }
        }

        // Squeeze 'len` field elements from the state, calling [`permute`] when
        // the squeeze-position reached the rate.
        for _ in 0..len {
            if self.pos_squeeze == Self::RATE {
                self.safe.permute(&mut self.state);

                self.pos_squeeze = 0;
                self.pos_absorb = 0;
            }
            self.output
                .push(self.state[self.pos_squeeze + Self::CAPACITY]);
            self.pos_squeeze += 1;
        }

        // Increase the position for the io pattern
        self.io_count += 1;

        Ok(())
    }
}

impl<S, T, const W: usize> Drop for Sponge<S, T, W>
where
    S: Safe<T, W>,
    T: Default + Copy,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<S, T, const W: usize> Zeroize for Sponge<S, T, W>
where
    S: Safe<T, W>,
    T: Default + Copy,
{
    fn zeroize(&mut self) {
        self.state.iter_mut().for_each(|elem| *elem = T::default());
        self.pos_absorb = 0;
        self.pos_squeeze = 0;
        self.output.iter_mut().for_each(|elem| *elem = T::default());
    }
}
