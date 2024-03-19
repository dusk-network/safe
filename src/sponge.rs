// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::{tag_input, Call, Error};

/// This trait defines the behavior of a sponge algorithm.
///
/// Note: The trait's specific implementation of addition enables usage within
/// zero-knowledge circuits.
pub trait Safe<T, const W: usize>
where
    T: Default + Copy + Zeroize,
{
    /// Apply one permutation to the state.
    fn permute(&mut self, state: &mut [T; W]);

    /// Create the tag by hashing the tag input to an element of type `T`.
    ///
    /// # Parameters
    ///
    /// - `input`: The domain-separator and IO-pattern encoded as a slice of
    ///   bytes.
    ///
    /// # Returns
    ///
    /// A tag element as the hash of the input to a field element `T`.
    fn tag(&mut self, input: &[u8]) -> T;

    /// Add two values of type `T` and return the result.
    ///
    /// # Parameters
    ///
    /// - `right`: The right operand of type `T`.
    /// - `left`: The left operand of type `T`.
    ///
    /// # Returns
    ///
    /// The result of the addition, of type `T`.
    fn add(&mut self, right: &T, left: &T) -> T;

    /// Create a state and initialize it with the tag and default values of `T`.
    ///
    /// # Parameters
    ///
    /// - `tag`: The initial tag value as computed by [`Self::tag`].
    ///
    /// # Returns
    ///
    /// An array of type `[T; W]` representing the initialized state.
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
    T: Default + Copy + Zeroize,
{
    state: [T; W],
    pub(crate) safe: S,
    pos_absorb: usize,
    pos_squeeze: usize,
    io_count: usize,
    iopattern: Vec<Call>,
    domain_sep: u64,
    pub(crate) output: Vec<T>,
}

impl<S, T, const W: usize> Sponge<S, T, W>
where
    S: Safe<T, W>,
    T: Default + Copy + Zeroize,
{
    /// The capacity of the sponge.
    const CAPACITY: usize = 1;

    /// The rate of the sponge.
    const RATE: usize = W - Self::CAPACITY;

    /// This initializes the sponge, setting the first element of the state to
    /// the [`Safe::tag()`] and the other elements to the default value of
    /// `T`. It’s done once in the lifetime of a sponge.
    ///
    /// # Parameters
    ///
    /// - `safe`: The sponge safe implementation.
    /// - `iopattern`: The IO-pattern for the sponge.
    /// - `domain_sep`: The domain separator to be used.
    ///
    /// # Returns
    ///
    /// A result containing the initialized Sponge on success, or an `Error` if
    /// the IO-pattern is invalid.
    pub fn start(
        safe: S,
        iopattern: impl Into<Vec<Call>>,
        domain_sep: u64,
    ) -> Result<Self, Error> {
        // Compute the tag and initialize the state.
        // Note: This will return an error if the IO-pattern is invalid.
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
    ///
    /// # Returns
    ///
    /// A result containing the output vector on success, or an `Error` if the
    /// IO-pattern wasn't followed.
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
    /// call matches the IO-pattern.
    ///
    /// # Parameters
    ///
    /// - `len`: The number of field elements to absorb.
    /// - `input`: The input slice of field elements.
    ///
    /// # Returns
    ///
    /// A result indicating success if the operation completes, or an `Error`
    /// if the IO-pattern wasn't followed.
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
        // Check that the IO-pattern is followed
        match self.iopattern.get(self.io_count) {
            // only proceed if we expect a call to absorb with the correct
            // length as per the IO-pattern
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

        // Increase the position for the IO-pattern
        self.io_count += 1;

        Ok(())
    }

    /// This extracts `len` field elements from the state with interleaving
    /// calls to the permutation function. It also checks if the call matches
    /// the IO-pattern.
    ///
    /// # Parameters
    ///
    /// - `len`: The number of field elements to squeeze.
    ///
    /// # Returns
    ///
    /// A result indicating success if the operation completes, or an `Error`
    /// if the IO-pattern wasn't followed.
    pub fn squeeze(&mut self, len: usize) -> Result<(), Error> {
        // Check that the IO-pattern is followed
        match self.iopattern.get(self.io_count) {
            // only proceed if we expect a call to squeeze with the correct
            // length as per the IO-pattern
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

        // Increase the position for the IO-pattern
        self.io_count += 1;

        Ok(())
    }
}

impl<S, T, const W: usize> Drop for Sponge<S, T, W>
where
    S: Safe<T, W>,
    T: Default + Copy + Zeroize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<S, T, const W: usize> Zeroize for Sponge<S, T, W>
where
    S: Safe<T, W>,
    T: Default + Copy + Zeroize,
{
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.pos_absorb.zeroize();
        self.pos_squeeze.zeroize();
        self.output.zeroize();
    }
}
