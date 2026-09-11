// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroize;

use crate::{Call, Error, tag_input};

/// This trait defines the behavior of a sponge algorithm.
///
/// Note: The trait's specific implementation of addition enables usage within
/// zero-knowledge circuits.
///
/// Implementers supply the security boundary: `T::default()` must represent
/// the additive identity (or override `initialized_state`), and `add` must be
/// field addition. The permutation and pattern-to-field hash must meet the
/// security requirements of the chosen SAFE instantiation. Field cardinality,
/// not the Rust representation size, determines capacity security. Native
/// secret-dependent operations must be constant-time; circuit implementations
/// must constrain their results. Any secrets retained by the backend require
/// its own cleanup: sponge zeroization does not erase the backend.
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
/// The capacity is fixed to one field element and the rate is `W - 1` field
/// elements. Widths below two are rejected. Operation errors and explicit
/// zeroization permanently invalidate the instance, including subsequent
/// clones of that failed instance; construct a new sponge to start again.
#[derive(Clone, PartialEq)]
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
    failed: bool,
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
    /// the IO-pattern is invalid or the width is less than two.
    pub fn start(
        safe: S,
        iopattern: impl Into<Vec<Call>>,
        domain_sep: u64,
    ) -> Result<Self, Error> {
        if W < 2 {
            return Err(Error::InvalidIOPattern);
        }
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
            failed: false,
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
        let ret = if !self.failed && self.io_count == self.iopattern.len() {
            Ok(core::mem::take(&mut self.output))
        } else {
            Err(Error::IOPatternViolation)
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
    #[inline]
    pub fn absorb(
        &mut self,
        len: usize,
        input: impl AsRef<[T]>,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::IOPatternViolation);
        }
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
    /// if the IO-pattern wasn't followed. Unrepresentable or unavailable
    /// output storage returns [`Error::InvalidIOPattern`] and invalidates the
    /// sponge. Callers must bound requested output to their memory budget.
    // Specialize small, constant-length calls without inlining allocation.
    #[inline(always)]
    pub fn squeeze(&mut self, len: usize) -> Result<(), Error> {
        if self.failed {
            return Err(Error::IOPatternViolation);
        }
        // Check that the IO-pattern is followed
        match self.iopattern.get(self.io_count) {
            // only proceed if we expect a call to squeeze with the correct
            // length as per the IO-pattern
            Some(Call::Squeeze(call_len)) if *call_len == len => {}
            _ => {
                self.zeroize();
                return Err(Error::IOPatternViolation);
            }
        }

        if len > self.output.capacity() - self.output.len()
            && self.grow_output(len).is_err()
        {
            self.zeroize();
            return Err(Error::InvalidIOPattern);
        }

        // Squeeze `len` field elements from the state, calling [`permute`] when
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

    // Never let Vec reallocate live secret output: allocator growth may free
    // the old allocation without wiping it. Grow only for actual squeeze
    // requests, not arbitrarily large future lengths in pattern metadata.
    // Keep allocation and wiping out of the repeated-call fast path.
    #[inline(never)]
    fn grow_output(&mut self, len: usize) -> Result<(), Error> {
        let required = self
            .output
            .len()
            .checked_add(len)
            .ok_or(Error::InvalidIOPattern)?;
        // No spare capacity is useful after the final operation. Keep
        // amortized growth for streaming, but not for a final AE tag.
        let capacity = if self.io_count + 1 == self.iopattern.len() {
            required
        } else {
            required.max(self.output.capacity().saturating_mul(2))
        };
        let mut replacement = Vec::new();
        replacement
            .try_reserve(capacity)
            .map_err(|_| Error::InvalidIOPattern)?;
        replacement.extend_from_slice(&self.output);
        self.output.zeroize();
        self.output = replacement;
        Ok(())
    }
}

impl<S, T, const W: usize> fmt::Debug for Sponge<S, T, W>
where
    S: Safe<T, W>,
    T: Default + Copy + Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sponge")
            .field("width", &W)
            .field("io_count", &self.io_count)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
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
    /// Erase the state and output, permanently invalidating this instance.
    fn zeroize(&mut self) {
        self.failed = true;
        self.state.zeroize();
        self.pos_absorb.zeroize();
        self.pos_squeeze.zeroize();
        self.output.zeroize();
    }
}

#[cfg(test)]
mod storage_tests {
    // Allocation-boundary tests; the integer/identity backend is NOT
    // cryptographic.
    extern crate std;
    use alloc::vec;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::ptr;

    use super::*;

    std::thread_local! {
        // Watch one initialized u64, never uninitialized capacity or freed memory.
        static WATCH: Cell<usize> = const { Cell::new(0) };
        static WIPED: Cell<bool> = const { Cell::new(false) };
        static FAIL_NEXT: Cell<bool> = const { Cell::new(false) };
        static FAIL_AFTER_SUBTRACT: Cell<bool> = const { Cell::new(false) };
        static PANIC_ON_SUBTRACT: Cell<bool> = const { Cell::new(false) };
    }
    struct Allocator;
    fn observe(ptr: *mut u8) {
        let _ = WATCH.try_with(|watch| {
            let address = watch.get();
            if address != 0 && address == ptr as usize {
                // SAFETY: watch() registers an initialized u64; this is the
                // matching, still-live allocation. Clearing a Vec<u64> does
                // not invalidate the initialized bytes in its retained storage.
                WIPED.set(unsafe { *ptr.cast::<u64>() == 0 });
                watch.set(0);
            }
        });
    }
    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if FAIL_NEXT
                .try_with(|flag| flag.replace(false))
                .unwrap_or(false)
            {
                return ptr::null_mut();
            }
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            observe(ptr);
            unsafe { System.dealloc(ptr, layout) }
        }
        unsafe fn realloc(
            &self,
            ptr: *mut u8,
            layout: Layout,
            size: usize,
        ) -> *mut u8 {
            observe(ptr);
            unsafe { System.realloc(ptr, layout, size) }
        }
    }
    #[global_allocator]
    static ALLOCATOR: Allocator = Allocator;

    #[derive(Clone)]
    struct Identity;
    impl Safe<u64, 4> for Identity {
        fn tag(&mut self, _: &[u8]) -> u64 {
            0
        }
        fn permute(&mut self, _: &mut [u64; 4]) {}
        fn add(&mut self, a: &u64, b: &u64) -> u64 {
            a.wrapping_add(*b)
        }
    }
    fn watch(value: &u64) {
        assert_ne!(*value, 0);
        WIPED.set(false);
        WATCH.set(value as *const u64 as usize);
    }
    #[test]
    fn growth_wipes_old_output_including_clones() {
        let mut original = Sponge::start(
            Identity,
            vec![Call::Absorb(1), Call::Squeeze(1), Call::Squeeze(4)],
            0,
        )
        .unwrap();
        original.absorb(1, [99]).unwrap();
        original.squeeze(1).unwrap();
        let cloned = original.clone();
        for mut sponge in [original, cloned] {
            // Identity's tag ignores the pattern, so adapt the final call to
            // force growth of this instance's actual buffer (already nonempty).
            let len = sponge.output.capacity().max(4);
            sponge.iopattern[2] = Call::Squeeze(len);
            watch(&sponge.output[0]);
            sponge.squeeze(len).unwrap();
            assert!(
                WIPED.get(),
                "old output must be wiped before allocator release"
            );
            let expected: Vec<_> =
                [99, 0, 0].into_iter().cycle().take(len + 1).collect();
            assert_eq!(sponge.finish().unwrap(), expected);
        }
    }
    #[test]
    fn allocation_failure_is_terminal() {
        for buffered in [false, true] {
            let mut sponge = Sponge::start(
                Identity,
                vec![Call::Absorb(1), Call::Squeeze(1), Call::Squeeze(1)],
                0,
            )
            .unwrap();
            sponge.absorb(1, [99]).unwrap();
            if buffered {
                sponge.squeeze(1).unwrap();
                watch(&sponge.output[0]);
            }
            // Identity's constant tag permits adapting the next call to force
            // growth.
            let len = sponge.output.capacity().max(1);
            sponge.iopattern[sponge.io_count] = Call::Squeeze(len);
            FAIL_NEXT.set(true);
            let result = sponge.squeeze(len);
            assert!(!FAIL_NEXT.replace(false));
            assert_eq!(result, Err(Error::InvalidIOPattern));
            assert!(sponge.output.is_empty());
            if buffered {
                // Inspect now, before finish/Drop could mask missed error
                // cleanup.
                observe(sponge.output.as_mut_ptr().cast());
                assert!(WIPED.get(), "buffered output must be wiped on error");
            }
            assert_eq!(sponge.squeeze(len), Err(Error::IOPatternViolation));
            assert_eq!(sponge.absorb(1, [99]), Err(Error::IOPatternViolation));
            assert_eq!(sponge.finish(), Err(Error::IOPatternViolation));
        }
    }
    #[cfg(feature = "encryption")]
    impl crate::Encryption<u64, 4> for Identity {
        fn subtract(&mut self, a: &u64, b: &u64) -> u64 {
            if FAIL_AFTER_SUBTRACT.replace(false) {
                watch(b);
                FAIL_NEXT.set(true);
            }
            if PANIC_ON_SUBTRACT.replace(false) {
                watch(b);
                panic!("injected backend panic");
            }
            a.wrapping_sub(*b)
        }
        fn is_equal(&mut self, a: &u64, b: &u64) -> bool {
            a == b
        }
    }
    #[cfg(feature = "encryption")]
    #[test]
    fn unwinding_wipes_message_buffer() {
        PANIC_ON_SUBTRACT.set(true);
        let result = std::panic::catch_unwind(|| {
            crate::decrypt(Identity, 0u64, [77u64; 5], &[7, 8], &9)
        });
        assert_eq!(
            result.unwrap_err().downcast_ref::<&str>(),
            Some(&"injected backend panic")
        );
        assert!(WIPED.get(), "message buffer must be wiped on unwind");
    }
    #[cfg(feature = "encryption")]
    #[test]
    fn late_allocation_failure_wipes_decrypted_message() {
        FAIL_AFTER_SUBTRACT.set(true);
        let result = crate::decrypt(Identity, 0u64, [77u64; 5], &[7, 8], &9);
        assert!(!FAIL_NEXT.replace(false));
        assert_eq!(result, Err(Error::InvalidIOPattern));
        assert!(
            WIPED.get(),
            "plaintext must be wiped on the late squeeze error"
        );
    }
}
