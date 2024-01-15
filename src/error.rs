// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

/// Defines all possible error for SAFE
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    /// A violation of the [`IOPattern`] during a call to [`absorb`] or
    /// [`squeeze`].
    IOPatternViolation,

    /// A violation of the [`IOPattern`] during a call to [`absorb`] or
    /// [`squeeze`].
    InvalidAbsorb,

    /// A violation of the [`IOPattern`] during a call to [`absorb`] or
    /// [`squeeze`].
    InvalidSqueeze,

    /// Invalid Absorb length
    InvalidAbsorbLen(usize),

    /// Invalid Squeeze length
    InvalidSqueezeLen(usize),
}
