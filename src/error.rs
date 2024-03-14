// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

/// Defines all possible error variants for SAFE
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    /// A call to `squeeze`, `absorb` or `finish` that doesn't fit the
    /// io-pattern.
    IOPatternViolation,

    /// Invalid io-pattern.
    InvalidIOPattern,

    /// The input doesn't yield enough input elements.
    TooFewInputElements,

    /// Failed to decrypt the message from the cipher with the provided secret
    /// and nonce.
    DecryptionFailed,
}
