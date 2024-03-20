// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

/// Defines all possible error variants for the SAFE library.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    /// This error occurs when the expected IO-pattern sequence wasn't followed
    /// during the usage of the sponge algorithm.
    IOPatternViolation,

    /// This error occurs when the provided IO-pattern is not valid.
    /// This means that:
    /// - It doesn't start with a call to squeeze or
    /// - It doesn't end with a call to absorb or
    /// - Every call to absorb or squeeze has a positive length.
    InvalidIOPattern,

    /// This error occurs when the input elements provided to the
    /// [`Sponge::absorb`] are less than the amount that should be absorbed.
    TooFewInputElements,

    /// This error indicates a failure during the encryption process.
    EncryptionFailed,

    /// This error indicates a failure during the decryption process.
    DecryptionFailed,
}
