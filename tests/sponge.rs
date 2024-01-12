// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use safe::{DomainSeparator, IOCall, Permutation, Sponge};

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const N: usize = 7;

#[derive(Default, Debug, Clone, Copy, PartialEq)]
struct State([u8; N]);

impl Permutation<u8, N> for State {
    fn new(state: [u8; N]) -> Self {
        Self(state)
    }

    fn inner_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    // rotate every item one item to the left
    fn permute(&mut self) {
        let tmp = self.0[0];
        for i in 1..N {
            self.0[i - 1] = self.0[i];
        }
        self.0[N - 1] = tmp;
    }

    fn tag(input: &[u8]) -> u8 {
        let mut hasher = DefaultHasher::new();
        Hash::hash_slice(input, &mut hasher);
        (hasher.finish() % 255) as u8
    }
}

#[test]
fn sponge() {
    let domain_sep = DomainSeparator::from(42);
    let mut iopattern = Vec::new();
    iopattern.push(IOCall::Absorb(N as u32 - 1));
    iopattern.push(IOCall::Squeeze(1));

    let mut sponge: Sponge<State, u8, N> = Sponge::start(iopattern, domain_sep);
    sponge
        .absorb(N - 1, &[1, 2, 3, 4, 5, 6])
        .expect("absorbing should not fail");
    let output = sponge.squeeze(1).expect("squeezing should not fail");
    println!("{:?}", sponge);
    assert_eq!(output[0], 2);
}