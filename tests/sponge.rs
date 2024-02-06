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
    fn state_mut(&mut self) -> &mut [u8; N] {
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

    fn tag(&mut self, input: &[u8]) -> u8 {
        let mut hasher = DefaultHasher::new();
        Hash::hash_slice(input, &mut hasher);
        (hasher.finish() % 255) as u8
    }

    fn zero_value() -> u8 {
        0
    }

    fn add(&mut self, right: u8, left: u8) -> u8 {
        right + left
    }
}

impl State {
    pub fn new(state: [u8; N]) -> Self {
        Self(state)
    }
}

#[test]
fn sponge() {
    // pick a domain-separator
    let domain_sep = DomainSeparator::from(0);

    // build the io-pattern
    let mut iopattern = Vec::new();
    iopattern.push(IOCall::Absorb(6));
    iopattern.push(IOCall::Squeeze(1));
    iopattern.push(IOCall::Absorb(8));
    iopattern.push(IOCall::Squeeze(3));
    let state = State::new([0; N]);

    // start the sponge
    let mut sponge = Sponge::start(state, iopattern, domain_sep)
        .expect("io-pattern should be valid");

    // absorb the first 6 elements of [1, 2, 3, 8, 5, 6, 7, 8, 9, 10]
    sponge
        .absorb(6, &[1, 2, 3, 8, 5, 6, 7, 8, 9, 10])
        .expect("absorbing should not fail");
    // memory after call to absorb:
    // state: [t, 1, 2, 3, 8, 5, 6]
    // output: []

    // call to squeeze triggers one permutation:
    sponge.squeeze(1).expect("squeezing should not fail");
    // memory after call to squeeze:
    // state: [1, 2, 3, 8, 5, 6, t]
    // output: [2]

    // call to absorb the 8 elements of [6, 6, 6, 6, 6, 6, 6, 6] triggers one
    // permutation and adds the input to the state:
    sponge
        .absorb(8, &[6, 6, 6, 6, 6, 6, 6, 6])
        .expect("absorbtion should not fail");
    // state during this call to absorb:
    // absorbing the first 6 elements: [1, 8. 9, 14, 11, 12, t + 6]
    // calling permutation:            [8. 9, 14, 11, 12, t + 6, 1]
    // absorbing the last 2 elements:  [8. 15, 20, 11, 12, t + 6, 1]
    // output: [2]

    // call to squeeze 3 elements triggers another permutation and adds 3
    // more elements to the output:
    sponge.squeeze(3).expect("squeezing should not fail");
    // memory after call to squeeze:
    // state: [15, 20, 11, 12, t + 6, 1, 8]
    // output: [2, 20, 11, 12]

    let output = sponge.finish().expect("Finishing should not fail");
    assert_eq!(output, vec![2, 20, 11, 12]);
}

// #[test]
// #[should_panic]
// fn sponge_fails {

// }
