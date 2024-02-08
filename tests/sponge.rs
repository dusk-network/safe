// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use safe::{DomainSeparator, Error, IOCall, Permutation, Sponge};

const W: usize = 7;

#[derive(Default, Debug, Clone, Copy, PartialEq)]
struct State([BlsScalar; W]);

impl Permutation<BlsScalar, W> for State {
    const ZERO_VALUE: BlsScalar = BlsScalar::zero();

    fn state_mut(&mut self) -> &mut [BlsScalar; W] {
        &mut self.0
    }

    // rotate every item one item to the left, first item becomes last
    fn permute(&mut self) {
        let tmp = self.0[0];
        for i in 1..W {
            self.0[i - 1] = self.0[i];
        }
        self.0[W - 1] = tmp;
    }

    // Setting the tag to a constant zero here so that the sponge state output
    // is predictable, this should *not* be done in production as it makes the
    // resulting hash vulnerable to collisions attacks.
    fn tag(&mut self, input: &[u8]) -> BlsScalar {
        let _input = input;
        BlsScalar::zero()
    }

    fn add(&mut self, right: &BlsScalar, left: &BlsScalar) -> BlsScalar {
        right + left
    }
}

impl State {
    pub fn new(state: [BlsScalar; W]) -> Self {
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
    iopattern.push(IOCall::Absorb(4));
    iopattern.push(IOCall::Absorb(4));
    iopattern.push(IOCall::Squeeze(3));
    iopattern.push(IOCall::Squeeze(4));

    // start the sponge
    let mut sponge = Sponge::start(
        State::new([BlsScalar::zero(); W]),
        iopattern,
        domain_sep,
    )
    .expect("io-pattern should be valid");

    // absorb the first 6 elements of [1, 2, 3, 8, 5, 6, 7]
    sponge
        .absorb(
            6,
            &[
                BlsScalar::from(1),
                BlsScalar::from(2),
                BlsScalar::from(3),
                BlsScalar::from(8),
                BlsScalar::from(5),
                BlsScalar::from(6),
                BlsScalar::from(7),
            ],
        )
        .expect("absorbing should not fail");
    // memory after call to absorb:
    // state: [0, 1, 2, 3, 8, 5, 6]
    // output: []

    // call to squeeze triggers one permutation:
    sponge.squeeze(1).expect("squeezing should not fail");
    // memory after call to squeeze:
    // state: [1, 2, 3, 8, 5, 6, 0]
    // output: [2]

    // now we twice absorb 4 times the element `6`
    let input = [BlsScalar::from(6); 4];
    sponge
        .absorb(4, &input)
        .expect("absorbtion should not fail");
    sponge
        .absorb(4, &input)
        .expect("absorbtion should not fail");
    // state during these calls to absorb:
    // absorbing the first 6 elements: [1, 8. 9, 14, 11, 12, 6]
    // calling permutation:            [8. 9, 14, 11, 12, 6, 1]
    // absorbing the last 2 elements:  [8. 15, 20, 11, 12, 6, 1]
    // output: [2]

    // call to squeeze 3 elements triggers another permutation and adds 3
    // more elements to the output:
    sponge.squeeze(3).expect("squeezing should not fail");
    // memory after call to squeeze:
    // state: [15, 20, 11, 12, 6, 1, 8]
    // output: [2, 20, 11, 12]

    // call to squeeze 4 elements first squeezes 3 more elements from the state,
    // triggers a permutation and squeezes the last element:
    sponge.squeeze(4).expect("squeezing should not fail");
    // memory after squeezing 3 elements:
    // state: [15, 20, 11, 12, 6, 1, 8]
    // output: [2, 20, 11, 12, 6, 1, 8]
    // memory after permuting the state and squeezing one more element:
    // state: [20, 11, 12, 6, 1, 8, 15]
    // output: [2, 20, 11, 12, 6, 1, 8, 11]

    let output = sponge.finish().expect("Finishing should not fail");
    assert_eq!(
        output,
        vec![
            BlsScalar::from(2),
            BlsScalar::from(20),
            BlsScalar::from(11),
            BlsScalar::from(12),
            BlsScalar::from(6),
            BlsScalar::from(1),
            BlsScalar::from(8),
            BlsScalar::from(11),
        ]
    );
}

#[test]
fn absorb_fails() {
    // pick a domain-separator
    let domain_sep = DomainSeparator::from(0);

    // build the io-pattern
    let mut iopattern = Vec::new();
    iopattern.push(IOCall::Absorb(6));
    iopattern.push(IOCall::Squeeze(1));

    // start the sponge
    let input = [BlsScalar::one(); 10];
    let state = State::new([BlsScalar::zero(); W]);
    let mut sponge = Sponge::start(state, iopattern, domain_sep)
        .expect("io-pattern should be valid");

    // input-slice smaller than len
    let error = sponge.clone().absorb(6, &input[..4]).unwrap_err();
    assert_eq!(error, Error::InvalidAbsorbLen(6));

    // absorb len is not as io-pattern specifies
    let error = sponge.clone().absorb(4, &input[..4]).unwrap_err();
    assert_eq!(error, Error::InvalidAbsorbLen(4));

    // unexpected call to squeeze
    let error = sponge.squeeze(1).unwrap_err();
    assert_eq!(error, Error::IOPatternViolation);
}

#[test]
fn squeeze_fails() {
    // pick a domain-separator
    let domain_sep = DomainSeparator::from(0);

    // build the io-pattern
    let mut iopattern = Vec::new();
    iopattern.push(IOCall::Absorb(6));
    iopattern.push(IOCall::Squeeze(1));

    // start the sponge
    let input = [BlsScalar::one(); 10];
    let state = State::new([BlsScalar::zero(); W]);
    let mut sponge = Sponge::start(state, iopattern, domain_sep)
        .expect("io-pattern should be valid");

    // absorb 6 elements as specified by the io-pattern
    sponge
        .absorb(6, &input[..6])
        .expect("absorbtion should not fail");

    // absorb len is not as io-pattern specifies
    let error = sponge.clone().squeeze(4).unwrap_err();
    assert_eq!(error, Error::InvalidSqueezeLen(4));

    // unexpected call to squeeze
    let error = sponge.absorb(1, &input).unwrap_err();
    assert_eq!(error, Error::IOPatternViolation);
}

#[test]
fn finish_fails() {
    // pick a domain-separator
    let domain_sep = DomainSeparator::from(0);

    // build the io-pattern
    let mut iopattern = Vec::new();
    iopattern.push(IOCall::Absorb(6));
    iopattern.push(IOCall::Squeeze(1));
    iopattern.push(IOCall::Absorb(1));
    iopattern.push(IOCall::Squeeze(1));

    // start the sponge
    let input = [BlsScalar::one(); 10];
    let state = State::new([BlsScalar::zero(); W]);
    let mut sponge = Sponge::start(state, iopattern, domain_sep)
        .expect("io-pattern should be valid");

    // absorb 6 elements as specified by the io-pattern
    sponge
        .absorb(6, &input[..6])
        .expect("absorbtion should not fail");
    // squeeze 1 element as specified by the io-pattern
    sponge.squeeze(1).expect("squeeze should not fail");

    // try to finalize before the io-pattern is exhausted
    let error = sponge.clone().finish().unwrap_err();
    assert_eq!(error, Error::IOPatternViolation);

    // absorb 1 elements as specified by the io-pattern
    sponge
        .absorb(1, &input)
        .expect("absorbtion should not fail");
    // squeeze 1 element as specified by the io-pattern
    sponge.squeeze(1).expect("squeeze should not fail");

    // absorbtion after io-pattern is exhausted should fail
    let error = sponge.absorb(1, &input).unwrap_err();
    assert_eq!(error, Error::IOPatternViolation);
}
