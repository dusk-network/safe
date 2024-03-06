// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_safe::{Call, Error, Safe, Sponge};

const W: usize = 7;

#[derive(Default, Debug, Clone, Copy, PartialEq)]
struct Rotate();

impl Safe<BlsScalar, W> for Rotate {
    // rotate every item one item to the left, first item becomes last
    fn permute(&mut self, state: &mut [BlsScalar; W]) {
        let tmp = state[0];
        for i in 1..W {
            state[i - 1] = state[i];
        }
        state[W - 1] = tmp;
    }

    // Setting the tag to a constant zero here so that the sponge output
    // is predictable, this should *not* be done in production as it makes the
    // resulting hash vulnerable to collisions attacks.
    fn tag(&mut self, _input: &[u8]) -> BlsScalar {
        BlsScalar::zero()
    }

    fn add(&mut self, right: &BlsScalar, left: &BlsScalar) -> BlsScalar {
        right + left
    }
}

impl Rotate {
    pub fn new() -> Self {
        Self()
    }
}

#[test]
fn sponge() -> Result<(), Error> {
    // pick a domain-separator
    let domain_sep = 0;

    // build the io-pattern
    let iopattern = vec![
        Call::Absorb(6),
        Call::Squeeze(1),
        Call::Absorb(4),
        Call::Absorb(4),
        Call::Squeeze(3),
        Call::Squeeze(4),
    ];

    // start the sponge
    let mut sponge = Sponge::start(Rotate::new(), iopattern, domain_sep)?;

    // absorb the first 6 elements of [1, 2, 3, 8, 5, 6, 7]
    sponge.absorb(
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
    )?;
    // memory after call to absorb:
    // state: [0, 1, 2, 3, 8, 5, 6]
    // output: []

    // call to squeeze triggers one permutation:
    sponge.squeeze(1)?;
    // memory after call to squeeze:
    // state: [1, 2, 3, 8, 5, 6, 0]
    // output: [2]

    // now we twice absorb 4 times the element `6`
    let input = [BlsScalar::from(6); 4];
    sponge.absorb(4, &input)?;
    sponge.absorb(4, &input)?;
    // state during these calls to absorb:
    // absorbing the first 6 elements: [1, 8. 9, 14, 11, 12, 6]
    // calling permutation:            [8. 9, 14, 11, 12, 6, 1]
    // absorbing the last 2 elements:  [8. 15, 20, 11, 12, 6, 1]
    // output: [2]

    // call to squeeze 3 elements triggers another permutation and adds 3
    // more elements to the output:
    sponge.squeeze(3)?;
    // memory after call to squeeze:
    // state: [15, 20, 11, 12, 6, 1, 8]
    // output: [2, 20, 11, 12]

    // call to squeeze 4 elements first squeezes 3 more elements from the state,
    // triggers a permutation and squeezes the last element:
    sponge.squeeze(4)?;
    // memory after squeezing 3 elements:
    // state: [15, 20, 11, 12, 6, 1, 8]
    // output: [2, 20, 11, 12, 6, 1, 8]
    // memory after permuting the state and squeezing one more element:
    // state: [20, 11, 12, 6, 1, 8, 15]
    // output: [2, 20, 11, 12, 6, 1, 8, 11]

    let output = sponge.finish()?;
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

    Ok(())
}

#[test]
fn absorb_fails() -> Result<(), Error> {
    // pick a domain-separator
    let domain_sep = 0;

    // build the io-pattern
    let iopattern = vec![Call::Absorb(6), Call::Squeeze(1)];

    // start the sponge
    let input = [BlsScalar::one(); 10];
    let mut sponge = Sponge::start(Rotate::new(), iopattern, domain_sep)?;

    // input-slice smaller than len
    let error = sponge.clone().absorb(6, &input[..4]).unwrap_err();
    assert_eq!(error, Error::TooFewInputElements);

    // absorb len is not as io-pattern specifies
    let error = sponge.clone().absorb(4, &input[..4]).unwrap_err();
    assert_eq!(error, Error::IOPatternViolation);

    // unexpected call to squeeze
    let error = sponge.squeeze(1).unwrap_err();
    assert_eq!(error, Error::IOPatternViolation);

    Ok(())
}

#[test]
fn squeeze_fails() -> Result<(), Error> {
    // pick a domain-separator
    let domain_sep = 0;

    // build the io-pattern
    let iopattern = vec![Call::Absorb(6), Call::Squeeze(1)];

    // start the sponge
    let input = [BlsScalar::one(); 10];
    let mut sponge = Sponge::start(Rotate::new(), iopattern, domain_sep)?;

    // absorb 6 elements as specified by the io-pattern
    sponge.absorb(6, &input[..6])?;

    // squeeze 4 elements when io-pattern expects 1
    let error = sponge.clone().squeeze(4).unwrap_err();
    assert_eq!(error, Error::IOPatternViolation);

    // unexpected call to absorb when io-pattern expects squeeze
    let error = sponge.absorb(1, &input).unwrap_err();
    assert_eq!(error, Error::IOPatternViolation);

    Ok(())
}

#[test]
fn finish_fails() -> Result<(), Error> {
    // pick a domain-separator
    let domain_sep = 0;

    // build the io-pattern
    let iopattern = vec![
        Call::Absorb(6),
        Call::Squeeze(1),
        Call::Absorb(1),
        Call::Squeeze(1),
    ];
    // start the sponge
    let input = [BlsScalar::one(); 10];
    let mut sponge = Sponge::start(Rotate::new(), iopattern, domain_sep)?;

    // absorb 6 elements as specified by the io-pattern
    sponge.absorb(6, &input[..6])?;
    // squeeze 1 element as specified by the io-pattern
    sponge.squeeze(1)?;

    // try to finalize before the io-pattern is exhausted
    let error = sponge.clone().finish().unwrap_err();
    assert_eq!(error, Error::IOPatternViolation);

    // absorb 1 element as specified by the io-pattern
    sponge.absorb(1, &input)?;
    // squeeze 1 element as specified by the io-pattern
    sponge.squeeze(1)?;

    // absorption after io-pattern is exhausted should fail
    let error = sponge.absorb(1, &input).unwrap_err();
    assert_eq!(error, Error::IOPatternViolation);

    Ok(())
}
