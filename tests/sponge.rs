// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_safe::{Call, Error, Safe, Sponge};
use zeroize::Zeroize;

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
fn failures_are_terminal() {
    for case in 0..9 {
        let mut sponge = Sponge::start(
            Rotate::new(),
            vec![Call::Absorb(2), Call::Squeeze(1)],
            0,
        )
        .unwrap();
        if case >= 5 {
            sponge.absorb(2, [BlsScalar::one(); 2]).unwrap();
        }
        if case >= 7 {
            sponge.squeeze(1).unwrap();
        }
        let error = match case {
            0 => sponge.squeeze(1),
            1 => sponge.absorb(1, [BlsScalar::one()]),
            2 => sponge.absorb(3, [BlsScalar::one(); 3]),
            3 => sponge.absorb(2, []),
            4 => sponge.absorb(2, [BlsScalar::one()]),
            5 | 7 => sponge.absorb(2, [BlsScalar::one(); 2]),
            _ => sponge.squeeze(2),
        };
        assert_eq!(
            error,
            Err(if matches!(case, 3 | 4) {
                Error::TooFewInputElements
            } else {
                Error::IOPatternViolation
            })
        );
        assert_eq!(
            sponge.absorb(2, [BlsScalar::one(); 2]),
            Err(Error::IOPatternViolation)
        );
        assert_eq!(sponge.squeeze(1), Err(Error::IOPatternViolation));
        assert_eq!(sponge.clone().finish(), Err(Error::IOPatternViolation));
        sponge.zeroize();
        assert_eq!(sponge.finish(), Err(Error::IOPatternViolation));
    }
}

#[test]
fn explicit_zeroization_is_terminal() {
    for progress in 0..3 {
        let mut sponge = Sponge::start(
            Rotate::new(),
            vec![Call::Absorb(1), Call::Squeeze(1)],
            0,
        )
        .unwrap();
        if progress >= 1 {
            sponge.absorb(1, [BlsScalar::one()]).unwrap();
        }
        if progress == 2 {
            sponge.squeeze(1).unwrap();
        }
        sponge.zeroize();
        assert_eq!(
            sponge.absorb(1, [BlsScalar::one()]),
            Err(Error::IOPatternViolation)
        );
        assert_eq!(sponge.squeeze(1), Err(Error::IOPatternViolation));
        assert_eq!(sponge.finish(), Err(Error::IOPatternViolation));
    }
}

#[test]
fn unsupported_widths_are_rejected() {
    // Mechanics-only backend; invalid widths must reject before invoking it.
    struct Minimal;
    impl<const N: usize> Safe<BlsScalar, N> for Minimal {
        fn tag(&mut self, _: &[u8]) -> BlsScalar {
            assert!(N >= 2);
            BlsScalar::zero()
        }
        fn add(&mut self, a: &BlsScalar, b: &BlsScalar) -> BlsScalar {
            a + b
        }
        fn permute(&mut self, _: &mut [BlsScalar; N]) {}
    }
    let pattern = vec![Call::Absorb(1), Call::Squeeze(1)];
    assert_eq!(
        Sponge::<_, BlsScalar, 0>::start(Minimal, pattern.clone(), 0)
            .unwrap_err(),
        Error::InvalidIOPattern
    );
    assert_eq!(
        Sponge::<_, BlsScalar, 1>::start(Minimal, pattern.clone(), 0)
            .unwrap_err(),
        Error::InvalidIOPattern
    );
    let mut sponge =
        Sponge::<_, BlsScalar, 2>::start(Minimal, pattern, 0).unwrap();
    sponge.absorb(1, [BlsScalar::one()]).unwrap();
    sponge.squeeze(1).unwrap();
    assert_eq!(sponge.finish().unwrap(), [BlsScalar::one()]);
}

#[test]
fn debug_is_redacted() {
    let mut sponge = Sponge::start(
        Rotate::new(),
        vec![Call::Absorb(1), Call::Squeeze(1)],
        0,
    )
    .unwrap();
    sponge.absorb(1, [BlsScalar::from(77665544)]).unwrap();
    sponge.squeeze(1).unwrap();
    assert_eq!(
        format!("{sponge:?}"),
        "Sponge { width: 7, io_count: 2, failed: false, .. }"
    );
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
