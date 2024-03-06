# SAFE - Sponge API for Field Elements

A generic API for sponge functions.

This is a minimal, `no_std`, pure Rust implementation of a sponge function, based on [SAFE](https://eprint.iacr.org/2023/522.pdf) (Sponge API for Field Elements), to be used in permutation-based symmetric primitives' design, such as hash functions, MACs, authenticated encryption schemes, PRNGs, and other.
The sponge is designed to be usable in zero-knowledge proving systems (ZKPs) as well as natively, operating on any type implementing the `Default` and `Copy` trait with a size of minimal 32 bytes.

## Introduction

Sponge functions are the basis of permutation-based symmetric primitives’ design. They can be seen as a stateful object that can ingest input (“absorb”) and produce output (“squeeze”) at any time and in arbitrary order.

As its main features, this sponge API:
- Does not use any padding, thus not wasting an extra call to the sponge permutation in any circumstances
- Is independent of an underlying permutation and thus can be used with almost every design on the market (including Poseidon’s).
- Eliminates a number of misuse patterns by limiting the set of operations callable at sponge and by binding a protocol designer to a specific order of these operations.
- Is provably secure in the random permutation model in a number of settings, including the overlooked but frequently required cross-protocol security.
- Is among the first constructions to store the protocol’s metadata in the sponge inner part, provably losing no security

This sponge construction in itself does not support variable-length hashing, i.e. hashing where the length of data hashed is unknown in advance.
However, this behavior can be achieved by wrapping the sponge in a hasher, that only starts the sponge upon finalizing the hash, thus at a time when the length of the input is known (example implementation of this wrapper can be found in [`dusk-poseidon`](https://github.com/dusk-network/Poseidon252)).

## Construction

The sponge constructed in this library is defined by:
- a state `[T; W]` with type `T: Default + Copy` and width `W`
- a permutation function that permutes the state
- a capacity of `1`
- a rate `R` with `R = W - 1`
- an input-output (IO) pattern that defines the sequence to ingest `len` items of input (`absorb(len)`) and pruduce output (`squeeze(len)`) (eg. `[absorb(4), absorb(1), squeeze(3)]`)
- a domain separator to distinguish between equivalent sponges with different usecases.

Note: With the capacity beeing one element of type `T` we need to restrict `T` to be at least 256 bits. It is the responsibility of the user to properly serialize input of different sizes into a type with at least 256 bits.

## Abstract API

### `start`

1. Verify IO pattern:
   - IO pattern has at least two calls.
   - First call is to `absorb`.
   - Last call is to `squeeze`.
   - No call has a `len == 0`.
2. Compute the tag using the IO pattern and a domain separator.
   1. Encode the IO pattern as a list of 32-bit words whose MSB is set to 1 for `absorb` and to 0 for `squeeze`, and the length is added to the lower bits. Any contiguous calls to `absorb` and `squeeze` will be aggregated, e.g. the above example of an IO pattern of `[absorb(4), absorb(1), squeeze(3)]` will have the same encoding as `[absorb(5), squeeze(3)]`: `[0x8000_0005, 0x0000_0001]`.
   2. Serialize the list of words into a byte string and append to it the domain separator: e.g. if the domain separator encoding is set to the two-byte sequence `0x4142`, then the example above would yield the string (with big-endian convention): `0x80000005000000014142`.
   3. Hash the byte string into the tag, an element of type `T`.
3. Initialize first element of the state to the tag and set the remaining elements to the default value of `T`.
4. Set both absorb and squeeze positions to zero.
5. Set the IO count to zero.

### `finish`

1. If the IO count is equal to the length of the IO pattern, return the output vector, if not return an error.
2. Erase the state and its variables

### `absorb(len, input)`

1. Check that the call to absorb matches the entry of in the IO pattern at the IO count, and check that the input yields sufficient elements (erase state and return error if not).
2. For the first `len` elements of `input`:
   1. Call the permutation function if `pos_absorb == rate` and set `pos_absorb = 0`.
   2. Add the element to the state at `pos_absort + 1` (we skip the first element which is the capacity).
   3. Increment `pos_absorb` by one.
3. Increment the IO count.
4. Set the `pos_squeeze` to the rate to force a call to the permutation function at the start of the next call to `squeeze`.

### `squeeze(len)`

1. Check that the call to absorb matches the entry of in the IO pattern at the IO count (erase state and return error if not).
2. `len` times:
   1. Call the permutation function if `pos_squeeze == rate` and set `pos_squeeze = 0`
   2. Append the element of the state at position `pos_squeeze + 1` (also here we skip the first element due to the capacity) to the output vector.
3. Increment the IO count.

*Note that we do not set the `pos_absorb` to the rate as we do with the `pos_squeeze` in the call to `absorb`, this is because we may want the state to absorb at the same positions that have been squeezed.*

## Example

```rust
use dusk_bls12_381::BlsScalar;
use ff::Field;
use rand::rngs::StdRng;
use rand::SeedableRng;
use dusk_safe::{Error, Call, Safe, Sponge};

const W: usize = 7;

#[derive(Default, Debug, Clone, Copy, PartialEq)]
struct Rotate();

impl Safe<BlsScalar, W> for Rotate {
    // Rotate every item one item to the left, first item becomes last.
    // Note: This permutation is just an example and *should not* be used for a
    // sponge construction for cryptographically safe hash functions.
    fn permute(&mut self, state: &mut [BlsScalar; W]) {
        let tmp = state[0];
        for i in 1..W {
            state[i - 1] = state[i];
        }
        state[W - 1] = tmp;
    }

    // Define the hasher used to generate the tag from the encoding of the
    // io-pattern and domain-separator.
    fn tag(&mut self, input: &[u8]) -> BlsScalar {
        BlsScalar::hash_to_scalar(input)
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

// pick a domain-separator
let domain_sep = 0;

// generate random input
let mut rng = StdRng::seed_from_u64(0x42424242);
let mut input = [BlsScalar::zero(); 8];
input.iter_mut().for_each(|s| *s = BlsScalar::random(&mut rng));

// build the io-pattern
let iopattern = vec![
    Call::Absorb(6),
    Call::Absorb(2),
    Call::Squeeze(1),
    Call::Squeeze(2),
];

// start the sponge
let mut sponge = Sponge::start(
    Rotate::new(),
    iopattern,
    domain_sep,
)
.expect("io-pattern should be valid");

// absorb 6 elements
sponge.absorb(6, &input).expect("absorbing should not fail");
// absorb 2 elements
sponge.absorb(2, &input[6..]).expect("absorbing should not fail");

// squeeze 1 element
sponge.squeeze(1).expect("squeezing should not fail");
// squeeze 2 elements
sponge.squeeze(2).expect("squeezing should not fail");

// generate the hash output
let output1 = sponge.finish().expect("Finishing should not fail");


// Generate another hash output from the same input and aggregated IO pattern:
// build the io-pattern
let iopattern = vec![
    Call::Absorb(8),
    Call::Squeeze(3),
];

// start the sponge
let mut sponge = Sponge::start(
    Rotate::new(),
    iopattern,
    domain_sep,
)
.expect("io-pattern should be valid");

// absorb 8 elements
sponge.absorb(8, &input).expect("absorbing should not fail");

// squeeze 3 elements
sponge.squeeze(3).expect("squeezing should not fail");

// generate the hash output
let output2 = sponge.finish().expect("Finishing should not fail");

assert_eq!(output1, output2);
```
