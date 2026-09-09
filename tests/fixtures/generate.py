#!/usr/bin/env python3
"""Independent SAFE AE vectors for tests/encryption.rs's mechanics backend.

Python integer arithmetic and hashlib only; no Rust implementation is called.
This models the existing hash-expanded fixture, NOT a cryptographic permutation.
Key = [7, 8], nonce = 9, domain = 2^31, message = [1, ..., n].
Run without arguments to check frozen bytes; --write explicitly regenerates them.
"""
import argparse
import hashlib
from pathlib import Path
import struct

Q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
RATE = 6


def field_hash(data):
    return int.from_bytes(hashlib.blake2b(data).digest(), 'little') % Q


def permute(state):
    data = b''.join(x.to_bytes(32, 'little') for x in state)
    return [field_hash(data + bytes([i])) for i in range(RATE + 1)]


def encrypt(n):
    # A(2), A(1), S(n), A(n), S(1) has the canonical runs A(3),S(n),A(n),S(1).
    tag_bytes = struct.pack('>IIIIQ', 0x80000003, n, 0x80000000 | n, 1, 1 << 31)
    state = [field_hash(tag_bytes)] + [0] * RATE
    absorb_pos, squeeze_pos = 0, RATE

    def absorb(values):
        nonlocal absorb_pos, squeeze_pos
        while values:
            if absorb_pos == RATE:
                state[:] = permute(state)
                absorb_pos = 0
            count = min(RATE - absorb_pos, len(values))
            for i in range(count):
                index = 1 + absorb_pos + i
                state[index] = (state[index] + values[i]) % Q
            values = values[count:]
            absorb_pos += count
        squeeze_pos = RATE

    def squeeze(count):
        nonlocal absorb_pos, squeeze_pos
        output = []
        while count:
            if squeeze_pos == RATE:
                state[:] = permute(state)
                squeeze_pos = 0
            take = min(RATE - squeeze_pos, count)
            output.extend(state[1 + squeeze_pos:1 + squeeze_pos + take])
            squeeze_pos += take
            count -= take
        absorb_pos = 0
        return output

    absorb([7, 8, 9])
    masks = squeeze(n)
    message = list(range(1, n + 1))
    absorb(message)
    return [(m + mask) % Q for m, mask in zip(message, masks)] + squeeze(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    content = '# Python stdlib reference; see generate.py for parameters/provenance.\n'
    for n in [1, 6, 7, 13]:
        content += f'{n} ' + b''.join(x.to_bytes(32, 'little') for x in encrypt(n)).hex() + '\n'
    path = Path(__file__).with_name('encryption.txt')
    if args.write:
        path.write_text(content)
    else:
        assert path.read_text() == content, 'frozen vectors differ from the independent model'
        print('four independent AE vectors match')
