pub const DIGEST_BYTES: usize = 256 / 8;
pub type Digest = [u8; DIGEST_BYTES];

pub fn hash(data: &[u8]) -> Digest {
    let padded = pad(data);
    let parsed = parse_blocks(&padded);

    let mut hash = START_HASH;
    for block in parsed {
        hash_round(block, &mut hash);
    }

    bytemuck::must_cast(hash.map(Word::to_be_bytes))
}

fn hash_round(block: Block, hash: &mut [Word; 8]) {
    let mut schedule: [Word; 64] = [0; 64];

    schedule[..16].copy_from_slice(&block);
    for t in 16..64 {
        schedule[t] = s1(schedule[t - 2])
            .wrapping_add(schedule[t - 7])
            .wrapping_add(s0(schedule[t - 15]))
            .wrapping_add(schedule[t - 16]);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *hash;
    for t in 0..64 {
        let temp1 = h
            .wrapping_add(bs1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(schedule[t]);
        let temp2 = bs0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    hash[0] = hash[0].wrapping_add(a);
    hash[1] = hash[1].wrapping_add(b);
    hash[2] = hash[2].wrapping_add(c);
    hash[3] = hash[3].wrapping_add(d);
    hash[4] = hash[4].wrapping_add(e);
    hash[5] = hash[5].wrapping_add(f);
    hash[6] = hash[6].wrapping_add(g);
    hash[7] = hash[7].wrapping_add(h);
}

type Word = u32;
type Block = [Word; BLOCK_WORDS];

pub const BLOCK_BYTES: usize = 512 / 8;
const BLOCK_WORDS: usize = 512 / 32;
const WORD_BYTES: usize = 32 / 8;

const START_HASH: [Word; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [Word; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn pad(data: &[u8]) -> Vec<u8> {
    let last_block_len = data.len() % BLOCK_BYTES;

    let k = (512 + 448 - last_block_len * 8 - 1) % 512;
    debug_assert_eq!((k + 1) % 8, 0);
    debug_assert!((k + 1) / 8 > 0);
    let zero_bytes_to_add = (k + 1) / 8 - 1;

    let mut output = data.to_owned();
    output.push(0b10000000);
    output.extend(std::iter::repeat(0u8).take(zero_bytes_to_add));
    output.extend_from_slice(&((data.len() * 8) as u64).to_be_bytes());

    debug_assert_eq!((output.len() * 8) % 512, 0);

    output
}

fn parse_blocks(data: &[u8]) -> Vec<Block> {
    assert_eq!(data.len() % BLOCK_BYTES, 0);

    let num_blocks = data.len() / BLOCK_BYTES;
    let mut output = Vec::with_capacity(num_blocks);

    for b in 0..num_blocks {
        let mut block = [0; BLOCK_WORDS];
        for (w, word) in block.iter_mut().enumerate() {
            let offset = b * BLOCK_BYTES + w * WORD_BYTES;
            let bytes: [u8; WORD_BYTES] = data[offset..offset + WORD_BYTES].try_into().unwrap();
            *word = Word::from_be_bytes(bytes);
        }
        output.push(block);
    }

    output
}

fn ch(x: Word, y: Word, z: Word) -> Word {
    (x & y) ^ (!x & z)
}

fn maj(x: Word, y: Word, z: Word) -> Word {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bs0(x: Word) -> Word {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn bs1(x: Word) -> Word {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn s0(x: Word) -> Word {
    x.rotate_right(7) ^ x.rotate_right(18) ^ x.wrapping_shr(3)
}

fn s1(x: Word) -> Word {
    x.rotate_right(17) ^ x.rotate_right(19) ^ x.wrapping_shr(10)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn pad_works() {
        let data = b"abc";
        let padded = pad(data);
        assert_eq!(
            &padded,
            &[
                b'a', b'b', b'c', 0b10000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24
            ]
        )
    }

    #[test]
    fn equals_real_sha() {
        let data = b"abc";
        let my_hash = hash(data);
        let official_hash = Sha256::digest(data);
        assert_eq!(&my_hash, &*official_hash);
    }
}
