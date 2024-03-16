use rand_core::{OsRng, RngCore};

use super::sha256::{self, Digest, BLOCK_BYTES, DIGEST_BYTES};

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
#[derive(Clone)]
pub struct Key(pub(crate) Block);

pub const KEY_BYTES: usize = sha256::BLOCK_BYTES;

type Block = [u8; sha256::BLOCK_BYTES];
const OPAD: Block = [0x5c; sha256::BLOCK_BYTES];
const IPAD: Block = [0x36; sha256::BLOCK_BYTES];

pub fn hmac(key: &Key, message: &[u8]) -> Digest {
    let mut inner_input = Vec::with_capacity(BLOCK_BYTES + message.len());
    inner_input.extend_from_slice(&xor_block(&key.0, &IPAD));
    inner_input.extend_from_slice(message);
    let inner = sha256::hash(&inner_input);

    let mut outer_input = Vec::with_capacity(BLOCK_BYTES + DIGEST_BYTES);
    outer_input.extend_from_slice(&xor_block(&key.0, &OPAD));
    outer_input.extend_from_slice(&inner);
    sha256::hash(&outer_input)
}

fn xor_block(a: &Block, b: &Block) -> Block {
    let mut output = [0; sha256::BLOCK_BYTES];
    for i in 0..output.len() {
        output[i] = a[i] ^ b[i];
    }

    output
}

impl Key {
    pub fn generate() -> Self {
        let mut bytes = [0u8; BLOCK_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}
