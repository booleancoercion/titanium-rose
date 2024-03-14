use rand_core::{OsRng, RngCore};

pub const KEY_BYTES: usize = 256 / 8;
pub const BLOCK_BYTES: usize = 128 / 8;

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
#[derive(Clone)]
pub struct Key(pub(crate) [u8; KEY_BYTES]); // 256 bits
pub type Block = [u8; BLOCK_BYTES]; // 128 bits

impl Key {
    pub fn generate() -> Self {
        let mut data = [0u8; 32];
        OsRng.fill_bytes(&mut data);

        Self(data)
    }
}

pub fn encrypt_block(key: &Key, block: &Block) -> Block {
    todo!()
}
