use crypto_bigint::{Encoding, Limb, Uint};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use self::twofish::{Block, Key};

pub mod elgamal;
pub mod twofish;

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
#[derive(Clone)]
pub struct SymmetricKey(Key);

impl SymmetricKey {
    fn generate() -> Self {
        Self(Key::generate())
    }

    fn from_elgamal_int(int: &elgamal::Int) -> Self {
        let bytes = int
            .resize::<{ twofish::KEY_BYTES / Limb::BYTES }>()
            .to_be_bytes();
        Self(Key(bytes))
    }

    fn to_elgamal_int(&self) -> elgamal::Int {
        let int = Uint::<{ twofish::KEY_BYTES / Limb::BYTES }>::from_be_bytes(self.0 .0);
        int.resize()
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let iv = {
            let mut iv = [0u8; twofish::BLOCK_BYTES];
            OsRng.fill_bytes(&mut iv);
            iv
        };

        let padded = pad(data);
        let blocks = bytemuck::cast_slice::<_, Block>(&padded);

        let mut ciphertext = Vec::with_capacity(blocks.len() * twofish::BLOCK_BYTES);
        let mut xorrer = iv;
        for block in blocks {
            let xored = xor_block(block, &xorrer);
            xorrer = twofish::encrypt_block(&self.0, &xored);
            ciphertext.extend_from_slice(&xorrer);
        }

        let ciphertext = CompleteCiphertext { ciphertext, iv };
        bincode::serialize(&ciphertext).unwrap()
    }

    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        let Ok(CompleteCiphertext { ciphertext, iv }) = bincode::deserialize(data) else {
            return None;
        };
        let Ok(blocks) = bytemuck::try_cast_slice::<_, Block>(&ciphertext) else {
            return None;
        };

        let mut plaintext = Vec::with_capacity(blocks.len() * twofish::BLOCK_BYTES);
        let mut xorrer = iv;
        for block in blocks {
            let decrypted = twofish::decrypt_block(&self.0, block);
            let xored = xor_block(&decrypted, &xorrer);
            xorrer = *block;
            plaintext.extend_from_slice(&xored);
        }

        if !remove_padding(&mut plaintext) {
            return None;
        }

        Some(plaintext)
    }
}

fn xor_block(a: &Block, b: &Block) -> Block {
    let mut output = [0u8; twofish::BLOCK_BYTES];
    for i in 0..twofish::BLOCK_BYTES {
        output[i] = a[i] ^ b[i];
    }

    output
}

// PKCS#7
fn pad(data: &[u8]) -> Vec<u8> {
    let last_block_len = data.len() % twofish::BLOCK_BYTES;
    let to_add = twofish::BLOCK_BYTES - last_block_len;

    let mut output = Vec::with_capacity(data.len() + to_add);
    output.extend_from_slice(data);
    output.extend(std::iter::repeat(to_add as u8).take(to_add));

    output
}

// return true iff the padding is correct
fn remove_padding(data: &mut Vec<u8>) -> bool {
    let Some(&last) = data.last() else {
        return false;
    };

    if data.len() < last as usize {
        return false;
    }

    if data.iter().rev().take(last as usize).any(|&x| x != last) {
        return false;
    }

    data.truncate(data.len() - (last as usize));
    true
}

#[derive(Serialize, Deserialize)]
struct CompleteCiphertext {
    ciphertext: Vec<u8>,
    iv: Block,
}
