use crypto_bigint::{Encoding, Limb, Uint};
use rand_core::{OsRng, RngCore};

use self::hmac::hmac;

pub mod elgamal;
pub mod hmac;
pub mod sha256;
pub mod twofish;

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
#[derive(Clone)]
pub struct SymmetricKey(twofish::Key, hmac::Key);

impl SymmetricKey {
    #[cfg(debug_assertions)]
    pub fn generate() -> Self {
        Self(twofish::Key::generate(), hmac::Key::generate())
    }

    #[cfg(not(debug_assertions))]
    fn generate() -> Self {
        Self(twofish::Key::generate(), hmac::Key::generate())
    }

    fn from_elgamal_int(int: &elgamal::Int) -> Self {
        let bytes = int
            .resize::<{ (twofish::KEY_BYTES + hmac::KEY_BYTES) / Limb::BYTES }>()
            .to_be_bytes();
        let twofish_bytes: [u8; twofish::KEY_BYTES] =
            bytes[..twofish::KEY_BYTES].try_into().unwrap();
        let hmac_bytes: [u8; hmac::KEY_BYTES] = bytes[twofish::KEY_BYTES..].try_into().unwrap();
        Self(twofish::Key(twofish_bytes), hmac::Key(hmac_bytes))
    }

    fn to_elgamal_int(&self) -> elgamal::Int {
        let mut bytes = Vec::with_capacity(twofish::KEY_BYTES + hmac::KEY_BYTES);
        bytes.extend_from_slice(&self.0 .0);
        bytes.extend_from_slice(&self.1 .0);
        let int = Uint::<{ (twofish::KEY_BYTES + hmac::KEY_BYTES) / Limb::BYTES }>::from_be_bytes(
            bytes.try_into().unwrap(),
        );
        int.resize()
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let iv = {
            let mut iv = [0u8; twofish::BLOCK_BYTES];
            OsRng.fill_bytes(&mut iv);
            iv
        };

        let padded = pad(data);
        let blocks = bytemuck::cast_slice::<_, twofish::Block>(&padded);

        let mut ciphertext = Vec::with_capacity(blocks.len() * twofish::BLOCK_BYTES);
        let mut xorrer = iv;
        for block in blocks {
            let xored = xor_block(block, &xorrer);
            xorrer = twofish::encrypt_block(&self.0, &xored);
            ciphertext.extend_from_slice(&xorrer);
        }

        let mut to_mac = Vec::with_capacity(iv.len() + ciphertext.len());
        to_mac.extend_from_slice(&iv);
        to_mac.extend_from_slice(&ciphertext);
        let mac = hmac(&self.1, &to_mac);

        CompleteCiphertext {
            ciphertext,
            iv,
            mac,
        }
        .serialize()
    }

    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        let CompleteCiphertext {
            ciphertext,
            iv,
            mac,
        } = CompleteCiphertext::deserialize(data)?;

        let calculated_mac = hmac(&self.1, &data[sha256::DIGEST_BYTES..]);
        if mac != calculated_mac {
            return None;
        }
        let Ok(blocks) = bytemuck::try_cast_slice::<_, twofish::Block>(&ciphertext) else {
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

fn xor_block(a: &twofish::Block, b: &twofish::Block) -> twofish::Block {
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

struct CompleteCiphertext {
    ciphertext: Vec<u8>,
    iv: twofish::Block,
    mac: sha256::Digest,
}

impl CompleteCiphertext {
    pub fn serialize(self) -> Vec<u8> {
        let Self {
            ciphertext,
            iv,
            mac,
        } = self;
        let mut output = Vec::with_capacity(mac.len() + iv.len() + ciphertext.len());

        output.extend_from_slice(&mac);
        output.extend_from_slice(&iv);
        output.extend_from_slice(&ciphertext);

        output
    }

    pub fn deserialize(mut data: &[u8]) -> Option<Self> {
        let mac: sha256::Digest = data[0..sha256::DIGEST_BYTES].try_into().ok()?;
        data = &data[sha256::DIGEST_BYTES..];

        let iv: twofish::Block = data[0..twofish::BLOCK_BYTES].try_into().ok()?;
        data = &data[twofish::BLOCK_BYTES..];

        let ciphertext = data.to_owned();

        Some(Self {
            ciphertext,
            iv,
            mac,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_decryption_symmetric() {
        let skey = SymmetricKey::generate();
        let data = b"Hello, World!";

        let encrypted = skey.encrypt(data);
        let decrypted = skey.decrypt(&encrypted).unwrap();

        assert_eq!(data, &*decrypted)
    }

    #[test]
    fn iv_tamper() {
        let skey = SymmetricKey::generate();
        let data = b"Hello, World!";

        let mut encrypted = skey.encrypt(data);
        let mut ciphertext = CompleteCiphertext::deserialize(&encrypted).unwrap();
        ciphertext.iv[0] ^= 42;
        encrypted = ciphertext.serialize();

        let decrypted = skey.decrypt(&encrypted);
        assert!(decrypted.is_none());
    }
}
