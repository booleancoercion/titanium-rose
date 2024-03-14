use crypto_bigint::{Encoding, Limb, Uint};

use self::twofish::{Key, KEY_BYTES};

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
        let bytes = int.resize::<{ KEY_BYTES / Limb::BYTES }>().to_be_bytes();
        Self(Key(bytes))
    }

    fn to_elgamal_int(&self) -> elgamal::Int {
        let int = Uint::<{ KEY_BYTES / Limb::BYTES }>::from_be_bytes(self.0 .0);
        int.resize()
    }
}
