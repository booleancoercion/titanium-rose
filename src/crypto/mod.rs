use rand_core::{OsRng, RngCore};

pub mod elgamal;

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
#[derive(Clone)]
pub struct SymmetricKey(u32); // change this!!

impl SymmetricKey {
    fn generate() -> Self {
        Self(OsRng.next_u32())
    }

    fn from_elgamal_int(int: &elgamal::Int) -> Self {
        Self(int.as_words()[0] as u32)
    }

    fn to_elgamal_int(&self) -> elgamal::Int {
        elgamal::Int::from_u32(self.0)
    }
}
