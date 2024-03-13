pub mod elgamal;

pub struct SymmetricKey(());

impl SymmetricKey {
    fn generate() -> Self {
        todo!()
    }

    fn from_elgamal_int(int: &elgamal::Int) -> Self {
        todo!()
    }

    fn to_elgamal_int(&self) -> elgamal::Int {
        todo!()
    }
}
