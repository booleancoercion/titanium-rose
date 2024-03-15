use crypto_bigint::subtle::{Choice, ConditionallySelectable};
use crypto_bigint::{CheckedSub, ConcatMixed, NonZero, RandomMod, U2048};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use super::SymmetricKey;

pub(crate) type Int = U2048;

const Q: Int = Int::from_be_hex("7f10d590db04c98b5b88dc544cf27fc758780dcd652763eafdffd0962153671e773bc4bed8214591be5fe640896f211a1a54457bdced391bfde8942f2a36904b8853bf65ecf849e75936bb9f37a972ff882bac35f632a24c31d2aba339e50b9aeb89bdd8db873fa3365907ca09042d3945f15c9f29c8df54cecbb2b98c0989ef315a32c2945c86fdec4f06374d337fbf4f81711c78233bcde92802a3064203c53094feeb8fc31cef66af51ef1d50ff2ad6c89afd7d7781e549eedeebd3afa8cba28eeee98cbb156ddbb9e30eb5227f5e7ac86c8a26301bca3ec15d9ba1e71f638227f00bcc7aa4323dafbb1b64ded53c20a9127be8cc5dfa80c10483dbde0ead").resize();
const NONZERO_Q: NonZero<Int> = NonZero::from_uint(Q);
const P: Int = Q.shl(1).saturating_add(&Int::ONE); // there is no overflow
const BIG_P: <Int as ConcatMixed<Int>>::MixedOutput = P.resize();

const G: Int = Int::from_be_hex("5A98F52C5D61C4047A68A9A2CA5D3CA087640121DE5FB00D1E92D660C3DB2F0B76FEB1D37679EF9215541986D9248AA2A2F876F2E66A48FB8C1C4948B0A259D8F3D75AC7AB352FE54A30E5889C56FAD6005B037F2B96437154A44DA609CCF975385350355E91F0D9223718376E0AC7FF858AA50608A21344CCEBCCE5707F2E32ECD6FAEEB54CB45C8A7EFD7C7DF16A76C947AC44371F33A54B03636AB30915A43F3697E100D6329BFF860B4EA7F5C54EAE0C79A1AF573085070ED243335DD523BB21653039F0A98DB73E7B17F98936FBE8DBDA998267C03586E669B83308E4183B877CE314B57A4E590795BECBFA94E69CC5D75981E66DF5D2F65ECB4A528D9C").resize();

// uniformly generates some x such that 1 <= x <= q - 1
fn generate_exponent() -> Int {
    loop {
        let x = Int::random_mod(&mut OsRng, &NONZERO_Q);
        if x != Int::ZERO {
            return x;
        }
    }
}

// calculates lhs * rhs (mod p)
fn mul(lhs: &Int, rhs: &Int) -> Int {
    let mul = lhs.mul(rhs);
    let rem = mul.wrapping_rem(&BIG_P);
    rem.resize()
}

// calculates base^exp (mod p)
fn pow(base: &Int, exp: &Int) -> Int {
    // this implementation uses iterated squaring.
    let mut result = Int::ONE;
    let mut a = *base;

    // iterating like this to remain constant-time
    // using SmallInt becase all of our numbers fit there, but we use Int for convenience
    for i in 0..Int::BITS {
        let multiplied = mul(&result, &a);
        let bit: Choice = exp.bit(i).into();
        result.conditional_assign(&multiplied, bit);

        a = mul(&a, &a);
    }

    result
}

// calculates base^(-exp) (mod p)
fn inv_pow(base: &Int, exp: &Int) -> Int {
    pow(base, &Q.checked_sub(exp).unwrap())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AlicePub(Int);

#[derive(Clone)]
pub struct Alice {
    secret: Int,
    public: AlicePub,
}

#[derive(Serialize, Deserialize)]
pub struct BobEphemeral(Int, Int);

#[derive(Clone)]
pub struct Bob {
    secret: SymmetricKey,
}

impl Alice {
    pub fn generate() -> Self {
        let secret = generate_exponent();
        let public = AlicePub(pow(&G, &secret));

        Self { secret, public }
    }

    pub fn get_public(&self) -> &AlicePub {
        &self.public
    }

    pub fn extract_shared_secret(&self, eph: BobEphemeral) -> SymmetricKey {
        let BobEphemeral(public, enc) = eph; // g^b, A^b * m
        let inv_key = inv_pow(&public, &self.secret); // (g^b)^-a
        let plaintext = mul(&enc, &inv_key);

        SymmetricKey::from_elgamal_int(&plaintext)
    }
}

impl Bob {
    pub fn generate() -> Self {
        Self {
            secret: SymmetricKey::generate(),
        }
    }

    pub fn encrypt_for_alice(&self, pk: &AlicePub) -> BobEphemeral {
        let exponent = generate_exponent();

        let public = pow(&G, &exponent);

        let AlicePub(alice) = &pk;
        let key = pow(alice, &exponent);
        let secret = self.secret.to_elgamal_int();
        let ciphertext = mul(&key, &secret);
        BobEphemeral(public, ciphertext)
    }

    pub fn extract_shared_secret(&self) -> SymmetricKey {
        self.secret.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let alice = Alice::generate();
        let bob = Bob::generate();

        let eph = bob.encrypt_for_alice(&alice.public);
        let shared_alice = alice.extract_shared_secret(eph);
        let shared_bob = bob.extract_shared_secret();

        assert_eq!(shared_alice, shared_bob)
    }
}
