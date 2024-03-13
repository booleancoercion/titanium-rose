use crypto_bigint::subtle::{Choice, ConditionallySelectable};
use crypto_bigint::{CheckedMul, CheckedSub, NonZero, RandomMod, U2048, U4096};
use rand_core::OsRng;

use super::SymmetricKey;

type SmallInt = U2048;
pub(crate) type Int = U4096;

const Q: Int = SmallInt::from_be_hex("7f10d590db04c98b5b88dc544cf27fc758780dcd652763eafdffd0962153671e773bc4bed8214591be5fe640896f211a1a54457bdced391bfde8942f2a36904b8853bf65ecf849e75936bb9f37a972ff882bac35f632a24c31d2aba339e50b9aeb89bdd8db873fa3365907ca09042d3945f15c9f29c8df54cecbb2b98c0989ef315a32c2945c86fdec4f06374d337fbf4f81711c78233bcde92802a3064203c53094feeb8fc31cef66af51ef1d50ff2ad6c89afd7d7781e549eedeebd3afa8cba28eeee98cbb156ddbb9e30eb5227f5e7ac86c8a26301bca3ec15d9ba1e71f638227f00bcc7aa4323dafbb1b64ded53c20a9127be8cc5dfa80c10483dbde0ead").resize();
const NONZERO_Q: NonZero<Int> = NonZero::from_uint(Q);
const P: Int = Q.shl(1).saturating_add(&Int::ONE); // there is no overflow

const G: Int = SmallInt::from_be_hex("74b6b788b52a14aaac9523692c19efc78b563a67d7bbeeb8faf38a56f5c8512afec40da8fbd65272de0a702288c43b706334c1542bed41c10fa709176cca565cec0f3b12ede38ff85150a548bbf571a574b829f2b065e12c7e4b6faaae595bf826c0db6371d075a61beaa96a014c8a8a277f57acaf1179f5af6c9de3832b6eeec9132e6b8bbd131d58d8c65c27fbe9878e8beb9cc2b8efb63eed99914979ad84dd3b2168a11e2c0f7db5a0495fbbb93eb84ac97ec714b80d77e2b9d43863de47098a843a1d7dae39884bb1091aeea5b9a900ebc445325ff532f472dccc5ae5d20a87cb8401b8cd10295b166905edb6170371b87135f30611c35ed104f8e858d1").resize();

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
    // cannot overflow
    let mul = lhs.checked_mul(rhs).unwrap();

    mul.wrapping_rem(&P)
}

// calculates base^exp (mod p)
fn pow(base: &Int, exp: &Int) -> Int {
    // this implementation uses iterated squaring.
    let mut result = Int::ONE;
    let mut a = *base;

    // iterating like this to remain constant-time
    // using SmallInt becase all of our numbers fit there, but we use Int for convenience
    for i in 0..SmallInt::BITS {
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

pub struct AlicePub(Int);

pub struct Alice {
    secret: Int,
    public: AlicePub,
}

pub struct BobEphemeral(Int, Int);

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

    pub fn extract_shared_secret(self, eph: BobEphemeral) -> SymmetricKey {
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

    pub fn extract_shared_secret(self) -> SymmetricKey {
        self.secret
    }
}
