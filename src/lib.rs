mod error;

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR, AffinePoint, ExtendedPoint, ExtendedNielsPoint, AffineNielsPoint, Fr};
use dusk_bls12_381::Scalar;
use subtle::ConstantTimeEq;
use crate::error::Error;
use rand::Rng;

pub struct SecretKey(Scalar);

pub struct PrivateKey(Fr);

impl PrivateKey {
    // This will create a new private key
    // from a scalar of the Field Fr.
    pub fn new() -> Result<PrivateKey, Error> {
        let scalar = Fr::random(&mut rand::thread_rng());
        if scalar.ct_eq(&Fr::zero()).unwrap_u8() == 1u8 {
            return Err(Error::InvalidParameters);
        }

        Ok(PrivateKey(scalar))
    }

    /// `to_public` returns the `PublicKey` of the `PrivateKey`.
    pub fn to_public(&self) -> PublicKey {
        let point = AffinePoint::from(GENERATOR_EXTENDED * &self.0);
        PublicKey(point)
    }
}


pub struct PublicKey(AffinePoint);

impl PublicKey {
    // This will create a new public key from a 
    // secret key
    pub fn from_secret(secret: &PrivateKey) -> PublicKey {
        let point = AffinePoint::from(GENERATOR_EXTENDED * secret.0);

        PublicKey(point)
    }

    pub fn new() -> Result<PublicKey, Error> {
        let sk = PrivateKey::new();
        let pk = PrivateKey::to_public(&sk.unwrap());
        Ok(pk)
    }
}

// pub struct KeyPair {
//     secret_key: PrivateKey,
//     public_key: PublicKey,
// }

pub struct Signature {
    R: AffinePoint,
    s: AffinePoint,
}

impl Signature {

    pub fn encrypt(pk: &PrivateKey, m: &Scalar) -> Self {
        let h_pk = sponge_hash(&[pk]);
        let r = sponge_hash(&[h_pk + m]);

        let R = r * GENERATOR;
        let h = sponge_hash(&[R.get_x(), R.get_y(), pk.get_x(), pk.get_y(), m]);
        let s = r + h * pk;

        Signature{R, s}
    }

    pub fn decrypt(&self, )
}