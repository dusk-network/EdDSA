mod error;

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR, AffinePoint, ExtendedPoint, ExtendedNielsPoint, AffineNielsPoint, Fr};
use dusk_bls12_381::Scalar;
use poseidon252::sponge::sponge::sponge_hash;
use subtle::ConstantTimeEq;
use crate::error::Error;
use rand::{CryptoRng, Rng};

pub struct Message(Scalar);


pub struct SecretKey(Fr);

impl SecretKey {
    // This will create a new private key
    // from a scalar of the Field Fr.
    pub fn new() -> Result<SecretKey, Error> {
        let scalar = Fr::random(&mut rand::thread_rng());
        if scalar.ct_eq(&Fr::zero()).unwrap_u8() == 1u8 {
            return Err(Error::InvalidParameters);
        }

        Ok(SecretKey(scalar))
    }

    /// `to_public` returns the `PublicKey` of the `SecretKey`.
    pub fn to_public(&self) -> PublicKey {
        let point = AffinePoint::from(GENERATOR_EXTENDED * &self.0);
        PublicKey(point)
    }
}


pub struct PublicKey(AffinePoint);

impl PublicKey {
    // This will create a new public key from a 
    // secret key
    pub fn from_secret(secret: &SecretKey) -> PublicKey {
        let point = AffinePoint::from(GENERATOR_EXTENDED * secret.0);

        PublicKey(point)
    }

    // pub fn from_hash([u8: 32]) -> PublicKey {
    //     let point = AffinePoint::from(GENERATOR_EXTENDED * self);

    //     PublicKey(point)
    // } 


    pub fn new() -> Result<PublicKey, Error> {
        let sk = SecretKey::new();
        let pk = SecretKey::to_public(&sk.unwrap());
        Ok(pk)
    }
}

// pub struct KeyPair {
//     sk_hash: [u8; 32],
//     public_key: PublicKey,
// }

// impl KeyPair {
    
//     pub fn new(SecretKey) -> KeyPair {
//         let scalar = Fr::random(&mut rand::thread_rng());
//         if scalar.ct_eq(&Fr::zero()).unwrap_u8() == 1u8 {
//             return Err(Error::InvalidParameters);
//         }
    
//         let s = sponge_hash(&[scalar.into()]);
//         let s_h = Fr::from_raw(*s.reduce().internal_repr());
//         let point = PublicKey::from_hash(s_h);

//         Ok(KeyPair.public_key(point))
//         Ok(KeyPair.sk_hash(s_h))
//     }
// }



pub struct Signature {
    R_b: [u8; 32],
    s: Fr,
    R: AffinePoint,
}

impl Signature {

    pub fn sign(sk: &SecretKey, m: &Message) -> Self {

        let pk = PublicKey::from_secret(sk);

        let h_sk = sponge_hash(&[sk.0.into()]);
        let r = sponge_hash(&[h_sk + m.0]);
        let r_j = Fr::from_raw(*r.reduce().internal_repr());

        let R = AffinePoint::from(GENERATOR_EXTENDED * r_j);
        let R_b = AffinePoint::from(GENERATOR_EXTENDED * r_j).to_bytes();

        let h = sponge_hash(&[R.get_x(), R.get_y(), pk.0.get_x(), pk.0.get_y(), m.0]);
        let h_j = Fr::from_raw(*h.reduce().internal_repr());
        let h_pk = h_j * sk.0;
        let s = h_pk + r_j;
        

        Signature{R_b, s, R}
    }

    pub fn verify(&self, m: &Message, pk: &PublicKey) -> bool {

        
        let h = sponge_hash(&[self.R.get_x(), self.R.get_y(), pk.0.get_y(), pk.0.get_x(), m.0]);
        let h_j = Fr::from_raw(*h.reduce().internal_repr());
        let p1 = GENERATOR_EXTENDED * self.s;
        let h_pk = AffinePoint::from(ExtendedPoint::from(pk.0) * h_j);
        let p2 = ExtendedPoint::from(self.R) + ExtendedPoint::from(h_pk);

        p1.eq(&p2)
    }
}

#[cfg(test)]
mod integrations {
    use super::*;
    use rand::Rng;

    #[test]
    fn sign_verify() {  // TestSignVerify
        let secret = SecretKey::new().unwrap();
        let mut rng = rand::thread_rng();

        let message = Message(Scalar::random(&mut rng));
    

        let a = Signature::sign(&secret, &message);
        let b = a.verify(&message, &PublicKey::from_secret(&secret));

        assert!(b);
    }
}
