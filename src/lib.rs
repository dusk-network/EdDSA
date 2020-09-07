// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”

mod error;

use dusk_jubjub::{GENERATOR_EXTENDED, AffinePoint, ExtendedPoint, Fr};
use dusk_bls12_381::Scalar;
use poseidon252::sponge::sponge::sponge_hash;
use poseidon252::perm_uses::fixed_hash::two_outputs;
use subtle::ConstantTimeEq;
use crate::error::Error;
use rand::{Rng, CryptoRng};
use std::io::{Read, Write};
use std::io;

#[derive(Default, Clone, Copy, Debug)]
pub struct Message(pub Scalar);

/// An EdDSA secret key, consisting of two JubJub scalars.
#[derive(Clone, Copy, Debug)]
pub struct SecretKey {
    p1: Fr,
    p2: Fr,
}

impl SecretKey {
    /// This will create a new [`SecretKey`] from a scalar 
    /// of the Field Fr.
    pub fn new<T>(rand: &mut T) -> SecretKey
    where 
        T: Rng + CryptoRng, 
    {
        let scalar = Fr::random(rand);
        

        let sk = two_outputs(scalar.into());

        let p1 = Fr::from_raw(*sk[0].reduce().internal_repr());
        let p2 = Fr::from_raw(*sk[1].reduce().internal_repr());

        SecretKey{
            p1,
            p2,
        }
    }

    /// Returns the [`PublicKey`] of the [`SecretKey`].
    pub fn to_public(&self) -> PublicKey {
        let point = AffinePoint::from(GENERATOR_EXTENDED * &self.p1);
        PublicKey(point)
    }

    /// Sign a [`Message`] with the [`SecretKey`], outputting a [`Signature`].
    #[allow(non_snake_case)]
    pub fn sign(&self, m: &Message) -> Signature {
        let pk = PublicKey::from_secret(self);

        let r = sponge_hash(&[self.p2.into(), m.0]);
        let r_j = Fr::from_raw(*r.reduce().internal_repr());

        let R = AffinePoint::from(GENERATOR_EXTENDED * r_j);

        let h = sponge_hash(&[R.get_x(), R.get_y(), pk.0.get_x(), pk.0.get_y(), m.0]);
        let h_j = Fr::from_raw(*h.reduce().internal_repr());
        let h_pk = h_j * self.p1;
        let s = h_pk + r_j;
        
        Signature{s, R}
    }
}

/// An EdDSA public key, internally represented by a point
/// on the JubJub curve.
#[derive(Clone, Copy, Debug)]
pub struct PublicKey(AffinePoint);

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        PublicKey::from_secret(sk)
    }
}

impl PublicKey {
    /// This will create a new [`PublicKey`] from a [`SecretKey`].
    pub fn from_secret(secret: &SecretKey) -> PublicKey {
        let point = AffinePoint::from(GENERATOR_EXTENDED * secret.p1);
        PublicKey(point)
    }

    /// This creates a new random [`PublicKey`].
    /// Note that this function does not return the [`SecretKey`]
    /// associated to this public key.
    pub fn new<T>(rand: &mut T) -> Result<PublicKey, Error>
    where 
        T: Rng + CryptoRng, 
    {
        let sk = SecretKey::new(rand);
        let pk = SecretKey::to_public(&sk);
        Ok(pk)
    }
}

/// A [`KeyPair`] contains both the [`SecretKey`] and the
/// associated [`PublicKey`].
#[derive(Clone, Copy, Debug)]
pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl From<SecretKey> for KeyPair {
    fn from(sk: SecretKey) -> Self {
        KeyPair::new_from_secret(sk)
    }
}


impl KeyPair {
    // This function generates a new KeyPair 
    // from a secret and private key 
    pub fn new<T>(rand: &mut T) -> Result<Self, Error> 
    where 
    T: Rng + CryptoRng, 
    {
        let sk = SecretKey::new(rand);
        let pk = SecretKey::to_public(&sk);
        
        Ok(KeyPair {
            secret_key: sk,
            public_key: pk,
        })
    }

    pub fn new_from_secret(sk: SecretKey) -> Self {
        let pk = SecretKey::to_public(&sk);
        
        KeyPair {
            secret_key: sk,
            public_key: pk,
        }
    }

    pub fn sign(&self, m: &Message) -> Signature {
        self.secret_key.sign(m)
    }
}

/// An EdDSA signature, produced by signing a [`Message`] with a
/// [`SecretKey`].
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    s: Fr,
    R: AffinePoint,
}

impl Signature {
    /// Verify the correctness of a [`Signature`], given a [`Message`]
    /// and a [`PublicKey`].
    pub fn verify(&self, m: &Message, pk: &PublicKey) -> Result<(), Error> {
        let h = sponge_hash(&[self.R.get_x(), self.R.get_y(), pk.0.get_y(), pk.0.get_x(), m.0]);
        let h_j = Fr::from_raw(*h.reduce().internal_repr());
        let p1 = GENERATOR_EXTENDED * self.s;
        let h_pk = AffinePoint::from(ExtendedPoint::from(pk.0) * h_j);
        let p2 = ExtendedPoint::from(self.R) + ExtendedPoint::from(h_pk);

        
        match p1.eq(&p2) {
            true => Ok(()),
            false => Err(Error::InvalidSignature),
        }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(&self.s.to_bytes());
        buf[32..].copy_from_slice(&self.R.to_bytes());

        buf
    }

    #[allow(non_snake_case)]
    pub fn from_bytes(buf: [u8; 64]) -> Result<Signature, Error> {
        let mut s_buf = [0u8; 32];
        s_buf.copy_from_slice(&buf[..32]);

        let mut R_buf = [0u8; 32];
        R_buf.copy_from_slice(&buf[32..]);

        let s = Fr::from_bytes(&s_buf);
        if s.is_none().unwrap_u8() == 1 {
            return Err(Error::InvalidData);
        }

        let R = AffinePoint::from_bytes(R_buf);
        if R.is_none().unwrap_u8() == 1 {
            return Err(Error::InvalidData);
        }  

        let sig = Signature {s: s.unwrap(), R: R.unwrap()};
        Ok(sig)
    }

}

impl Read for Signature {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;

        buf.chunks_mut(32)
            .next()
            .ok_or(Error::Generic)
            .map_err::<io::Error, _>(|e| e.into())?;
        n += 32;
        buf.copy_from_slice(&self.s.to_bytes());

        buf.chunks_mut(32)
            .next()
            .ok_or(Error::Generic)
            .map_err::<io::Error, _>(|e| e.into())?;
        n += 32;
        buf.copy_from_slice(&self.R.to_bytes());

        Ok(n)
    }
}

#[allow(non_snake_case)]
impl Write for Signature {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut n = 0;

        let s_buf = buf
            .chunks(32)
            .next()
            .ok_or(Error::Generic)
            .map_err::<io::Error, _>(|e| e.into())?;
        n += 32;
        let mut s_arr = [0u8; 32];
        s_arr.copy_from_slice(&s_buf);
        let s = Fr::from_bytes(&s_arr);
        if s.is_none().unwrap_u8() == 1 {
            return Err(Error::Generic.into());
        }

        let R_buf = buf
            .chunks(32)
            .next()
            .ok_or(Error::Generic)
            .map_err::<io::Error, _>(|e| e.into())?;
        n += 32;
        let mut R_arr = [0u8; 32];
        R_arr.copy_from_slice(&R_buf);
        let R = AffinePoint::from_bytes(R_arr);
        if R.is_none().unwrap_u8() == 1 {
            return Err(Error::Generic.into());
        }

        self.s = s.unwrap();
        self.R = R.unwrap();

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
