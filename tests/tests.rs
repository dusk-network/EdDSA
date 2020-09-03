// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”

use eddsa::{Message, KeyPair, PublicKey};
use dusk_bls12_381::Scalar;

#[cfg(test)]
mod integrations {
    use super::*;
    
    #[test]
    // TestSignVerify
    fn sign_verify() {  
        let keypair = KeyPair::new(&mut rand::thread_rng()).unwrap();
        let mut rng = rand::thread_rng();

        let message = Message(Scalar::random(&mut rng));
    
        let a = keypair.sign(&message);
        let b = a.verify(&message, &keypair.public_key);

        assert!(b);
    }

    #[test]
    // Test to see failure with wrong Public Key
    fn test_wrong_keys() {
        let keypair = KeyPair::new(&mut rand::thread_rng()).unwrap();
        let mut rng = rand::thread_rng();

        let message = Message(Scalar::random(&mut rng));
    
        let a = keypair.sign(&message);
        let b = a.verify(&message, &PublicKey::new(&mut rand::thread_rng()).unwrap());

        assert!(!b);
    }


}
