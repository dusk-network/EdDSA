// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”

#[derive(Debug)]
/// Standard error for the interface
pub enum Error {
    /// Cryptographic invalidity
    Generic,
    /// Invalid secret key
    InvalidSeed,
    
}

impl Error {
    /// Return a generic error from any type. Represents a cryptographic mistake
    pub fn generic<T>(_e: T) -> Error {
        Error::Generic
    }
}