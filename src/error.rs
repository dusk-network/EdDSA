// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”


use thiserror::Error;

#[derive(Error, Debug)]
/// Standard error for the interface
pub enum Error {
    /// Cryptographic invalidity
    #[error(
        "Digital signature scheme failing"
    )]
    Generic,
    /// Invalid secret key
    #[error(
        "Invalid seed provided to generate Secret key"
    )]
    InvalidSeed,
    
}

impl Error {
    /// Return a generic error from any type. Represents a cryptographic mistake
    pub fn generic<T>(_e: T) -> Error {
        Error::Generic
    }
}