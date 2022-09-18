//! Implementation of Poseidon codehash

use ff::*;
use poseidon_rs::{Fr, Poseidon};

const POSEIDON_RATE: u32 = 2;

/// Poseidon code hasher
pub struct PoseidonCodehash {
    poseidon: Poseidon,
}

impl PoseidonCodehash {
    /// Create a new Self.
    pub fn new() -> Self {
        PoseidonCodehash {
            poseidon: Poseidon::new(),
        }
    }

    /// Pad the code and compute the codehash using Poseidon hash function
    pub fn codehash(&self, code: &Vec<u8>) -> Fr {
        // todo!
        Fr::from_str("0").unwrap()
    }
}

/// Compute the codehash with Poseidon
pub fn codehash(code: &Vec<u8>) -> [u8; 32] {
    let hasher = PoseidonCodehash::new();
    let codehash = hasher.codehash(code);
    let repr = codehash.into_repr();
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    repr.write_be(&mut buf).unwrap();
    let bytes: [u8; 32] = match buf.try_into() {
        Ok(ba) => ba,
        Err(_) => panic!("Expected a vec of length 32"),
    };
    bytes
}
