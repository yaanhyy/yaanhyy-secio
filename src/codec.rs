use hmac::{self, Mac};
use sha2::{Sha256, Sha512};
use super::algo::Digest;

#[derive(Debug, Clone)]
pub enum Hmac {
    Sha256(hmac::Hmac<Sha256>),
    Sha512(hmac::Hmac<Sha512>),
}

impl Hmac {
    /// Returns the size of the hash in bytes.
    #[inline]
    pub fn num_bytes(&self) -> usize {
        match *self {
            Hmac::Sha256(_) => 32,
            Hmac::Sha512(_) => 64,
        }
    }

    /// Builds a `Hmac` from an algorithm and key.
    pub fn from_key(algorithm: Digest, key: &[u8]) -> Self {
        // TODO: it would be nice to tweak the hmac crate to add an equivalent to new_varkey that
        //       never errors
        match algorithm {
            Digest::Sha256 => Hmac::Sha256(Mac::new_varkey(key)
                .expect("Hmac::new_varkey accepts any key length")),
            Digest::Sha512 => Hmac::Sha512(Mac::new_varkey(key)
                .expect("Hmac::new_varkey accepts any key length")),
        }
    }

    /// Signs the data.
    // TODO: better return type?
    pub fn sign(&self, crypted_data: &[u8]) -> Vec<u8> {
        match *self {
            Hmac::Sha256(ref hmac) => {
                let mut hmac = hmac.clone();
                hmac.input(crypted_data);
                hmac.result().code().to_vec()
            },
            Hmac::Sha512(ref hmac) => {
                let mut hmac = hmac.clone();
                hmac.input(crypted_data);
                hmac.result().code().to_vec()
            },
        }
    }

    /// Verifies that the data matches the expected hash.
    // TODO: better error?
    pub fn verify(&self, crypted_data: &[u8], expected_hash: &[u8]) -> Result<(), ()> {
        match *self {
            Hmac::Sha256(ref hmac) => {
                let mut hmac = hmac.clone();
                hmac.input(crypted_data);
                hmac.verify(expected_hash).map_err(|_| ())
            },
            Hmac::Sha512(ref hmac) => {
                let mut hmac = hmac.clone();
                hmac.input(crypted_data);
                hmac.verify(expected_hash).map_err(|_| ())
            },
        }
    }
}
