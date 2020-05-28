// Copyright 2017 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! This module contains some utilities for algorithm support exchange.
//!
//! One important part of the SECIO handshake is negotiating algorithms. This is what this module
//! helps you with.



use ring::digest;
use std::cmp::Ordering;
use super::exchange::KeyAgreement;
use super::stream_cipher::Cipher;

const ECDH_P256: &str = "P-256";
const ECDH_P384: &str = "P-384";

const AES_128: &str = "AES-128";
const AES_256: &str = "AES-256";
const TWOFISH_CTR: &str = "TwofishCTR";
const NULL: &str = "NULL";

const SHA_256: &str = "SHA256";
const SHA_512: &str = "SHA512";

pub(crate) const DEFAULT_AGREEMENTS_PROPOSITION: &str = "P-256,P-384";
pub(crate) const DEFAULT_CIPHERS_PROPOSITION: &str = "AES-128,AES-256";
pub(crate) const DEFAULT_DIGESTS_PROPOSITION: &str = "SHA256,SHA512";


/// Given two key agreement proposition strings try to figure out a match.
///
/// The `Ordering` parameter determines which argument is preferred. If `Less` or `Equal` we
/// try for each of `theirs` every one of `ours`, for `Greater` it's the other way around.
pub fn select_agreement(r: Ordering, ours: &str, theirs: &str)  -> Result<KeyAgreement, String> {
    let (a, b) = match r {
        Ordering::Less | Ordering::Equal => (theirs, ours),
        Ordering::Greater =>  (ours, theirs)
    };
    for x in a.split(',') {
        if b.split(',').any(|y| x == y) {
            match x {
                ECDH_P256 => return Ok(KeyAgreement::EcdhP256),
                ECDH_P384 => return Ok(KeyAgreement::EcdhP384),
                _ => continue
            }
        }
    }
    Err("NoSupportIntersection".to_string())
}

/// Given two cipher proposition strings try to figure out a match.
///
/// The `Ordering` parameter determines which argument is preferred. If `Less` or `Equal` we
/// try for each of `theirs` every one of `ours`, for `Greater` it's the other way around.
pub fn select_cipher(r: Ordering, ours: &str, theirs: &str) -> Result<Cipher, String> {
    let (a, b) = match r {
        Ordering::Less | Ordering::Equal => (theirs, ours),
        Ordering::Greater =>  (ours, theirs)
    };
    for x in a.split(',') {
        if b.split(',').any(|y| x == y) {
            match x {
                AES_128 => return Ok(Cipher::Aes128),
                AES_256 => return Ok(Cipher::Aes256),
                TWOFISH_CTR => return Ok(Cipher::TwofishCtr),
                NULL => return Ok(Cipher::Null),
                _ => continue
            }
        }
    }
    Err("SecioError::NoSupportIntersection".to_string())
}

/// Possible digest algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Digest {
    Sha256,
    Sha512
}

impl Digest {
    /// Returns the size in bytes of a digest of this kind.
    #[inline]
    pub fn num_bytes(&self) -> usize {
        match *self {
            Digest::Sha256 => 256 / 8,
            Digest::Sha512 => 512 / 8,
        }
    }
}


/// Given two digest proposition strings try to figure out a match.
///
/// The `Ordering` parameter determines which argument is preferred. If `Less` or `Equal` we
/// try for each of `theirs` every one of `ours`, for `Greater` it's the other way around.
pub fn select_digest(r: Ordering, ours: &str, theirs: &str) -> Result<Digest, String> {
    let (a, b) = match r {
        Ordering::Less | Ordering::Equal => (theirs, ours),
        Ordering::Greater =>  (ours, theirs)
    };
    for x in a.split(',') {
        if b.split(',').any(|y| x == y) {
            match x {
                SHA_256 => return Ok(Digest::Sha256),
                SHA_512 => return Ok(Digest::Sha512),
                _ => continue
            }
        }
    }
    Err("SecioError::NoSupportIntersection".to_string())
}
