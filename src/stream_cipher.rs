use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewStreamCipher, LoopError, SyncStreamCipher};
use aes_ctr::{Aes128Ctr, Aes256Ctr};
use ctr::Ctr128;
use twofish::Twofish;
use aes_ctr::stream_cipher;

pub type StreamCipher = Box<dyn stream_cipher::StreamCipher + Send>;
/// Possible encryption ciphers.
#[derive(Clone, Copy, Debug)]
pub enum Cipher {
    Aes128,
    Aes256,
    TwofishCtr,
    Null,
}

impl Cipher {
    /// Returns the size of in bytes of the key expected by the cipher.
    pub fn key_size(&self) -> usize {
        match *self {
            Cipher::Aes128 => 16,
            Cipher::Aes256 => 32,
            Cipher::TwofishCtr => 32,
            Cipher::Null => 0,
        }
    }

    /// Returns the size of in bytes of the IV expected by the cipher.
    #[inline]
    pub fn iv_size(&self) -> usize {
        match self {
            Cipher::Aes128 | Cipher::Aes256 | Cipher::TwofishCtr => 16,
            Cipher::Null => 0
        }
    }
}

/// A no-op cipher which does not encrypt or decrypt at all.
/// Obviously only useful for debugging purposes.
#[derive(Clone, Copy, Debug)]
pub struct NullCipher;

impl SyncStreamCipher for NullCipher {
    fn try_apply_keystream(&mut self, _data: &mut [u8]) -> Result<(), LoopError> {
        Ok(())
    }
}


pub fn ctr(key_size: Cipher, key: &[u8], iv: &[u8]) -> StreamCipher {
    ctr_int(key_size, key, iv)
}


#[inline]
fn ctr_int(key_size: Cipher, key: &[u8], iv: &[u8]) -> StreamCipher {
    match key_size {
        Cipher::Aes128 => Box::new(Aes128Ctr::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(iv),
        )),
        Cipher::Aes256 => Box::new(Aes256Ctr::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(iv),
        )),
        Cipher::TwofishCtr => Box::new(Ctr128::<Twofish>::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(iv),
        )),
        Cipher::Null => Box::new(NullCipher),
    }
}
