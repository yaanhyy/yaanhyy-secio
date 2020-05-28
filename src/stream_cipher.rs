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

