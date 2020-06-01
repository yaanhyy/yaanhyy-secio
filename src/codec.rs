use hmac::{self, Mac};
use sha2::{Sha256, Sha512};
use super::algo::Digest;
use futures::prelude::*;
use crate::stream_cipher::StreamCipher;
use log::debug;
use std::{pin::Pin, task::Context, task::Poll, io};

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

pub struct SecureConn<S> {
    pub socket: S,
    pub encoding_cipher: StreamCipher,
    pub decoding_cipher: StreamCipher,
    pub encoding_hmac: Hmac,
    pub decoding_hmac: Hmac,
}


// impl AsyncRead for SecureConn<S>
// {
//     fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8])
//                  -> Poll<Result<(), String>> {
//         Poll::Ready(Ok(()))
//     }
// }

impl <S: AsyncRead + AsyncWrite  + Send + Unpin + 'static>SecureConn<S> {
    pub async fn send(&mut self, buf: & mut Vec<u8>) -> Result<(),String> {
        self.encoding_cipher.encrypt( buf.as_mut());
        let signature = self.encoding_hmac.sign(buf.as_mut());
        buf.extend_from_slice(signature.as_ref());
        let mut res = self.socket.write_all(&(buf.len() as u32).to_be_bytes()).await;
        if let Ok(_) = res {
            res = self.socket.write_all(buf.as_mut()).await;
            if let Err(e) = res {
                return Err("secio send fail".to_string());
            }
        } else {
            return Err("secio send fail".to_string());
        }
        Ok(())
    }

    pub async fn read(&mut self) -> Result<Vec<u8>,String>{
        let mut len = [0; 4];
        self.socket.read_exact(&mut len).await.unwrap();
        let mut n = u32::from_be_bytes(len) as usize;
        let mut read_buf = vec![0u8; n];
        self.socket.read_exact(&mut read_buf).await.unwrap();
        println!("buf_len:{},buf:{:?}", n, read_buf);
        let content_length = read_buf.len() - self.decoding_hmac.num_bytes();
        {
            let (crypted_data, expected_hash) = read_buf.split_at(content_length);
            debug_assert_eq!(expected_hash.len(), self.decoding_hmac.num_bytes());

            if self.decoding_hmac.verify(crypted_data, expected_hash).is_err() {
                debug!("hmac mismatch when decoding secio frame");
                return Err("SecioError::HmacNotMatching".to_string());
            }
        }

        let mut data_buf = read_buf;
        data_buf.truncate(content_length);
        self.decoding_cipher.decrypt(&mut data_buf);
        return Ok(data_buf);
    }
}