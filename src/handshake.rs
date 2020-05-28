use rand::{self, RngCore};
use super::config::SecioConfig;
use futures::prelude::*;
use super::algo::{DEFAULT_AGREEMENTS_PROPOSITION, DEFAULT_CIPHERS_PROPOSITION, DEFAULT_DIGESTS_PROPOSITION, select_agreement, select_cipher, select_digest};
use super::spipe::{Propose, Exchange};
use super::exchange::{KeyAgreement, generate_agreement, agree};
use prost::Message;
use sha2::{Digest as ShaDigestTrait, Sha256};
use log::debug;
use super::identity::PublicKey;
use super::codec::Hmac;
use std::{cmp::{self, Ordering}, io};

fn encode_prefix_len(msg: Vec<u8>, max_len: u32) -> Result<Vec<u8>, String>{
    let len = msg.len();
    if len as u32 > max_len {
        return Err("msg too long".to_string());
    }
    return Ok(msg)
}

async fn handshake<S>(mut socket: S, mut config: SecioConfig) -> Result<(), String>
where S: AsyncRead + AsyncWrite  + Send + Unpin + 'static
{
    // step 1. Propose -- propose cipher suite + send pubkeys + nonce
    let local_nonce = {
        let mut local_nonce = [0; 16];
        rand::thread_rng()
            .try_fill_bytes(&mut local_nonce)
            .map_err(|e| format!("rand err:{:?}", e));
        local_nonce
    };
    println!("rand:{:?}", local_nonce);
    let pubkey = config.key.public();
    let local_public_key_encoded = pubkey.into_protobuf_encoding();
    config.agreements_prop = Some(DEFAULT_AGREEMENTS_PROPOSITION.to_string());
    config.ciphers_prop = Some(DEFAULT_CIPHERS_PROPOSITION.to_string());
    config.digests_prop = Some(DEFAULT_DIGESTS_PROPOSITION.to_string());
    let mut  propose_out = Propose {
        rand: Some(local_nonce.into()),
        exchanges : Some("P-256".to_string()),
        ciphers : config.ciphers_prop.clone(),
        hashes : config.digests_prop.clone(),
        pubkey : Some(local_public_key_encoded.clone())
    };
    println!("propose_out:{:?}", propose_out);
    let mut local_proposition_bytes = Vec::with_capacity(propose_out.encoded_len());
    propose_out.encode(&mut local_proposition_bytes).expect("Vec<u8> provides capacity as needed");

    println!("msg:{:?}", local_proposition_bytes);

    //fix me, change to async
    let mut len = [0; 4];
    socket.read_exact(&mut len).await.unwrap();
    let mut n = u32::from_be_bytes(len) as usize;
    let mut remote_proposition_bytes = vec![0u8; n];
    socket.read_exact(&mut remote_proposition_bytes).await.unwrap();
    println!("buf_len:{},buf:{:?}", n, remote_proposition_bytes);

    let local_proposition_bytes_clone = local_proposition_bytes.clone();
    let res = socket.write_all(&(local_proposition_bytes_clone.len() as u32).to_be_bytes()).await;
    if let Ok(e) = res {
        let res = socket.write_all(&(local_proposition_bytes_clone)).await;
    }

    // step 1.1 Identify -- get identity from their key
    let mut  propose_in: Propose = match Propose::decode(&remote_proposition_bytes[..]) {
        Ok(prop) => prop,
        Err(_) => {
            println!("failed to parse remote's proposition protobuf message");
            return Err("SecioError::HandshakeParsingFailure".to_string());
        }
    };

    let remote_public_key_encoded = propose_in.pubkey.unwrap_or_default();
    let remote_nonce = propose_in.rand.unwrap_or_default();
    println!("remote_nonce:{:?}", remote_nonce);

    let remote_public_key = match PublicKey::from_protobuf_encoding(&remote_public_key_encoded) {
        Ok(p) => p,
        Err(e) => {
            println!("failed to parse remote's proposition's pubkey protobuf:{:?}", e);
            return Err("SecioError::HandshakeParsingFailure".to_string());
        },
    };

    // step 1.2 Selection -- select/agree on best encryption parameters
    // In order to determine which protocols to use, we compute two hashes and choose
    // based on which hash is larger.
    let hashes_ordering = {
        let oh1 = {
            let mut ctx = Sha256::new();
            ctx.input(&remote_public_key_encoded);
            ctx.input(&local_nonce);
            ctx.result()
        };

        let oh2 = {
            let mut ctx = Sha256::new();
            ctx.input(&local_public_key_encoded);
            ctx.input(&remote_nonce);
            ctx.result()
        };

        oh1.as_ref().cmp(&oh2.as_ref())
    };

    let chosen_exchange = {
        let ours = config.agreements_prop.as_ref()
            .map(|s| s.as_ref())
            .unwrap_or(DEFAULT_AGREEMENTS_PROPOSITION);
        let theirs = &propose_in.exchanges.unwrap_or_default();
        match select_agreement(hashes_ordering, ours, theirs) {
            Ok(a) => a,
            Err(err) => {
                debug!("failed to select an exchange protocol");
                return Err(err);
            }
        }
    };

    let chosen_cipher = {
        let ours = config.ciphers_prop.as_ref()
            .map(|s| s.as_ref())
            .unwrap_or(DEFAULT_CIPHERS_PROPOSITION);
        let theirs = &propose_in.ciphers.unwrap_or_default();
        match select_cipher(hashes_ordering, ours, theirs) {
            Ok(a) => {
                debug!("selected cipher: {:?}", a);
                a
            }
            Err(err) => {
                debug!("failed to select a cipher protocol");
                return Err(err);
            }
        }
    };

    let chosen_hash = {
        let ours = config.digests_prop.as_ref()
            .map(|s| s.as_ref())
            .unwrap_or(DEFAULT_DIGESTS_PROPOSITION);
        let theirs = &propose_in.hashes.unwrap_or_default();
        match select_digest(hashes_ordering, ours, theirs) {
            Ok(a) => {
                debug!("selected hash: {:?}", a);
                a
            }
            Err(err) => {
                debug!("failed to select a hash protocol");
                return Err(err);
            }
        }
    };

    // step 2. Exchange -- exchange (signed) ephemeral keys. verify signatures.
    // Generate an ephemeral key for the negotiation.
    // fix me async?
    let (tmp_priv_key, tmp_pub_key) =  generate_agreement(chosen_exchange)?;

    // Send the ephemeral pub key to the remote in an `Exchange` struct. The `Exchange` also
    // contains a signature of the two propositions encoded with our static public key.
    let local_exchange = {
        let mut data_to_sign = local_proposition_bytes.clone();
        data_to_sign.extend_from_slice(&remote_proposition_bytes);
        data_to_sign.extend_from_slice(&tmp_pub_key);

        Exchange {
            epubkey: Some(tmp_pub_key.clone()),
            signature: match config.key.sign(&data_to_sign) {
                Ok(sig) => Some(sig),
                Err(_) => return Err("SecioError::SigningFailure".to_string())
            }
        }
    };

    let local_exch = {
        let mut buf = Vec::with_capacity(local_exchange.encoded_len());
        local_exchange.encode(&mut buf).expect("Vec<u8> provides capacity as needed");
        buf
    };


    // Receive the remote's `Exchange`.
    let mut len = [0; 4];
    socket.read_exact(&mut len).await.unwrap();
    let mut n = u32::from_be_bytes(len) as usize;
    let mut remote_exchange_bytes = vec![0u8; n];
    socket.read_exact(&mut remote_exchange_bytes).await.unwrap();
    println!("buf_len:{},buf:{:?}", n, remote_exchange_bytes);

    // Send our local `Exchange`.
    let res = socket.write_all(&(local_exch.len() as u32).to_be_bytes()).await;
    if let Ok(e) = res {
        let res = socket.write_all(&(local_exch)).await;
    }

    // step 2.1. Verify -- verify their exchange packet is good.
    let mut  exchange_in: Exchange = match Exchange::decode(&remote_exchange_bytes[..]) {
        Ok(exchage) => exchage,
        Err(_) => {
            println!("failed to parse remote's exchage protobuf message");
            return Err("failed to parse remote's exchange protobuf".to_string());
        }
    };

    // Check the validity of the remote's `Exchange`. This verifies that the remote was really
    // the sender of its proposition, and that it is the owner of both its global and ephemeral
    // keys.
    {
        let mut data_to_verify = remote_proposition_bytes.clone();
        data_to_verify.extend_from_slice(&local_proposition_bytes);
        data_to_verify.extend_from_slice(exchange_in.epubkey.as_deref().unwrap_or_default());

        if !remote_public_key.verify(&data_to_verify, &exchange_in.signature.unwrap_or_default()) {
            return Err("SecioError::SignatureVerificationFailed".to_string())
        }

        println!("successfully verified the remote's signature");
    }

    // step 2.2. Keys -- generate keys for mac + encryption
    // Generate a key from the local ephemeral private key and the remote ephemeral public key,
    // derive from it a cipher key, an iv, and a hmac key, and build the encoder/decoder.
    let key_material = agree(
        chosen_exchange,
        tmp_priv_key,
        &exchange_in.epubkey.unwrap_or_default(),
        chosen_hash.num_bytes()
    )?;



    let cipher_key_size = chosen_cipher.key_size();
    let iv_size = chosen_cipher.iv_size();

    let key = Hmac::from_key(chosen_hash, &key_material);
    let mut longer_key = vec![0u8; 2 * (iv_size + cipher_key_size + 20)];
    stretch_key(key, &mut longer_key);

    let (local_infos, remote_infos) = {
        let (first_half, second_half) = longer_key.split_at(longer_key.len() / 2);
        match hashes_ordering {
            Ordering::Equal => {
                let msg = "equal digest of public key and nonce for local and remote";
                return Err(msg.to_string())
            }
            Ordering::Less => (second_half, first_half),
            Ordering::Greater => (first_half, second_half),
        }
    };

    Ok(())
}

/// Custom algorithm translated from reference implementations. Needs to be the same algorithm
/// amongst all implementations.
fn stretch_key(hmac: Hmac, result: &mut [u8]) {
    match hmac {
        Hmac::Sha256(hmac) => stretch_key_inner(hmac, result),
        Hmac::Sha512(hmac) => stretch_key_inner(hmac, result),
    }
}

fn stretch_key_inner<D>(hmac: ::hmac::Hmac<D>, result: &mut [u8])
    where D: ::hmac::digest::Input + ::hmac::digest::BlockInput +
    ::hmac::digest::FixedOutput + ::hmac::digest::Reset + Default + Clone,
          ::hmac::Hmac<D>: Clone + ::hmac::crypto_mac::Mac
{
    use ::hmac::Mac;
    const SEED: &[u8] = b"key expansion";

    let mut init_ctxt = hmac.clone();
    init_ctxt.input(SEED);
    let mut a = init_ctxt.result().code();

    let mut j = 0;
    while j < result.len() {
        let mut context = hmac.clone();
        context.input(a.as_ref());
        context.input(SEED);
        let b = context.result().code();

        let todo = cmp::min(b.as_ref().len(), result.len() - j);

        result[j..j + todo].copy_from_slice(&b.as_ref()[..todo]);

        j += todo;

        let mut context = hmac.clone();
        context.input(a.as_ref());
        a = context.result().code();
    }
}


mod tests {
    use crate::identity;
    use super::handshake;
    use crate::config::SecioConfig;
    use std::thread::sleep;
    use std::time;
    use sha2::{Digest as ShaDigestTrait, Sha256};
    #[test]
    fn handshake_test(){
        async_std::task::block_on(async move {
            let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
            let connec = listener.accept().await.unwrap().0;
            let key1 = identity::Keypair::generate_ed25519();
            let mut config = SecioConfig::new(key1);
            let res = handshake(connec, config).await;
            println!("handshake res:{:?}", res);
        });
//        loop{
//            println!("wait");
//            let ten_millis = time::Duration::from_secs(10);
//            sleep(ten_millis);
//        };
    }

    #[test]
    fn sha_cmp_test() {
        let mut ctx = Sha256::new();
        ctx.input("15c");
        ctx.input("123");
        let res = ctx.result();
        println!("res:{:?}", res );

        let mut ctx1 = Sha256::new();
        ctx1.input("edf");
        ctx1.input("456");
        let res1 = ctx1.result();
        println!("res1:{:?}", res1 );
        let cmp_res = res.as_ref().cmp(&res1.as_ref());
        println!("cmp_res:{:?}", cmp_res );
    }
}