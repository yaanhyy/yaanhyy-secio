use rand::{self, RngCore};
use super::config::SecioConfig;
use futures::prelude::*;
use super::algo::{DEFAULT_AGREEMENTS_PROPOSITION, DEFAULT_CIPHERS_PROPOSITION, DEFAULT_DIGESTS_PROPOSITION};
use super::spipe::Propose;
use super::exchange::KeyAgreement;
use prost::Message;

fn handshake<S>(socket: S, mut config: SecioConfig) -> Result<(), String>
where S: AsyncRead + AsyncWrite
{
    let local_nonce = {
        let mut local_nonce = [0; 16];
        rand::thread_rng()
            .try_fill_bytes(&mut local_nonce)
            .map_err(|e| format!("rand err:{:?}", e));
        local_nonce
    };
    println!("rand:{:?}", local_nonce);
    let pubkey = config.key.public();
    config.agreements_prop = Some(DEFAULT_AGREEMENTS_PROPOSITION.to_string());
    config.ciphers_prop = Some(DEFAULT_CIPHERS_PROPOSITION.to_string());
    config.digests_prop = Some(DEFAULT_DIGESTS_PROPOSITION.to_string());
    let mut  propose_out = Propose {
        rand: Some(local_nonce.into()),
        exchanges : Some("P-256".to_string()),
        ciphers : config.ciphers_prop,
        hashes : config.digests_prop,
        pubkey : Some(pubkey.into_protobuf_encoding())
    };
    println!("propose_out:{:?}", propose_out);
    let mut msg = Vec::with_capacity(propose_out.encoded
    _len());
    propose_out.encode(&mut msg).expect("Vec<u8> provides capacity as needed");
    println!("msg:{:?}", msg);
    Ok(())
}

mod tests {
    use crate::identity;
    use super::handshake;
    use crate::config::SecioConfig;
    use async_std::net;
    use std::thread::sleep;
    use std::time;
    #[test]
    fn handshake_test(){
        async_std::task::spawn(async move {
            let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
            let connec = listener.accept().await.unwrap().0;
            let key1 = identity::Keypair::generate_ed25519();
            let mut config = SecioConfig::new(key1);
            handshake(connec, config);
        });
        loop{
            println!("wait");
            let ten_millis = time::Duration::from_secs(10);
            sleep(ten_millis);
        };
    }
}