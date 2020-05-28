use rand::{self, RngCore};
use super::config::SecioConfig;
use futures::prelude::*;
use super::algo::{DEFAULT_AGREEMENTS_PROPOSITION, DEFAULT_CIPHERS_PROPOSITION, DEFAULT_DIGESTS_PROPOSITION};
use super::spipe::Propose;
use super::exchange::KeyAgreement;
use prost::Message;


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
    let mut msg = Vec::with_capacity(propose_out.encoded_len());
    propose_out.encode(&mut msg).expect("Vec<u8> provides capacity as needed");

    println!("msg:{:?}", msg);
    let mut buf = vec![0u8; 1024];
    let n = socket.read(&mut buf).await.unwrap();
    println!("buf_len:{},buf:{:?}", n, buf);
    let msg_clone = msg.clone();
    let res = socket.write_all(&(msg_clone.len() as u32).to_be_bytes()).await;
    if let Ok(e) = res {
        let res = socket.write_all(&(msg_clone.clone())).await;
    }
    Ok(())
}

mod tests {
    use crate::identity;
    use super::handshake;
    use crate::config::SecioConfig;
    use std::thread::sleep;
    use std::time;
    #[test]
    fn handshake_test(){
        async_std::task::block_on(async move {
            let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
            let connec = listener.accept().await.unwrap().0;
            let key1 = identity::Keypair::generate_ed25519();
            let mut config = SecioConfig::new(key1);
            let res = handshake(connec, config).await;
        });
//        loop{
//            println!("wait");
//            let ten_millis = time::Duration::from_secs(10);
//            sleep(ten_millis);
//        };
    }
}