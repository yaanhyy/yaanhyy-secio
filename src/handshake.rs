use rand::{self, RngCore};
use super::config::SecioConfig;
use futures::prelude::*;


fn handshake<S>(socket: S, config: SecioConfig) -> Result<(), String>
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
    Ok(())
}

mod tests {
    use crate::identity;
    use super::handshake;
    #[test]
    fn handshake_test(){
        async_std::task::spawn(async move {
            let listener = async_std::net::TcpListener::bind(&"127.0.0.1:0").await.unwrap();
            let connec = listener.accept().await.unwrap().0;
            let key1 = identity::Keypair::generate_ed25519();
            handshake(connec, key1);
        });
    }
}