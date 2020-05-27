use super::identity;

pub struct SecioConfig {
    /// Private and public keys of the local node.
    pub key: identity::Keypair,
    pub agreements_prop: Option<String>,
    pub ciphers_prop: Option<String>,
    pub digests_prop: Option<String>,
    pub max_frame_len: usize
}

impl SecioConfig {
    /// Create a new `SecioConfig` with the given keypair.
    pub fn new(kp: identity::Keypair) -> Self {
        SecioConfig {
            key: kp,
            agreements_prop: None,
            ciphers_prop: None,
            digests_prop: None,
            max_frame_len: 8 * 1024 * 1024
        }
    }
}