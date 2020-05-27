use super::identity;

pub struct SecioConfig {
    /// Private and public keys of the local node.
    pub key: identity::Keypair,
    pub agreements_prop: Option<String>,
    pub ciphers_prop: Option<String>,
    pub digests_prop: Option<String>,
    pub max_frame_len: usize
}