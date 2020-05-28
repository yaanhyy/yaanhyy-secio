use ring::agreement as ring_agreement;
use ring::rand as ring_rand;
use log::debug;

/// Possible key agreement algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyAgreement {
    EcdhP256,
    EcdhP384
}

impl Into<&'static ring_agreement::Algorithm> for KeyAgreement {
    #[inline]
    fn into(self) -> &'static ring_agreement::Algorithm {
        match self {
            KeyAgreement::EcdhP256 => &ring_agreement::ECDH_P256,
            KeyAgreement::EcdhP384 => &ring_agreement::ECDH_P384,
        }
    }
}

/// Opaque private key type.
pub type AgreementPrivateKey = ring_agreement::EphemeralPrivateKey;

/// Generates a new key pair as part of the exchange.
///
/// Returns the opaque private key and the corresponding public key.
pub fn generate_agreement(algorithm: KeyAgreement) ->  Result<(AgreementPrivateKey, Vec<u8>), String> {
    let rng = ring_rand::SystemRandom::new();

    match ring_agreement::EphemeralPrivateKey::generate(algorithm.into(), &rng) {
        Ok(tmp_priv_key) => {
            let r = tmp_priv_key.compute_public_key()
                .map_err(|e| "SecioError::EphemeralKeyGenerationFailed".to_string())
                .map(move |tmp_pub_key| (tmp_priv_key, tmp_pub_key.as_ref().to_vec()));
            return r
        },
        Err(_) => {
            debug!("failed to generate ECDH key");
            Err("SecioError::EphemeralKeyGenerationFailed".to_string())
        },
    }
}

/// Finish the agreement. On success, returns the shared key that both remote agreed upon.
pub fn agree(algorithm: KeyAgreement, my_private_key: AgreementPrivateKey, other_public_key: &[u8], _out_size: usize)
             ->  Result<Vec<u8>, String>
{
    let ret = ring_agreement::agree_ephemeral(my_private_key,
                                              &ring_agreement::UnparsedPublicKey::new(algorithm.into(), other_public_key),
                                              "agree err".to_string(),
                                              |key_material| Ok(key_material.to_vec()));
    ret
}
