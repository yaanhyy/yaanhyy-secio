/// Possible key agreement algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyAgreement {
    EcdhP256,
    EcdhP384
}
