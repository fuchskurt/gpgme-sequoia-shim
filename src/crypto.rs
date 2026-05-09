//! Cryptographic operations: verify, encrypt, sign, and decrypt.

pub mod decrypt;
pub mod encrypt;
pub mod sign;
pub mod verify;

// Re-export the Password type used across submodules.
pub use sequoia_openpgp::crypto::Password;
