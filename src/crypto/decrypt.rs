//! Public-key decryption with optional signature verification, using Sequoia-PGP.

use std::io;

use sequoia_openpgp::crypto::{Password, SessionKey};
use sequoia_openpgp::packet::{Key, PKESK, SKESK};
use sequoia_openpgp::parse::Parse as _;
use sequoia_openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageLayer, MessageStructure, VerificationHelper,
};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::{Cert, KeyHandle};

use crate::error::{GPG_ERR_BAD_SIGNATURE, GPG_ERR_NO_ERROR, gpg_error};
use crate::ffi_types::PassphraseCbFn;
use crate::ffi_types::{
    GPGME_SIGSUM_GREEN, GPGME_SIGSUM_RED, GPGME_SIGSUM_VALID, GPGME_VALIDITY_FULL,
    GPGME_VALIDITY_UNKNOWN,
};
use crate::keyring::{call_passphrase_cb, load_certs, load_secret_certs};

/// Internal record of a single signature encountered during decryption.
pub struct SigRecord2 {
    /// Hex fingerprint of the signing key, or `None` if unavailable.
    pub fpr: Option<String>,
    /// GPGME error code for this signature.
    pub status: u32,
    /// Bitmask of `GPGME_SIGSUM_*` flags.
    pub summary: u32,
    /// Validity level (`GPGME_VALIDITY_*`).
    pub validity: u32,
}

/// Sequoia `VerificationHelper` and `DecryptionHelper` used during decryption.
struct DHelper {
    /// Pre-fetched passphrase for symmetric decryption.
    passphrase: Option<Password>,
    /// Public certificates for signature verification.
    pub_certs: Vec<Cert>,
    /// Secret certificates (TSKs) used for decryption.
    secret_certs: Vec<Cert>,
    /// Accumulated per-signature records.
    sig_records: Vec<SigRecord2>,
}

impl VerificationHelper for DHelper {
    fn check(&mut self, structure: MessageStructure<'_>) -> sequoia_openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for res in results {
                    let record = match res {
                        Ok(good) => SigRecord2 {
                            fpr: Some(good.ka.key().fingerprint().to_hex()),
                            status: GPG_ERR_NO_ERROR,
                            summary: GPGME_SIGSUM_GREEN | GPGME_SIGSUM_VALID,
                            validity: GPGME_VALIDITY_FULL,
                        },
                        Err(_) => SigRecord2 {
                            fpr: None,
                            status: gpg_error(GPG_ERR_BAD_SIGNATURE),
                            summary: GPGME_SIGSUM_RED,
                            validity: GPGME_VALIDITY_UNKNOWN,
                        },
                    };
                    self.sig_records.push(record);
                }
            }
        }
        Ok(())
    }

    fn get_certs(&mut self, ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(ids
            .iter()
            .flat_map(|id| {
                self.pub_certs
                    .iter()
                    .filter(move |cert| {
                        cert.keys().any(|key| {
                            let fpr_kh = KeyHandle::Fingerprint(key.key().fingerprint());
                            let kid_kh = KeyHandle::KeyID(key.key().keyid());
                            id == &fpr_kh || id == &kid_kh
                        })
                    })
                    .cloned()
            })
            .collect())
    }
}

impl DecryptionHelper for DHelper {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> sequoia_openpgp::Result<Option<Cert>> {
        for pkesk in pkesks {
            for cert in &self.secret_certs {
                let recipient = pkesk.recipient();
                for key in cert.keys().secret() {
                    let fpr_kh = KeyHandle::Fingerprint(key.key().fingerprint());
                    let kid_kh = KeyHandle::KeyID(key.key().keyid());
                    let matches = recipient
                        .as_ref()
                        .is_none_or(|rec| rec == &fpr_kh || rec == &kid_kh);
                    if !matches {
                        continue;
                    }
                    let skey = key.key().clone().parts_into_secret();
                    let mut keypair = match skey {
                        Ok(secret_key) if !secret_key.secret().is_encrypted() => {
                            match secret_key.into_keypair() {
                                Ok(kp) => kp,
                                Err(_) => continue,
                            }
                        }
                        Ok(secret_key) => {
                            if let Some(pass) = self.passphrase.as_ref() {
                                match secret_key.decrypt_secret(pass).and_then(Key::into_keypair) {
                                    Ok(kp) => kp,
                                    Err(_) => continue,
                                }
                            } else {
                                continue;
                            }
                        }
                        Err(_) => continue,
                    };
                    if let Some((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo)
                        && decrypt(algo, &session_key)
                    {
                        return Ok(Some(cert.clone()));
                    }
                }
            }
        }
        if let Some(pass) = self.passphrase.as_ref() {
            for skesk in skesks {
                if let Ok((algo, session_key)) = skesk.decrypt(pass)
                    && decrypt(algo, &session_key)
                {
                    return Ok(None);
                }
            }
        }
        Err(sequoia_openpgp::Error::MissingSessionKey("no matching key".into()).into())
    }
}

/// Decrypt `ciphertext` and return the plaintext together with any embedded signature records.
///
/// # Safety
/// `passphrase_hook` must be valid for the duration of any `passphrase_cb` invocation.
pub unsafe fn decrypt_sq(
    home: &str,
    passphrase_cb: Option<PassphraseCbFn>,
    passphrase_hook: *mut u8,
    ciphertext: &[u8],
) -> sequoia_openpgp::Result<(Vec<u8>, Vec<SigRecord2>)> {
    let pub_certs = load_certs(home);
    let secret_certs = load_secret_certs(home);
    let passphrase =
        // SAFETY: passphrase_hook is valid for the duration of the callback, as required by the caller.
        passphrase_cb.and_then(|cb| unsafe { call_passphrase_cb(cb, passphrase_hook, "") });
    let policy = StandardPolicy::new();
    let mut plaintext = Vec::new();
    let helper = DHelper {
        pub_certs,
        secret_certs,
        passphrase,
        sig_records: Vec::new(),
    };
    let decryptor_builder = match DecryptorBuilder::from_bytes(ciphertext) {
        Ok(val) => val,
        Err(err) => return Err(err),
    };
    let mut decryptor = match decryptor_builder.with_policy(&policy, None, helper) {
        Ok(val) => val,
        Err(err) => return Err(err),
    };
    if let Err(err) = io::copy(&mut decryptor, &mut plaintext) {
        return Err(err.into());
    }
    let decrypted = decryptor.into_helper();
    Ok((plaintext, decrypted.sig_records))
}
