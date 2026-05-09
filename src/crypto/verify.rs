//! Detached-signature verification using Sequoia-PGP.

use std::io;
use std::time::UNIX_EPOCH;

use sequoia_openpgp::parse::Parse as _;
use sequoia_openpgp::parse::stream::{
    DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper,
};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::{Cert, KeyHandle};

use crate::error::{GPG_ERR_BAD_SIGNATURE, GPG_ERR_NO_ERROR, GPG_ERR_NO_PUBKEY, gpg_error};
use crate::ffi_types::{
    GPGME_SIGSUM_GREEN, GPGME_SIGSUM_KEY_MISSING, GPGME_SIGSUM_RED, GPGME_SIGSUM_VALID,
    GPGME_VALIDITY_UNKNOWN,
};
use crate::keyring::load_certs;

/// Internal record of a single signature result from a verify operation.
pub struct SigRecord {
    /// Signature expiry timestamp (Unix seconds, 0 = no expiry).
    pub exp_timestamp: u64,
    /// Hex fingerprint of the signing key, or `None` if unavailable.
    pub fpr: Option<String>,
    /// GPGME error code for this signature.
    pub status: u32,
    /// Bitmask of `GPGME_SIGSUM_*` flags.
    pub summary: u32,
    /// Signature creation timestamp (Unix seconds).
    pub timestamp: u64,
    /// Validity level (`GPGME_VALIDITY_*`).
    pub validity: u32,
}

/// Sequoia `VerificationHelper` used during detached-signature verification.
struct VHelper {
    /// Public certificates available for verifying.
    certs: Vec<Cert>,
    /// Accumulated per-signature results.
    records: Vec<SigRecord>,
}

impl VerificationHelper for VHelper {
    fn check(&mut self, structure: MessageStructure<'_>) -> sequoia_openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for res in results {
                    match res {
                        Ok(good) => {
                            let fpr = good.ka.key().fingerprint().to_hex();
                            let ts = good
                                .sig
                                .signature_creation_time()
                                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                                .map_or(0, |dur| dur.as_secs());
                            let exp = good
                                .sig
                                .signature_expiration_time()
                                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                                .map_or(0, |dur| dur.as_secs());
                            self.records.push(SigRecord {
                                fpr: Some(fpr),
                                status: GPG_ERR_NO_ERROR,
                                summary: GPGME_SIGSUM_GREEN | GPGME_SIGSUM_VALID,
                                validity: GPGME_VALIDITY_UNKNOWN,
                                timestamp: ts,
                                exp_timestamp: exp,
                            });
                        }
                        Err(err) => {
                            use sequoia_openpgp::parse::stream::VerificationError::{
                                BadKey, BadSignature, MalformedSignature, MissingKey, UnboundKey,
                                UnknownSignature,
                            };
                            let (fpr, status, summary) = match err {
                                MissingKey { sig } => {
                                    let fp = sig.get_issuers().into_iter().find_map(|handle| {
                                        if let KeyHandle::Fingerprint(fp) = handle {
                                            Some(fp.to_hex())
                                        } else {
                                            None
                                        }
                                    });
                                    (fp, gpg_error(GPG_ERR_NO_PUBKEY), GPGME_SIGSUM_KEY_MISSING)
                                }
                                UnboundKey { .. }
                                | BadKey { .. }
                                | BadSignature { .. }
                                | MalformedSignature { .. }
                                | UnknownSignature { .. }
                                | _ => (None, gpg_error(GPG_ERR_BAD_SIGNATURE), GPGME_SIGSUM_RED),
                            };
                            self.records.push(SigRecord {
                                fpr,
                                status,
                                summary,
                                validity: GPGME_VALIDITY_UNKNOWN,
                                timestamp: 0,
                                exp_timestamp: 0,
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn get_certs(&mut self, ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(ids
            .iter()
            .flat_map(|id| {
                self.certs
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

/// Verify a detached PGP signature against plaintext and return per-signature records.
///
/// On a fatal verification error a single "bad signature" record is returned.
pub fn verify_sq(home: &str, sig_bytes: &[u8], data_bytes: &[u8]) -> Vec<SigRecord> {
    let certs = load_certs(home);
    let policy = StandardPolicy::new();
    match (|| -> sequoia_openpgp::Result<VHelper> {
        let builder = match DetachedVerifierBuilder::from_bytes(sig_bytes) {
            Ok(val) => val,
            Err(err) => return Err(err),
        };
        let mut verifier = match builder.with_policy(
            &policy,
            None,
            VHelper {
                certs,
                records: Vec::new(),
            },
        ) {
            Ok(val) => val,
            Err(err) => return Err(err),
        };
        if let Err(err) = verifier.verify_reader(io::Cursor::new(data_bytes)) {
            return Err(err);
        }
        Ok(verifier.into_helper())
    })() {
        Ok(helper) => helper.records,
        Err(_) => vec![SigRecord {
            fpr: None,
            status: gpg_error(GPG_ERR_BAD_SIGNATURE),
            summary: GPGME_SIGSUM_RED,
            validity: GPGME_VALIDITY_UNKNOWN,
            timestamp: 0,
            exp_timestamp: 0,
        }],
    }
}
