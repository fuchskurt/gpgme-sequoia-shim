//! Public-key encryption using Sequoia-PGP.

use std::io::Write as _;

use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message};

use crate::keyring::load_certs;

/// Encrypt `plaintext` for the given `recipient_fprs` and return the ciphertext.
///
/// Fingerprints are matched by exact or suffix comparison (case-insensitive hex).
/// When `armor` is `true`, the output is ASCII-armored.
pub fn encrypt_sq(
    home: &str,
    recipient_fprs: &[String],
    plaintext: &[u8],
    armor: bool,
) -> sequoia_openpgp::Result<Vec<u8>> {
    let certs = load_certs(home);
    let policy = StandardPolicy::new();
    let valid_certs: Vec<_> = certs
        .iter()
        .filter(|cert| {
            let fpr = cert.fingerprint().to_hex();
            recipient_fprs
                .iter()
                .any(|rec_fpr| fpr == *rec_fpr || fpr.ends_with(rec_fpr.as_str()))
        })
        .filter_map(|cert| cert.with_policy(&policy, None).ok())
        .collect();
    if valid_certs.is_empty() {
        return Err(
            sequoia_openpgp::Error::InvalidOperation("no valid recipient keys".into()).into(),
        );
    }
    let enc_keys: Vec<_> = valid_certs
        .iter()
        .flat_map(|vc| {
            vc.keys()
                .supported()
                .alive()
                .revoked(false)
                .for_transport_encryption()
        })
        .collect();
    let mut output = Vec::new();
    let sink = Message::new(&mut output);
    let armored = if armor {
        match Armorer::new(sink).build() {
            Ok(val) => val,
            Err(err) => return Err(err),
        }
    } else {
        sink
    };
    let encrypted = match Encryptor::for_recipients(armored, enc_keys).build() {
        Ok(val) => val,
        Err(err) => return Err(err),
    };
    let mut lit = match LiteralWriter::new(encrypted).build() {
        Ok(val) => val,
        Err(err) => return Err(err),
    };
    if let Err(err) = lit.write_all(plaintext) {
        return Err(err.into());
    }
    if let Err(err) = lit.finalize() {
        return Err(err);
    }
    Ok(output)
}
