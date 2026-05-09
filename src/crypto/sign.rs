//! Message signing using Sequoia-PGP.

use std::io::Write as _;

use sequoia_openpgp::crypto::KeyPair;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{LiteralWriter, Message, Signer};

use crate::ffi_types::{GPGME_SIG_MODE_CLEAR, GPGME_SIG_MODE_DETACH, PassphraseCbFn};
use crate::keyring::{call_passphrase_cb, load_secret_certs};

/// Write a signed message into `output` using the given `keypair` and signing `mode`.
fn write_signed_output(
    output: &mut Vec<u8>,
    keypair: KeyPair,
    plaintext: &[u8],
    mode: u32,
) -> sequoia_openpgp::Result<()> {
    match mode {
        GPGME_SIG_MODE_DETACH => {
            let sink = Message::new(output);
            let signer_tmp = match Signer::new(sink, keypair) {
                Ok(val) => val,
                Err(err) => return Err(err),
            };
            let mut signer = match signer_tmp.detached().build() {
                Ok(val) => val,
                Err(err) => return Err(err),
            };
            if let Err(err) = signer.write_all(plaintext) {
                return Err(err.into());
            }
            if let Err(err) = signer.finalize() {
                return Err(err);
            }
        }
        GPGME_SIG_MODE_CLEAR => {
            let sink = Message::new(output);
            let signer_tmp = match Signer::new(sink, keypair) {
                Ok(val) => val,
                Err(err) => return Err(err),
            };
            let mut signer = match signer_tmp.cleartext().build() {
                Ok(val) => val,
                Err(err) => return Err(err),
            };
            if let Err(err) = signer.write_all(plaintext) {
                return Err(err.into());
            }
            if let Err(err) = signer.finalize() {
                return Err(err);
            }
        }
        _ => {
            let sink = Message::new(output);
            let signer_tmp = match Signer::new(sink, keypair) {
                Ok(val) => val,
                Err(err) => return Err(err),
            };
            let signed = match signer_tmp.build() {
                Ok(val) => val,
                Err(err) => return Err(err),
            };
            let mut lit = match LiteralWriter::new(signed).build() {
                Ok(val) => val,
                Err(err) => return Err(err),
            };
            if let Err(err) = lit.write_all(plaintext) {
                return Err(err.into());
            }
            if let Err(err) = lit.finalize() {
                return Err(err);
            }
        }
    }
    Ok(())
}

/// Sign `plaintext` with a key from the home keyring and return the signed output.
///
/// `signer_fprs` may be empty, in which case the first available secret key is used.
/// `mode` selects normal, detached, or cleartext signing.
///
/// # Safety
/// `passphrase_hook` must be valid for the duration of any `passphrase_cb` invocation.
pub unsafe fn sign_sq(
    home: &str,
    signer_fprs: &[String],
    passphrase_cb: Option<PassphraseCbFn>,
    passphrase_hook: *mut u8,
    plaintext: &[u8],
    mode: u32,
) -> sequoia_openpgp::Result<Vec<u8>> {
    let secret_certs = load_secret_certs(home);
    let policy = StandardPolicy::new();
    let cert_opt = if signer_fprs.is_empty() {
        secret_certs.into_iter().next()
    } else {
        secret_certs.into_iter().find(|cert| {
            let fpr = cert.fingerprint().to_hex();
            signer_fprs
                .iter()
                .any(|signer_fpr| fpr == *signer_fpr || fpr.ends_with(signer_fpr.as_str()))
        })
    };
    let cert = match cert_opt
        .ok_or_else(|| sequoia_openpgp::Error::InvalidOperation("no signing key".into()))
    {
        Ok(val) => val,
        Err(err) => return Err(err.into()),
    };

    let vc = match cert.with_policy(&policy, None) {
        Ok(val) => val,
        Err(err) => return Err(err),
    };
    let signing_key = match vc
        .keys()
        .secret()
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .ok_or_else(|| sequoia_openpgp::Error::InvalidOperation("no valid signing subkey".into()))
    {
        Ok(val) => val,
        Err(err) => return Err(err.into()),
    };

    let keypair = {
        let key = match signing_key.key().clone().parts_into_secret() {
            Ok(val) => val,
            Err(err) => return Err(err),
        };
        if key.secret().is_encrypted() {
            let passphrase = match passphrase_cb
                .and_then(|cb| {
                    let hint = cert
                        .userids()
                        .next()
                        .map(|uid| String::from_utf8_lossy(uid.component().value()).to_string())
                        .unwrap_or_default();
                    // SAFETY: passphrase_hook is valid for the duration of the callback, as required by the caller.
                    unsafe { call_passphrase_cb(cb, passphrase_hook, &hint) }
                })
                .ok_or_else(|| sequoia_openpgp::Error::InvalidOperation("no passphrase".into()))
            {
                Ok(val) => val,
                Err(err) => return Err(err.into()),
            };
            let decrypted = match key.decrypt_secret(&passphrase) {
                Ok(val) => val,
                Err(err) => return Err(err),
            };
            match decrypted.into_keypair() {
                Ok(val) => val,
                Err(err) => return Err(err),
            }
        } else {
            match key.into_keypair() {
                Ok(val) => val,
                Err(err) => return Err(err),
            }
        }
    };

    let mut output = Vec::new();
    if let Err(err) = write_signed_output(&mut output, keypair, plaintext, mode) {
        return Err(err);
    }
    Ok(output)
}
