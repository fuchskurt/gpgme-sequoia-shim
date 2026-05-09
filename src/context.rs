//! GPGME context type and constructor.

use alloc::ffi::CString;
use core::ptr;

use crate::ffi_types::{
    GPGME_KEYLIST_MODE_LOCAL, GPGME_PROTOCOL_OPENPGP, GpgmeDecryptResult, GpgmeEncryptResult,
    GpgmeImportResult, GpgmeImportStatus, GpgmeSignResult, GpgmeVerifyResult, PassphraseCbFn,
};
use sequoia_openpgp::Cert;

/// Internal context object; aliased as `GpgmeCtx` in the C ABI.
pub struct SqCtx {
    /// Result storage for the last decrypt operation.
    pub decrypt_result: Box<GpgmeDecryptResult>,
    /// Result storage for the last encrypt operation.
    pub encrypt_result: Box<GpgmeEncryptResult>,
    /// `GnuPG` home directory for this context.
    pub home_dir: CString,
    /// Result storage for the last import operation.
    pub import_result: Box<GpgmeImportResult>,
    /// Status node for the last import operation.
    pub import_status: Box<GpgmeImportStatus>,
    /// Certificates loaded for the current keylist iteration.
    pub keylist_certs: Vec<Cert>,
    /// Active keylist mode flags.
    pub keylist_mode: u32,
    /// Current position within `keylist_certs`.
    pub keylist_pos: usize,
    /// Optional passphrase callback registered by the application.
    pub passphrase_cb: Option<PassphraseCbFn>,
    /// Opaque hook pointer passed to `passphrase_cb`.
    pub passphrase_hook: *mut u8,
    /// Active protocol (always `OpenPGP`).
    pub protocol: u32,
    /// Result storage for the last sign operation.
    pub sign_result: Box<GpgmeSignResult>,
    /// Fingerprints of keys that should sign outgoing messages.
    pub signer_fprs: Vec<String>,
    /// Result storage for the last verify operation.
    pub verify_result: Box<GpgmeVerifyResult>,
}

/// C-ABI alias for [`SqCtx`].
pub type GpgmeCtx = SqCtx;

impl SqCtx {
    /// Allocate and return a new context using the given `GnuPG` home directory.
    pub fn new(home_dir: CString) -> Box<Self> {
        Box::new(Self {
            home_dir,
            keylist_mode: GPGME_KEYLIST_MODE_LOCAL,
            protocol: GPGME_PROTOCOL_OPENPGP,
            passphrase_cb: None,
            passphrase_hook: ptr::null_mut(),
            signer_fprs: Vec::new(),
            verify_result: Box::new(GpgmeVerifyResult {
                signatures: ptr::null_mut(),
                file_name: ptr::null(),
                is_mime: 0,
            }),
            import_result: Box::new(GpgmeImportResult {
                considered: 0,
                no_user_id: 0,
                imported: 0,
                imported_rsa: 0,
                unchanged: 0,
                new_user_ids: 0,
                new_sub_keys: 0,
                new_signatures: 0,
                new_revocations: 0,
                secret_read: 0,
                secret_imported: 0,
                secret_unchanged: 0,
                skipped_new_keys: 0,
                not_imported: 0,
                imports: ptr::null_mut(),
                skipped_v3_keys: 0,
            }),
            import_status: Box::new(GpgmeImportStatus {
                next: ptr::null_mut(),
                fpr: ptr::null(),
                error: 0,
                result: 0,
                status: 0,
            }),
            encrypt_result: Box::new(GpgmeEncryptResult {
                invalid_recipients: ptr::null_mut(),
            }),
            sign_result: Box::new(GpgmeSignResult {
                invalid_signers: ptr::null_mut(),
                signatures: ptr::null_mut(),
            }),
            decrypt_result: Box::new(GpgmeDecryptResult {
                unsupported_algorithm: ptr::null(),
                bitflags: 0,
                recipients: ptr::null_mut(),
                file_name: ptr::null(),
                session_key: ptr::null(),
                symkey_algo: ptr::null(),
            }),
            keylist_certs: Vec::new(),
            keylist_pos: 0,
        })
    }
}
