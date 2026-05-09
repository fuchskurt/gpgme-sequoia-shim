//! C-ABI struct layouts and type aliases, verified against gpgme.h 2.0 on x86_64.

use core::ffi::{c_char, c_int};

use crate::error::GpgmeError;

// ── GPGME constants ────────────────────────────────────────────────────────────

/// Validity level: unknown.
pub const GPGME_VALIDITY_UNKNOWN: u32 = 0;
/// Validity level: full.
pub const GPGME_VALIDITY_FULL: u32 = 4;
/// Signature summary flag: signature is valid.
pub const GPGME_SIGSUM_VALID: u32 = 0x0001;
/// Signature summary flag: green (good) signature.
pub const GPGME_SIGSUM_GREEN: u32 = 0x0002;
/// Signature summary flag: red (bad) signature.
pub const GPGME_SIGSUM_RED: u32 = 0x0004;
/// Signature summary flag: signing key is missing.
pub const GPGME_SIGSUM_KEY_MISSING: u32 = 0x0080;
/// Keylist mode flag: use the local keyring.
pub const GPGME_KEYLIST_MODE_LOCAL: u32 = 0x0001;
/// Protocol identifier for `OpenPGP`.
pub const GPGME_PROTOCOL_OPENPGP: u32 = 0;
/// Data encoding: no specific encoding (binary).
pub const GPGME_DATA_ENCODING_NONE: u32 = 0;
/// Signature mode: normal (inline) signature.
pub const GPGME_SIG_MODE_NORMAL: u32 = 0;
/// Signature mode: detached signature.
pub const GPGME_SIG_MODE_DETACH: u32 = 1;
/// Signature mode: cleartext signature.
pub const GPGME_SIG_MODE_CLEAR: u32 = 2;

// ── Seek whence constants ──────────────────────────────────────────────────────

/// Seek from the beginning of the buffer.
pub const SEEK_SET: c_int = 0;
/// Seek relative to the current position.
pub const SEEK_CUR: c_int = 1;
/// Seek relative to the end of the buffer.
pub const SEEK_END: c_int = 2;

// ── C-ABI structs ─────────────────────────────────────────────────────────────

/// A single signature result as returned by GPGME.
#[repr(C)]
pub struct GpgmeSig {
    /// Pointer to the next signature in the linked list.
    pub next: *mut Self,
    /// Bitmask of `GPGME_SIGSUM_*` flags.
    pub summary: u32,
    /// Hex fingerprint of the signing key, or null.
    pub fpr: *const c_char,
    /// Error code for this signature.
    pub status: u32,
    /// Unused notation list (always null in this implementation).
    pub notations: *mut u8,
    /// Creation timestamp (Unix seconds).
    pub timestamp: u64,
    /// Expiry timestamp (Unix seconds, 0 = no expiry).
    pub exp_timestamp: u64,
    /// Packed bit-flags (reserved).
    pub bitflags: u32,
    /// Validity level (`GPGME_VALIDITY_*`).
    pub validity: u32,
    /// Reason code for the validity level.
    pub validity_reason: u32,
    /// Public-key algorithm identifier.
    pub pubkey_algo: u32,
    /// Hash algorithm identifier.
    pub hash_algo: u32,
    /// PKA address string (unused, always null).
    pub pka_address: *const c_char,
    /// Associated key object (unused, always null).
    pub key: *mut u8,
}

/// Aggregate result of a verify operation.
#[repr(C)]
pub struct GpgmeVerifyResult {
    /// Linked list of per-signature results.
    pub signatures: *mut GpgmeSig,
    /// File name embedded in the message (unused).
    pub file_name: *const c_char,
    /// Non-zero if the message is MIME (unused).
    pub is_mime: u32,
}

/// Status entry for a single imported key.
#[repr(C)]
pub struct GpgmeImportStatus {
    /// Pointer to the next status entry.
    pub next: *mut Self,
    /// Fingerprint of the imported key.
    pub fpr: *const c_char,
    /// Per-key error code.
    pub error: u32,
    /// Import result code.
    pub result: u32,
    /// Import status flags.
    pub status: u32,
}

/// Aggregate result of an import operation.
#[repr(C)]
pub struct GpgmeImportResult {
    /// Total number of keys considered.
    pub considered: c_int,
    /// Keys without a user ID.
    pub no_user_id: c_int,
    /// Number of newly imported keys.
    pub imported: c_int,
    /// Number of newly imported RSA keys.
    pub imported_rsa: c_int,
    /// Number of unchanged keys.
    pub unchanged: c_int,
    /// New user IDs added.
    pub new_user_ids: c_int,
    /// New subkeys added.
    pub new_sub_keys: c_int,
    /// New signatures added.
    pub new_signatures: c_int,
    /// New revocations added.
    pub new_revocations: c_int,
    /// Secret keys read.
    pub secret_read: c_int,
    /// Secret keys imported.
    pub secret_imported: c_int,
    /// Unchanged secret keys.
    pub secret_unchanged: c_int,
    /// New keys skipped.
    pub skipped_new_keys: c_int,
    /// Keys not imported.
    pub not_imported: c_int,
    /// Linked list of per-key import status entries.
    pub imports: *mut GpgmeImportStatus,
    /// V3 keys skipped.
    pub skipped_v3_keys: c_int,
}

/// Result of an encrypt operation.
#[repr(C)]
pub struct GpgmeEncryptResult {
    /// List of invalid recipients (always null in this implementation).
    pub invalid_recipients: *mut u8,
}

/// Result of a sign operation.
#[repr(C)]
pub struct GpgmeSignResult {
    /// List of invalid signers (always null in this implementation).
    pub invalid_signers: *mut u8,
    /// List of created signatures (always null in this implementation).
    pub signatures: *mut u8,
}

/// Result of a decrypt operation.
#[repr(C)]
pub struct GpgmeDecryptResult {
    /// Unsupported algorithm string (always null in this implementation).
    pub unsupported_algorithm: *const c_char,
    /// Packed bit-flags.
    pub bitflags: u32,
    /// List of recipient information (always null in this implementation).
    pub recipients: *mut u8,
    /// File name embedded in the message (always null).
    pub file_name: *const c_char,
    /// Session key string (always null).
    pub session_key: *const c_char,
    /// Symmetric-key algorithm string (always null).
    pub symkey_algo: *const c_char,
}

/// Information about a crypto engine available to GPGME.
#[repr(C)]
pub struct GpgmeEngineInfo {
    /// Pointer to the next engine info entry.
    pub next: *mut Self,
    /// Protocol this engine implements.
    pub protocol: u32,
    /// Path to the engine executable.
    pub file_name: *const c_char,
    /// Engine version string.
    pub version: *const c_char,
    /// Minimum required engine version.
    pub req_version: *const c_char,
    /// `GnuPG` home directory used by the engine.
    pub home_dir: *const c_char,
}

// SAFETY: GpgmeEngineInfo holds raw pointers to static string literals that
// never move and are valid for the lifetime of the process.
unsafe impl Sync for GpgmeEngineInfo {}
// SAFETY: same reasoning as Sync.
unsafe impl Send for GpgmeEngineInfo {}

/// A single subkey (primary key or subkey) as presented through the GPGME ABI.
#[repr(C)]
pub struct GpgmeSubkey {
    /// Pointer to the next subkey in the linked list.
    pub next: *mut Self,
    /// Packed bit-flags (revoked, expired, disabled, …).
    pub bitflags: u32,
    /// Public-key algorithm identifier.
    pub pubkey_algo: u32,
    /// Key length in bits.
    pub length: u32,
    /// Hex key-ID string.
    pub keyid: *const c_char,
    /// Hex fingerprint string.
    pub fpr: *const c_char,
    /// Creation timestamp (Unix seconds).
    pub timestamp: i64,
    /// Expiry timestamp (Unix seconds, 0 = no expiry).
    pub expires: i64,
    /// Smart-card serial number (unused, always null).
    pub card_number: *const c_char,
    /// Elliptic-curve name (unused, always null).
    pub curve: *const c_char,
    /// Key-grip hex string (unused, always null).
    pub keygrip: *const c_char,
}

/// A user ID packet as presented through the GPGME ABI.
#[repr(C)]
pub struct GpgmeUserId {
    /// Pointer to the next user ID in the linked list.
    pub next: *mut Self,
    /// Packed bit-flags (revoked, invalid, …).
    pub bitflags: u32,
    /// Validity level of this user ID.
    pub validity: u32,
    /// Raw user-ID string.
    pub uid: *const c_char,
    /// Name component.
    pub name: *const c_char,
    /// E-mail component.
    pub email: *const c_char,
    /// Comment component.
    pub comment: *const c_char,
    /// Certification signatures (unused, always null).
    pub signatures: *mut u8,
    /// Last certification signature (private, always null).
    pub _last_keysig: *mut u8,
    /// Mailbox address (unused, always null).
    pub address: *const c_char,
    /// TOFU information (unused, always null).
    pub tofu: *mut u8,
    /// Timestamp of the last update.
    pub last_update: u64,
    /// UID hash string (unused, always null).
    pub uidhash: *const c_char,
}

/// A key (certificate) as presented through the GPGME ABI.
#[repr(C)]
pub struct GpgmeKey {
    /// Reference count (freed when it drops to zero).
    pub refs: u32,
    /// Packed bit-flags (revoked, expired, disabled, invalid, can-*, …).
    pub bitflags: u32,
    /// Protocol this key belongs to.
    pub protocol: u32,
    /// Issuer serial (X.509 only, always null here).
    pub issuer_serial: *const c_char,
    /// Issuer name (X.509 only, always null here).
    pub issuer_name: *const c_char,
    /// Chain ID (X.509 only, always null here).
    pub chain_id: *const c_char,
    /// Owner trust level.
    pub owner_trust: u32,
    /// Linked list of subkeys.
    pub subkeys: *mut GpgmeSubkey,
    /// Linked list of user IDs.
    pub uids: *mut GpgmeUserId,
    /// Private: pointer to last subkey (for append operations).
    pub _last_subkey: *mut GpgmeSubkey,
    /// Private: pointer to last user ID (for append operations).
    pub _last_uid: *mut GpgmeUserId,
    /// Keylist mode in effect when this key was retrieved.
    pub keylist_mode: u32,
    /// Hex fingerprint of the primary key.
    pub fpr: *const c_char,
    /// Timestamp of the last key-server update.
    pub last_update: u64,
}

/// Callback type invoked by GPGME to obtain a passphrase from the application.
///
/// # Safety
/// The caller must guarantee that `hook`, `uid_hint`, and `passphrase_info` remain
/// valid for the duration of the call, and that `fd` is a writable file descriptor.
pub type PassphraseCbFn = unsafe extern "C" fn(
    hook: *mut u8,
    uid_hint: *const c_char,
    passphrase_info: *const c_char,
    prev_was_bad: c_int,
    fd: c_int,
) -> GpgmeError;
