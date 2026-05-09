//! gpgme-sq: complete GPGME 2.x C ABI in Rust, backed by Sequoia-PGP 2.x.
//!
//! This crate is a `cdylib` that exports every symbol required by the GPGME 2.x
//! C ABI so that pacman (and other GPGME consumers) can link against it without
//! requiring a full `GnuPG` installation, delegating all cryptographic work to
//! Sequoia-PGP.

// ── Lint configuration ────────────────────────────────────────────────────────

// C FFI requires non-idiomatic names in many places.
#![expect(
    // Formatting choice
    clippy::semicolon_inside_block,
    // Crypto helper functions intentionally share their module's name prefix.
    clippy::module_name_repetitions,
    // Optional trait methods (`inspect`, etc.) are not relevant to this impl.
    clippy::missing_trait_methods,
    // // Multiple unsafe ops per block are grouped intentionally for readability in FFI.
    // clippy::multiple_unsafe_ops_per_block,
    reason = "Unavoidable in stable-Rust C FFI code"
)]

// Allow use of alloc crate for CString (which lives in alloc::ffi).
extern crate alloc;

// ── Module declarations (alphabetical) ────────────────────────────────────────

/// Exported C-ABI functions.
pub(crate) mod api;
/// GPGME context object.
pub(crate) mod context;
/// Cryptographic operations (verify, encrypt, sign, decrypt).
pub(crate) mod crypto;
/// In-memory data buffer.
pub(crate) mod data;
/// Error codes and helper constructors.
pub(crate) mod error;
/// C-ABI struct layouts, type aliases, and GPGME constants.
pub(crate) mod ffi_types;
/// Process-global state (engine info, home directory).
pub(crate) mod global;
/// Key-generation helper.
pub(crate) mod keygen;
/// Keyring loading and certificate utilities.
pub(crate) mod keyring;

// ── Note on symbol export ─────────────────────────────────────────────────────
//
// All `#[unsafe(no_mangle)] pub unsafe extern "C"` functions are exported from
// the cdylib automatically by the linker; no explicit re-export is needed here.
