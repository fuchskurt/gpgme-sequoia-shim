//! GPGME error codes and helper functions.

/// No error occurred.
pub const GPG_ERR_NO_ERROR: u32 = 0;
/// End-of-file sentinel.
pub const GPG_ERR_EOF: u32 = 16383;
/// No public key found.
pub const GPG_ERR_NO_PUBKEY: u32 = 7;
/// Bad signature.
pub const GPG_ERR_BAD_SIGNATURE: u32 = 8;
/// Invalid value supplied to function.
pub const GPG_ERR_INV_VALUE: u32 = 55;
/// Invalid crypto engine.
pub const GPG_ERR_INV_ENGINE: u32 = 108;
/// Feature not implemented.
pub const GPG_ERR_NOT_IMPLEMENTED: u32 = 69;
/// No secret key found.
pub const GPG_ERR_NO_SECKEY: u32 = 17;
/// Error source identifier for GPGME (13 in the source field).
pub const GPG_ERR_SOURCE_GPGME: u32 = 13;
/// The GPGME error type: a 32-bit packed `(source << 24) | code` value.
pub type GpgmeError = u32;

/// Pack an error code into a full GPGME error value with the GPGME source tag.
///
/// A zero code is returned unchanged so that `GPG_ERR_NO_ERROR` remains 0.
#[inline]
pub const fn gpg_error(code: u32) -> GpgmeError {
    if code == 0 {
        0
    } else {
        GPG_ERR_SOURCE_GPGME.wrapping_shl(24) | (code & 0xFFFF)
    }
}

/// Return a "not implemented" GPGME error value.
#[inline]
pub const fn not_impl() -> GpgmeError {
    gpg_error(GPG_ERR_NOT_IMPLEMENTED)
}
