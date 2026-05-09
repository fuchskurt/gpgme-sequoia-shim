//! Key-retrieval and keylist functions.

use core::ffi::CStr;
use core::ffi::{c_char, c_int};
use core::ptr;

use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::parse::Parse as _;

use crate::context::GpgmeCtx;
use crate::data::GpgmeData;
use crate::error::{GPG_ERR_EOF, GPG_ERR_INV_VALUE, GPG_ERR_NO_ERROR, gpg_error, not_impl};
use crate::ffi_types::GpgmeKey;
use crate::keyring::{cert_to_key, free_key, load_certs};

/// Look up a key by fingerprint or key-ID and write it into `*r_key`.
///
/// # Safety
/// `ctx` and `r_key` must be valid, non-null pointers.  `fpr` must be a
/// valid, null-terminated C string.  `_secret` is unused.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_get_key(
    ctx: *mut GpgmeCtx,
    fpr: *const c_char,
    r_key: *mut *mut GpgmeKey,
    _secret: c_int,
) -> u32 {
    // SAFETY: `r_key` may be null; `as_mut` handles the null check safely.
    let Some(out) = (unsafe { r_key.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    *out = ptr::null_mut();

    if fpr.is_null() {
        return gpg_error(GPG_ERR_INV_VALUE);
    }
    // SAFETY: `fpr` is non-null and caller guarantees it is a valid nul-terminated C string.
    let fpr_upper = match unsafe { CStr::from_ptr(fpr) }.to_str() {
        Ok(str_ref) => str_ref.to_uppercase(),
        Err(_) => return gpg_error(GPG_ERR_INV_VALUE),
    };

    // SAFETY: caller guarantees `ctx` is valid, aligned, and non-null.
    let Some(ctx_ref) = (unsafe { ctx.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    let certs = load_certs(&ctx_ref.home_dir.to_string_lossy());
    certs
        .iter()
        .find(|cert| {
            cert.keys().any(|key| {
                key.key().fingerprint().to_hex().ends_with(&fpr_upper)
                    || key.key().keyid().to_hex().ends_with(&fpr_upper)
            })
        })
        .map_or_else(
            || gpg_error(GPG_ERR_EOF),
            |cert| {
                *out = cert_to_key(cert);
                GPG_ERR_NO_ERROR
            },
        )
}

/// Increment the reference count of a key.
///
/// # Safety
/// `key` must be either null or a valid `GpgmeKey`.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_key_ref(key: *mut GpgmeKey) {
    // SAFETY: `key` may be null; `as_mut` handles the null check safely.
    if let Some(key_ref) = unsafe { key.as_mut() } {
        key_ref.refs = key_ref.refs.saturating_add(1);
    }
}

/// Decrement the reference count of a key, freeing it when it reaches zero.
///
/// # Safety
/// `key` must be either null or a valid, heap-allocated `GpgmeKey`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_key_unref(key: *mut GpgmeKey) {
    // SAFETY: `key` may be null; `as_mut` handles the null check safely.
    let should_free = if let Some(key_ref) = unsafe { key.as_mut() } {
        key_ref.refs = key_ref.refs.saturating_sub(1);
        key_ref.refs == 0
    } else {
        false
    };
    if should_free {
        // SAFETY: `key` is non-null and caller guarantees it was heap-allocated by this library.
        unsafe { free_key(key) };
    }
}

/// Release a key (decrement its reference count).
///
/// # Safety
/// `key` must be either null or a valid, heap-allocated `GpgmeKey`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_key_release(key: *mut GpgmeKey) {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_key_unref(key) }
}

/// Not implemented: construct a key from a UID string.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_key_from_uid(
    _r_key: *mut *mut GpgmeKey,
    _uid: *const c_char,
) -> u32 {
    not_impl()
}

/// Not implemented: retrieve the key that made a specific signature.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_sig_key(
    _ctx: *mut GpgmeCtx,
    _idx: c_int,
    _r_key: *mut *mut GpgmeKey,
) -> u32 {
    not_impl()
}

/// Return null (deprecated signature-status API not implemented).
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_sig_status(
    _ctx: *mut GpgmeCtx,
    _idx: c_int,
    _r_stat: *mut u32,
    _r_created: *mut libc::time_t,
) -> *const c_char {
    ptr::null()
}

/// Start a keylist iteration.
///
/// Loads all certs matching `pattern` (if any) into the context.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.  `pattern`, if non-null, must be a
/// valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_keylist_start(
    ctx: *mut GpgmeCtx,
    pattern: *const c_char,
    _secret: c_int,
) -> u32 {
    // SAFETY: caller guarantees `ctx` is valid, aligned, and non-null.
    let Some(ctx_ref) = (unsafe { ctx.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    let home = ctx_ref.home_dir.to_string_lossy().to_string();
    let mut certs = load_certs(&home);
    if !pattern.is_null() {
        // SAFETY: `pattern` is non-null and caller guarantees it is a valid nul-terminated C string.
        if let Ok(pat) = unsafe { CStr::from_ptr(pattern) }.to_str() {
            let pat_upper = pat.to_uppercase();
            certs.retain(|cert| {
                cert.keys().any(|key| {
                    key.key().fingerprint().to_hex().contains(&pat_upper)
                        || key.key().keyid().to_hex().contains(&pat_upper)
                }) || cert.userids().any(|uid| {
                    String::from_utf8_lossy(uid.component().value())
                        .to_uppercase()
                        .contains(&pat_upper)
                })
            });
        }
    }
    ctx_ref.keylist_certs = certs;
    ctx_ref.keylist_pos = 0;
    GPG_ERR_NO_ERROR
}

/// Start a keylist iteration with multiple patterns (delegates to single-pattern variant).
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_keylist_ext_start(
    ctx: *mut GpgmeCtx,
    _patterns: *mut *const c_char,
    _secret: c_int,
    _reserved: c_int,
) -> u32 {
    // SAFETY: caller upholds the same preconditions as gpgme_op_keylist_start.
    unsafe { gpgme_op_keylist_start(ctx, ptr::null(), 0) }
}

/// Start a keylist from an in-memory data object.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.  `data` must point to a valid
/// `GpgmeData`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_keylist_from_data_start(
    ctx: *mut GpgmeCtx,
    data: *mut GpgmeData,
    _reserved: c_int,
) -> u32 {
    // SAFETY: caller guarantees `ctx` is valid, aligned, and non-null.
    let Some(ctx_ref) = (unsafe { ctx.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `data` may be null; `as_ref` handles the null check safely.
    let Some(data_ref) = (unsafe { data.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    ctx_ref.keylist_certs = CertParser::from_bytes(&data_ref.buf)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .collect();
    ctx_ref.keylist_pos = 0;
    GPG_ERR_NO_ERROR
}

/// Return the next key from the keylist iteration.
///
/// Writes a heap-allocated `GpgmeKey` into `*r_key`.  Returns
/// `GPG_ERR_EOF` when the list is exhausted.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.  `r_key` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_keylist_next(
    ctx: *mut GpgmeCtx,
    r_key: *mut *mut GpgmeKey,
) -> u32 {
    // SAFETY: caller guarantees `ctx` is valid, aligned, and non-null.
    let ctx_ref = unsafe { &mut *ctx };

    if let Some(cert) = ctx_ref.keylist_certs.get(ctx_ref.keylist_pos) {
        // SAFETY: caller guarantees `r_key` is valid, aligned, and non-null.
        unsafe { *r_key = cert_to_key(cert) };
        ctx_ref.keylist_pos = ctx_ref.keylist_pos.saturating_add(1);
        GPG_ERR_NO_ERROR
    } else {
        // SAFETY: caller guarantees `r_key` is valid, aligned, and non-null.
        unsafe { *r_key = ptr::null_mut() };
        gpg_error(GPG_ERR_EOF)
    }
}

/// End the keylist iteration and release associated resources.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_keylist_end(ctx: *mut GpgmeCtx) -> u32 {
    // SAFETY: caller guarantees `ctx` is valid, aligned, and non-null.
    let Some(ctx_ref) = (unsafe { ctx.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    ctx_ref.keylist_certs.clear();
    ctx_ref.keylist_pos = 0;
    GPG_ERR_NO_ERROR
}

/// Return null (keylist result not stored).
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_keylist_result(_ctx: *mut GpgmeCtx) -> *mut u8 {
    ptr::null_mut()
}

/// Not implemented: start fetching multiple keys by fingerprint array.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_keys_start(
    _ctx: *mut GpgmeCtx,
    _fprs: *mut *const c_char,
    _secret: c_int,
) -> u32 {
    not_impl()
}

/// Not implemented: fetch next key.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_keys_next(
    _ctx: *mut GpgmeCtx,
    _r_key: *mut *mut GpgmeKey,
) -> u32 {
    not_impl()
}

/// No-op end of `gpgme_get_keys_*` iteration; always returns success.
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_keys_end(_ctx: *mut GpgmeCtx) -> u32 {
    GPG_ERR_NO_ERROR
}
