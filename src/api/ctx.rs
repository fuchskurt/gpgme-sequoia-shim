//! GPGME context management functions.

use alloc::ffi::CString;
use core::ffi::CStr;
use core::ffi::{c_char, c_int, c_uint};
use core::ptr;

use crate::context::{GpgmeCtx, SqCtx};
use crate::error::{GPG_ERR_INV_ENGINE, GPG_ERR_INV_VALUE, GPG_ERR_NO_ERROR, gpg_error, not_impl};
use crate::ffi_types::{GPGME_PROTOCOL_OPENPGP, GpgmeEngineInfo, GpgmeKey, PassphraseCbFn};
use crate::global::{ENGINE_INFO, default_home_dir};
use crate::keyring::free_sig_list;

/// Allocate a new GPGME context and write it into `*r_ctx`.
///
/// # Safety
/// `r_ctx` must be a valid, non-null pointer to a `*mut GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_new(r_ctx: *mut *mut GpgmeCtx) -> u32 {
    // SAFETY: caller guarantees ctx is a valid non-null pointer.
    unsafe {
        if r_ctx.is_null() {
            return gpg_error(GPG_ERR_INV_VALUE);
        }
        *r_ctx = Box::into_raw(SqCtx::new(default_home_dir()));
        GPG_ERR_NO_ERROR
    }
}

/// Release a GPGME context and all associated resources.
///
/// # Safety
/// `ctx` must be either null or a pointer to a valid, heap-allocated `GpgmeCtx`
/// previously returned by `gpgme_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_release(ctx: *mut GpgmeCtx) {
    // SAFETY: caller guarantees `ctx` is a valid, aligned, non-null pointer
    // to a heap-allocated `GpgmeCtx` that is no longer used after this call.
    let Some(mut boxed) = (unsafe { ctx.as_mut() }).map(|ptr| unsafe { Box::from_raw(ptr) }) else {
        return;
    };
    // SAFETY: `signatures` is either null or a valid linked-list allocated by this library.
    unsafe { free_sig_list(boxed.verify_result.signatures) };
    boxed.verify_result.signatures = ptr::null_mut();
}

/// Return the engine info associated with `_ctx` (always the global info).
///
/// # Safety
/// `_ctx` is unused; the returned pointer is valid for the process lifetime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_ctx_get_engine_info(_ctx: *mut GpgmeCtx) -> *mut GpgmeEngineInfo {
    core::ptr::addr_of!(ENGINE_INFO).cast_mut()
}

/// Set the engine info for `proto` on an individual context.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.  `home_dir`, if non-null, must be a
/// valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_ctx_set_engine_info(
    ctx: *mut GpgmeCtx,
    proto: u32,
    _file_name: *const c_char,
    home_dir: *const c_char,
) -> u32 {
    if proto != GPGME_PROTOCOL_OPENPGP {
        return gpg_error(GPG_ERR_INV_ENGINE);
    }
    if !home_dir.is_null() {
        // SAFETY: `home_dir` is non-null and caller guarantees it points
        // to a valid nul-terminated C string that outlives this call.
        let cstr_ref = unsafe { CStr::from_ptr(home_dir) };
        if let Ok(str_ref) = cstr_ref.to_str()
            && let Ok(cstr) = CString::new(str_ref)
            // SAFETY: caller guarantees `ctx` is valid, aligned, and non-null.
            && let Some(ctx_ref) = unsafe { ctx.as_mut() }
        {
            ctx_ref.home_dir = cstr;
        }
    }
    GPG_ERR_NO_ERROR
}

/// No-op locale setter.
///
/// # Safety
/// All arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_locale(
    _ctx: *mut GpgmeCtx,
    _category: c_int,
    _value: *const c_char,
) -> u32 {
    GPG_ERR_NO_ERROR
}

/// Set the active protocol on a context.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_set_protocol(ctx: *mut GpgmeCtx, proto: u32) -> u32 {
    // SAFETY: caller guarantees ctx is a valid non-null pointer.
    unsafe {
        if proto != GPGME_PROTOCOL_OPENPGP {
            return gpg_error(GPG_ERR_INV_ENGINE);
        }
        (*ctx).protocol = proto;
        GPG_ERR_NO_ERROR
    }
}

/// Return the active protocol of a context.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_get_protocol(ctx: *mut GpgmeCtx) -> u32 {
    // SAFETY: caller guarantees ctx is a valid non-null pointer.
    unsafe { (*ctx).protocol }
}

/// No-op sub-protocol setter.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_sub_protocol(_ctx: *mut GpgmeCtx, _proto: u32) -> u32 {
    GPG_ERR_NO_ERROR
}

/// Return 0 (no sub-protocol).
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_sub_protocol(_ctx: *mut GpgmeCtx) -> u32 {
    0
}

/// Return the keylist mode of a context.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_get_keylist_mode(ctx: *mut GpgmeCtx) -> u32 {
    // SAFETY: caller guarantees ctx is a valid non-null pointer.
    unsafe { (*ctx).keylist_mode }
}

/// Set the keylist mode of a context.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_set_keylist_mode(ctx: *mut GpgmeCtx, mode: u32) -> u32 {
    // SAFETY: caller guarantees ctx is a valid non-null pointer.
    unsafe {
        (*ctx).keylist_mode = mode;
        GPG_ERR_NO_ERROR
    }
}

/// No-op armor setter.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_armor(_ctx: *mut GpgmeCtx, _yes: c_int) {}

/// Return 0 (armor not set).
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_armor(_ctx: *mut GpgmeCtx) -> c_int {
    0
}

/// No-op text-mode setter.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_textmode(_ctx: *mut GpgmeCtx, _yes: c_int) {}

/// Return 0 (text mode not set).
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_textmode(_ctx: *mut GpgmeCtx) -> c_int {
    0
}

/// No-op offline setter.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_offline(_ctx: *mut GpgmeCtx, _yes: c_int) {}

/// Return 0 (offline mode not set).
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_offline(_ctx: *mut GpgmeCtx) -> c_int {
    0
}

/// No-op include-certs setter.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_include_certs(_ctx: *mut GpgmeCtx, _nr: c_int) {}

/// Return 0 (default include-certs).
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_include_certs(_ctx: *mut GpgmeCtx) -> c_int {
    0
}

/// No-op pinentry-mode setter.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_pinentry_mode(_ctx: *mut GpgmeCtx, _mode: u32) -> u32 {
    GPG_ERR_NO_ERROR
}

/// Return 0 (default pinentry mode).
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_pinentry_mode(_ctx: *mut GpgmeCtx) -> u32 {
    0
}

/// Register a passphrase callback on a context.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.  `hook` must remain valid for as
/// long as the callback may be invoked.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_set_passphrase_cb(
    ctx: *mut GpgmeCtx,
    cb: Option<PassphraseCbFn>,
    hook: *mut u8,
) {
    // SAFETY: caller guarantees `ctx` is valid, aligned, and non-null.
    let Some(ctx_ref) = (unsafe { ctx.as_mut() }) else {
        return;
    };
    ctx_ref.passphrase_cb = cb;
    ctx_ref.passphrase_hook = hook;
}

/// Retrieve the registered passphrase callback from a context.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.  `cb` and `hook`, if non-null,
/// must point to valid storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_get_passphrase_cb(
    ctx: *mut GpgmeCtx,
    cb: *mut Option<PassphraseCbFn>,
    hook: *mut *mut u8,
) {
    // SAFETY: caller guarantees `ctx` is valid, aligned, and non-null.
    let ctx_ref = unsafe { &*ctx };
    // SAFETY: caller guarantees `cb` is either null or a valid aligned pointer.
    if let Some(out) = unsafe { cb.as_mut() } {
        *out = ctx_ref.passphrase_cb;
    }
    // SAFETY: caller guarantees `hook` is either null or a valid aligned pointer.
    if let Some(out) = unsafe { hook.as_mut() } {
        *out = ctx_ref.passphrase_hook;
    }
}

/// No-op progress callback setter.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_progress_cb(
    _ctx: *mut GpgmeCtx,
    _cb: *mut u8,
    _hook: *mut u8,
) {
}

/// No-op progress callback getter.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_progress_cb(
    _ctx: *mut GpgmeCtx,
    _cb: *mut *mut u8,
    _hook: *mut *mut u8,
) {
}

/// No-op status callback setter.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_status_cb(
    _ctx: *mut GpgmeCtx,
    _cb: *mut u8,
    _hook: *mut u8,
) {
}

/// No-op status callback getter.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_status_cb(
    _ctx: *mut GpgmeCtx,
    _cb: *mut *mut u8,
    _hook: *mut *mut u8,
) {
}

/// No-op I/O callback setter.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_io_cbs(_ctx: *mut GpgmeCtx, _cbs: *mut u8) {}

/// No-op I/O callback getter.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_io_cbs(_ctx: *mut GpgmeCtx, _cbs: *mut u8) {}

/// No-op context flag setter; always returns success.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_ctx_flag(
    _ctx: *mut GpgmeCtx,
    _name: *const c_char,
    _value: *const c_char,
) -> u32 {
    GPG_ERR_NO_ERROR
}

/// Return null (no context flags are implemented).
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_ctx_flag(
    _ctx: *mut GpgmeCtx,
    _name: *const c_char,
) -> *const c_char {
    ptr::null()
}

/// No-op sender setter; always returns success.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_sender(
    _ctx: *mut GpgmeCtx,
    _address: *const c_char,
) -> u32 {
    GPG_ERR_NO_ERROR
}

/// Return null (no sender is stored).
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_sender(_ctx: *mut GpgmeCtx) -> *const c_char {
    ptr::null()
}

/// Clear all registered signers from a context.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_signers_clear(ctx: *mut GpgmeCtx) {
    // SAFETY: caller guarantees ctx is a valid non-null pointer.
    unsafe {
        (*ctx).signer_fprs.clear();
    }
}

/// Add a key's fingerprint to the list of signers for a context.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.  `key` must point to a valid
/// `GpgmeKey` for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_signers_add(ctx: *mut GpgmeCtx, key: *mut GpgmeKey) -> u32 {
    // SAFETY: `key` may be null; `as_ref` handles the null check safely.
    let Some(key_ref) = (unsafe { key.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };

    let fpr = if !key_ref.fpr.is_null() {
        // SAFETY: `key_ref.fpr` is non-null and caller guarantees it is a valid nul-terminated C string.
        unsafe { CStr::from_ptr(key_ref.fpr) }
            .to_string_lossy()
            .to_string()
        // SAFETY: `subkeys` is either null or a valid pointer to a `GpgmeKey` allocated by this library.
    } else if let Some(subkey) = unsafe { key_ref.subkeys.as_ref() }
        && !subkey.fpr.is_null()
    {
        // SAFETY: `subkey.fpr` is non-null and caller guarantees it is a valid nul-terminated C string.
        unsafe { CStr::from_ptr(subkey.fpr) }
            .to_string_lossy()
            .to_string()
    } else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };

    // SAFETY: caller guarantees `ctx` is valid, aligned, and non-null.
    let Some(ctx_ref) = (unsafe { ctx.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    ctx_ref.signer_fprs.push(fpr);
    GPG_ERR_NO_ERROR
}

/// Return the number of registered signers.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_signers_count(ctx: *mut GpgmeCtx) -> c_uint {
    // SAFETY: caller guarantees ctx is a valid non-null pointer.
    unsafe { c_uint::try_from((*ctx).signer_fprs.len()).unwrap_or(c_uint::MAX) }
}

/// Return null (signer enumeration not implemented).
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_signers_enum(
    _ctx: *mut GpgmeCtx,
    _idx: c_int,
) -> *mut GpgmeKey {
    ptr::null_mut()
}

/// No-op signature notation adder; always returns success.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_sig_notation_add(
    _ctx: *mut GpgmeCtx,
    _name: *const c_char,
    _value: *const c_char,
    _flags: u32,
) -> u32 {
    GPG_ERR_NO_ERROR
}

/// No-op signature notation clear.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_sig_notation_clear(_ctx: *mut GpgmeCtx) {}

/// Return null (no notations stored).
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_sig_notation_get(_ctx: *mut GpgmeCtx) -> *mut u8 {
    ptr::null_mut()
}

/// Cancel a pending asynchronous operation; always returns success.
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_cancel(_ctx: *mut GpgmeCtx) -> u32 {
    GPG_ERR_NO_ERROR
}

/// Cancel a pending asynchronous operation (async variant); always returns success.
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_cancel_async(_ctx: *mut GpgmeCtx) -> u32 {
    GPG_ERR_NO_ERROR
}

/// Wait for a pending operation; always returns null (synchronous-only implementation).
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_wait(
    _ctx: *mut GpgmeCtx,
    _status: *mut u32,
    _hang: c_int,
) -> *mut GpgmeCtx {
    ptr::null_mut()
}

/// Extended wait; always returns "not implemented".
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_wait_ext(
    _ctx: *mut GpgmeCtx,
    _r_ctx: *mut *mut GpgmeCtx,
    _status: *mut u32,
    _hang: c_int,
) -> u32 {
    not_impl()
}

/// No-op global flag setter; always returns 0.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_set_global_flag(
    _name: *const c_char,
    _value: *const c_char,
) -> c_int {
    0
}
