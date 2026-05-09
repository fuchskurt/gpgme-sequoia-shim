//! Key import and export functions.

use core::ffi::CStr;
use core::ffi::{c_char, c_int};
use core::ptr;
use std::io::Write as _;
use std::process::{Command, Stdio};

use sequoia_openpgp::serialize::Serialize as _;

use crate::context::GpgmeCtx;
use crate::data::GpgmeData;
use crate::error::{GPG_ERR_INV_VALUE, GPG_ERR_NO_ERROR, gpg_error, not_impl};
use crate::ffi_types::{GpgmeImportResult, GpgmeKey};
use crate::keyring::load_certs;

/// Import key material from `keydata` into the local keyring.
///
/// # Safety
/// `ctx` and `keydata` must be valid, non-null pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_import(ctx: *mut GpgmeCtx, keydata: *mut GpgmeData) -> u32 {
    // SAFETY: `ctx` may be null; `as_mut` handles the null check safely.
    let Some(ctx_ref) = (unsafe { ctx.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `keydata` may be null; `as_ref` handles the null check safely.
    let Some(keydata_ref) = (unsafe { keydata.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };

    let home = ctx_ref.home_dir.to_string_lossy().to_string();
    let bytes = keydata_ref.buf.clone();
    let success = Command::new("/usr/bin/gpg-sq")
        .args(["--homedir", &home, "--batch", "--no-tty", "--import"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut child| {
            if let Some(mut stdin) = child.stdin.take()
                && let Err(err) = stdin.write_all(&bytes)
            {
                return Err(err);
            }
            child.wait()
        })
        .is_ok_and(|status| status.success());

    ctx_ref.import_result.considered = 1_i32;
    ctx_ref.import_result.imported = c_int::from(success);
    ctx_ref.import_result.imports = &raw mut *ctx_ref.import_status;
    ctx_ref.import_status.result = GPG_ERR_NO_ERROR;
    ctx_ref.import_status.next = ptr::null_mut();
    GPG_ERR_NO_ERROR
}

/// Asynchronous variant of `gpgme_op_import`.
///
/// # Safety
/// Same requirements as `gpgme_op_import`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_import_start(ctx: *mut GpgmeCtx, data: *mut GpgmeData) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_op_import(ctx, data) }
}

/// Extended import with an extra (ignored) counter parameter.
///
/// # Safety
/// Same requirements as `gpgme_op_import`.  `_nr` is unused.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_import_ext(
    ctx: *mut GpgmeCtx,
    data: *mut GpgmeData,
    _nr: *mut c_int,
) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_op_import(ctx, data) }
}

/// Return a pointer to the import result stored in `ctx`.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_import_result(ctx: *mut GpgmeCtx) -> *mut GpgmeImportResult {
    // SAFETY: caller guarantees ctx is a valid non-null pointer.
    unsafe { &raw mut *(*ctx).import_result }
}

/// Import keys from a null-terminated array of `GpgmeKey` pointers by receiving them.
///
/// # Safety
/// `ctx` and `keys` must be valid, non-null pointers.  `*keys` must be a valid
/// `GpgmeKey`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_import_keys(ctx: *mut GpgmeCtx, keys: *mut *mut GpgmeKey) -> u32 {
    // SAFETY: `ctx` may be null; `as_mut` handles the null check safely.
    let Some(ctx_ref) = (unsafe { ctx.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `keys` may be null; `as_ref` handles the null check safely.
    let Some(keys_ref) = (unsafe { keys.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `*keys` may be null; `as_ref` handles the null check safely.
    let Some(key) = (unsafe { keys_ref.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `key.subkeys` may be null; `as_ref` handles the null check safely.
    let Some(subkey) = (unsafe { key.subkeys.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };

    let fpr = if !subkey.fpr.is_null() {
        // SAFETY: `subkey.fpr` is non-null and caller guarantees it is a valid nul-terminated C string.
        unsafe { CStr::from_ptr(subkey.fpr) }
            .to_string_lossy()
            .to_string()
    } else if !subkey.keyid.is_null() {
        // SAFETY: `subkey.keyid` is non-null and caller guarantees it is a valid nul-terminated C string.
        unsafe { CStr::from_ptr(subkey.keyid) }
            .to_string_lossy()
            .to_string()
    } else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };

    let home = ctx_ref.home_dir.to_string_lossy().to_string();
    drop(
        Command::new("/usr/bin/gpg-sq")
            .args([
                "--homedir",
                &home,
                "--batch",
                "--no-tty",
                "--recv-keys",
                &fpr,
            ])
            .output(),
    );
    ctx_ref.import_result.considered = 1_i32;
    ctx_ref.import_result.imported = 1_i32;
    ctx_ref.import_result.imports = &raw mut *ctx_ref.import_status;
    ctx_ref.import_status.result = GPG_ERR_NO_ERROR;
    ctx_ref.import_status.next = ptr::null_mut();
    GPG_ERR_NO_ERROR
}

/// Asynchronous variant of `gpgme_op_import_keys`.
///
/// # Safety
/// Same requirements as `gpgme_op_import_keys`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_import_keys_start(
    ctx: *mut GpgmeCtx,
    keys: *mut *mut GpgmeKey,
) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_op_import_keys(ctx, keys) }
}

/// Export keys matching `pattern` into `keydata`.
///
/// # Safety
/// `ctx` must be a valid, non-null pointer.  `pattern`, if non-null, must be a
/// valid null-terminated C string.  `keydata`, if non-null, must point to a
/// valid `GpgmeData`.  `_mode` is unused.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_export(
    ctx: *mut GpgmeCtx,
    pattern: *const c_char,
    _mode: u32,
    keydata: *mut GpgmeData,
) -> u32 {
    // SAFETY: `ctx` may be null; `as_ref` handles the null check safely.
    let Some(ctx_ref) = (unsafe { ctx.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    let home = ctx_ref.home_dir.to_string_lossy().to_string();

    let pat = if pattern.is_null() {
        String::new()
    } else {
        // SAFETY: `pattern` is non-null and caller guarantees it is a valid nul-terminated C string.
        unsafe { CStr::from_ptr(pattern) }
            .to_string_lossy()
            .to_string()
    };

    let certs = load_certs(&home);
    let matching: Vec<_> = if pat.is_empty() {
        certs.iter().collect()
    } else {
        let pat_upper = pat.to_uppercase();
        certs
            .iter()
            .filter(|cert| cert.fingerprint().to_hex().contains(&pat_upper))
            .collect()
    };

    // SAFETY: `keydata` may be null; `as_mut` handles the null check safely.
    if let Some(keydata_ref) = unsafe { keydata.as_mut() } {
        let mut out = Vec::new();
        for cert in matching {
            drop(cert.serialize(&mut out));
        }
        keydata_ref.buf = out;
        keydata_ref.pos = 0;
    }

    GPG_ERR_NO_ERROR
}

/// Asynchronous variant of `gpgme_op_export`.
///
/// # Safety
/// Same requirements as `gpgme_op_export`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_export_start(
    ctx: *mut GpgmeCtx,
    pattern: *const c_char,
    mode: u32,
    data: *mut GpgmeData,
) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_op_export(ctx, pattern, mode, data) }
}

/// Not implemented: extended export.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_export_ext(
    _ctx: *mut GpgmeCtx,
    _patterns: *mut *const c_char,
    _mode: u32,
    _keydata: *mut GpgmeData,
) -> u32 {
    not_impl()
}

/// Not implemented: extended export (async).
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_export_ext_start(
    _ctx: *mut GpgmeCtx,
    _patterns: *mut *const c_char,
    _mode: u32,
    _keydata: *mut GpgmeData,
) -> u32 {
    not_impl()
}

/// Not implemented: export a set of keys by pointer array.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_export_keys(
    _ctx: *mut GpgmeCtx,
    _keys: *mut *mut GpgmeKey,
    _mode: u32,
    _keydata: *mut GpgmeData,
) -> u32 {
    not_impl()
}

/// Not implemented: export keys by pointer array (async).
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_export_keys_start(
    _ctx: *mut GpgmeCtx,
    _keys: *mut *mut GpgmeKey,
    _mode: u32,
    _keydata: *mut GpgmeData,
) -> u32 {
    not_impl()
}
