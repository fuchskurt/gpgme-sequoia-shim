//! Crypto operation functions: verify, encrypt, sign, decrypt, and key generation.

use alloc::ffi::CString;
use core::ffi::CStr;
use core::ffi::{c_char, c_ulong};
use core::ptr;

use crate::context::GpgmeCtx;
use crate::crypto::decrypt::decrypt_sq;
use crate::crypto::encrypt::encrypt_sq;
use crate::crypto::sign::sign_sq;
use crate::crypto::verify::SigRecord;
use crate::crypto::verify::verify_sq;
use crate::data::GpgmeData;
use crate::error::{
    GPG_ERR_INV_VALUE, GPG_ERR_NO_ERROR, GPG_ERR_NO_PUBKEY, GPG_ERR_NO_SECKEY, gpg_error, not_impl,
};
use crate::ffi_types::{
    GPGME_SIG_MODE_NORMAL, GPGME_SIGSUM_VALID, GPGME_VALIDITY_FULL, GpgmeDecryptResult,
    GpgmeEncryptResult, GpgmeKey, GpgmeSig, GpgmeSignResult, GpgmeVerifyResult,
};
use crate::keygen::genkey_sq;
use crate::keyring::{collect_recipient_fprs, extract_parm, free_sig_list, load_certs};

// ─── Verify ───────────────────────────────────────────────────────────────────

/// Verify a detached signature and store the result in `ctx`.
///
/// # Safety
/// `ctx`, `sig`, and `signed_text` must all be valid, non-null pointers.
/// `_plain_text` is unused.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_verify(
    ctx: *mut GpgmeCtx,
    sig: *mut GpgmeData,
    signed_text: *mut GpgmeData,
    _plain_text: *mut GpgmeData,
) -> u32 {
    // SAFETY: `ctx` may be null; `as_mut` handles the null check safely.
    let Some(ctx_ref) = (unsafe { ctx.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `sig` may be null; `as_ref` handles the null check safely.
    let Some(sig_ref) = (unsafe { sig.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `signed_text` may be null; `as_ref` handles the null check safely.
    let Some(signed_text_ref) = (unsafe { signed_text.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };

    // SAFETY: `signatures` is either null or a valid linked-list allocated by this library.
    unsafe { free_sig_list(ctx_ref.verify_result.signatures) };
    ctx_ref.verify_result.signatures = ptr::null_mut();

    let home = ctx_ref.home_dir.to_string_lossy().to_string();
    let mut records = verify_sq(&home, &sig_ref.buf, &signed_text_ref.buf);

    // Upgrade validity for keys actually present in the local keyring.
    if records
        .iter()
        .any(|rec| rec.status == GPG_ERR_NO_ERROR && rec.validity < GPGME_VALIDITY_FULL)
    {
        let certs = load_certs(&home);
        for rec in &mut records {
            if rec.status != GPG_ERR_NO_ERROR || rec.validity >= GPGME_VALIDITY_FULL {
                continue;
            }
            let in_keyring = rec.fpr.as_ref().is_some_and(|fpr| {
                let fpr_upper = fpr.to_uppercase();
                certs.iter().any(|cert| {
                    cert.keys()
                        .any(|key| key.key().fingerprint().to_hex() == fpr_upper)
                })
            });
            if in_keyring {
                rec.validity = GPGME_VALIDITY_FULL;
                rec.summary |= GPGME_SIGSUM_VALID;
            }
        }
    }

    // SAFETY: `build_sig_list` allocates a linked list of raw pointers owned by `ctx_ref`.
    ctx_ref.verify_result.signatures = unsafe { build_sig_list(&records) };
    GPG_ERR_NO_ERROR
}
/// Return a pointer to the verify result stored in `ctx`.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_verify_result(ctx: *mut GpgmeCtx) -> *mut GpgmeVerifyResult {
    // SAFETY: caller guarantees ctx points to a valid GpgmeCtx.
    unsafe { &raw mut *(*ctx).verify_result }
}

/// Asynchronous variant of `gpgme_op_verify` (delegates to the synchronous version).
///
/// # Safety
/// Same requirements as `gpgme_op_verify`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_verify_start(
    ctx: *mut GpgmeCtx,
    sig: *mut GpgmeData,
    signed_text: *mut GpgmeData,
    plain: *mut GpgmeData,
) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_op_verify(ctx, sig, signed_text, plain) }
}

/// Not implemented: extended verify.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_verify_ext(
    _ctx: *mut GpgmeCtx,
    _sig: *mut GpgmeData,
    _signed_text: *mut GpgmeData,
    _plain: *mut GpgmeData,
    _flags: u32,
) -> u32 {
    not_impl()
}

/// Not implemented: extended verify (async).
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_verify_ext_start(
    _ctx: *mut GpgmeCtx,
    _sig: *mut GpgmeData,
    _signed_text: *mut GpgmeData,
    _plain: *mut GpgmeData,
    _flags: u32,
) -> u32 {
    not_impl()
}

// ─── Encrypt ──────────────────────────────────────────────────────────────────

/// Encrypt `plain` for `keys` and write the result into `cipher`.
///
/// # Safety
/// `ctx`, `plain`, and `cipher` must be valid, non-null pointers.  `keys` may
/// be null (symmetric encryption is not supported).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_encrypt(
    ctx: *mut GpgmeCtx,
    keys: *mut *mut GpgmeKey,
    _flags: u32,
    plain: *mut GpgmeData,
    cipher: *mut GpgmeData,
) -> u32 {
    // SAFETY: `ctx` may be null; `as_ref` handles the null check safely.
    let Some(ctx_ref) = (unsafe { ctx.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `plain` may be null; `as_ref` handles the null check safely.
    let Some(plain_ref) = (unsafe { plain.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `cipher` may be null; `as_mut` handles the null check safely.
    let Some(cipher_ref) = (unsafe { cipher.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };

    let home = ctx_ref.home_dir.to_string_lossy().to_string();
    // SAFETY: `keys` is either null or a valid null-terminated array of `GpgmeKey` pointers.
    let fprs = unsafe { collect_recipient_fprs(keys) };
    encrypt_sq(&home, &fprs, &plain_ref.buf, false).map_or_else(
        |_| gpg_error(GPG_ERR_NO_PUBKEY),
        |out| {
            cipher_ref.buf = out;
            cipher_ref.pos = 0;
            GPG_ERR_NO_ERROR
        },
    )
}

/// Asynchronous variant of `gpgme_op_encrypt`.
///
/// # Safety
/// Same requirements as `gpgme_op_encrypt`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_encrypt_start(
    ctx: *mut GpgmeCtx,
    keys: *mut *mut GpgmeKey,
    flags: u32,
    plain: *mut GpgmeData,
    cipher: *mut GpgmeData,
) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_op_encrypt(ctx, keys, flags, plain, cipher) }
}

/// Return a pointer to the encrypt result stored in `ctx`.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_encrypt_result(ctx: *mut GpgmeCtx) -> *mut GpgmeEncryptResult {
    // SAFETY: caller guarantees ctx points to a valid GpgmeCtx.
    unsafe { &raw mut *(*ctx).encrypt_result }
}

/// Not implemented: extended encrypt.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_encrypt_ext(
    _ctx: *mut GpgmeCtx,
    _keys: *mut *mut GpgmeKey,
    _expr: *const c_char,
    _flags: u32,
    _plain: *mut GpgmeData,
    _cipher: *mut GpgmeData,
) -> u32 {
    not_impl()
}

/// Not implemented: extended encrypt (async).
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_encrypt_ext_start(
    _ctx: *mut GpgmeCtx,
    _keys: *mut *mut GpgmeKey,
    _expr: *const c_char,
    _flags: u32,
    _plain: *mut GpgmeData,
    _cipher: *mut GpgmeData,
) -> u32 {
    not_impl()
}

/// Sign `plain` and then encrypt it for `keys`, writing the result into `cipher`.
///
/// # Safety
/// `ctx`, `plain`, and `cipher` must be valid, non-null pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_encrypt_sign(
    ctx: *mut GpgmeCtx,
    keys: *mut *mut GpgmeKey,
    _flags: u32,
    plain: *mut GpgmeData,
    cipher: *mut GpgmeData,
) -> u32 {
    // SAFETY: `ctx` may be null; `as_mut` handles the null check safely.
    let Some(ctx_ref) = (unsafe { ctx.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `plain` may be null; `as_ref` handles the null check safely.
    let Some(plain_ref) = (unsafe { plain.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `cipher` may be null; `as_mut` handles the null check safely.
    let Some(cipher_ref) = (unsafe { cipher.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };

    let home = ctx_ref.home_dir.to_string_lossy().to_string();
    // SAFETY: `keys` is either null or a valid null-terminated array of `GpgmeKey` pointers.
    let fprs = unsafe { collect_recipient_fprs(keys) };
    // SAFETY: `passphrase_cb` and `passphrase_hook` are either null or valid for the duration of the call.
    let Ok(signed) = (unsafe {
        sign_sq(
            &home,
            &ctx_ref.signer_fprs,
            ctx_ref.passphrase_cb,
            ctx_ref.passphrase_hook,
            &plain_ref.buf,
            GPGME_SIG_MODE_NORMAL,
        )
    }) else {
        return gpg_error(GPG_ERR_NO_SECKEY);
    };
    encrypt_sq(&home, &fprs, &signed, false).map_or_else(
        |_| gpg_error(GPG_ERR_NO_PUBKEY),
        |out| {
            cipher_ref.buf = out;
            cipher_ref.pos = 0;
            GPG_ERR_NO_ERROR
        },
    )
}

/// Asynchronous variant of `gpgme_op_encrypt_sign`.
///
/// # Safety
/// Same requirements as `gpgme_op_encrypt_sign`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_encrypt_sign_start(
    ctx: *mut GpgmeCtx,
    keys: *mut *mut GpgmeKey,
    flags: u32,
    plain: *mut GpgmeData,
    cipher: *mut GpgmeData,
) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_op_encrypt_sign(ctx, keys, flags, plain, cipher) }
}

/// Not implemented: extended encrypt+sign.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_encrypt_sign_ext(
    _ctx: *mut GpgmeCtx,
    _keys: *mut *mut GpgmeKey,
    _expr: *const c_char,
    _flags: u32,
    _plain: *mut GpgmeData,
    _cipher: *mut GpgmeData,
) -> u32 {
    not_impl()
}

/// Not implemented: extended encrypt+sign (async).
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_encrypt_sign_ext_start(
    _ctx: *mut GpgmeCtx,
    _keys: *mut *mut GpgmeKey,
    _expr: *const c_char,
    _flags: u32,
    _plain: *mut GpgmeData,
    _cipher: *mut GpgmeData,
) -> u32 {
    not_impl()
}

// ─── Sign ─────────────────────────────────────────────────────────────────────

/// Sign `plain` according to `mode` and write the result into `sig`.
///
/// # Safety
/// `ctx`, `plain`, and `sig` must be valid, non-null pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_sign(
    ctx: *mut GpgmeCtx,
    plain: *mut GpgmeData,
    sig: *mut GpgmeData,
    mode: u32,
) -> u32 {
    // SAFETY: `ctx` may be null; `as_ref` handles the null check safely.
    let Some(ctx_ref) = (unsafe { ctx.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `plain` may be null; `as_ref` handles the null check safely.
    let Some(plain_ref) = (unsafe { plain.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `sig` may be null; `as_mut` handles the null check safely.
    let Some(sig_ref) = (unsafe { sig.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };

    let home = ctx_ref.home_dir.to_string_lossy().to_string();
    // SAFETY: `passphrase_cb` and `passphrase_hook` are either null or valid for the duration of the call.
    unsafe {
        sign_sq(
            &home,
            &ctx_ref.signer_fprs,
            ctx_ref.passphrase_cb,
            ctx_ref.passphrase_hook,
            &plain_ref.buf,
            mode,
        )
    }
    .map_or_else(
        |_| gpg_error(GPG_ERR_NO_SECKEY),
        |out| {
            sig_ref.buf = out;
            sig_ref.pos = 0;
            GPG_ERR_NO_ERROR
        },
    )
}

/// Asynchronous variant of `gpgme_op_sign`.
///
/// # Safety
/// Same requirements as `gpgme_op_sign`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_sign_start(
    ctx: *mut GpgmeCtx,
    plain: *mut GpgmeData,
    sig: *mut GpgmeData,
    mode: u32,
) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_op_sign(ctx, plain, sig, mode) }
}

/// Return a pointer to the sign result stored in `ctx`.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_sign_result(ctx: *mut GpgmeCtx) -> *mut GpgmeSignResult {
    // SAFETY: caller guarantees ctx points to a valid GpgmeCtx.
    unsafe { &raw mut *(*ctx).sign_result }
}

// ─── Decrypt ──────────────────────────────────────────────────────────────────

/// Decrypt `cipher` and write the plaintext into `plain`.
///
/// # Safety
/// `ctx`, `cipher`, and `plain` must all be valid, non-null pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_decrypt(
    ctx: *mut GpgmeCtx,
    cipher: *mut GpgmeData,
    plain: *mut GpgmeData,
) -> u32 {
    // SAFETY: `ctx` may be null; `as_mut` handles the null check safely.
    let Some(ctx_ref) = (unsafe { ctx.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `cipher` may be null; `as_ref` handles the null check safely.
    let Some(cipher_ref) = (unsafe { cipher.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `plain` may be null; `as_mut` handles the null check safely.
    let Some(plain_ref) = (unsafe { plain.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };

    let home = ctx_ref.home_dir.to_string_lossy().to_string();
    // SAFETY: `passphrase_cb` and `passphrase_hook` are either null or valid for the duration of the call.
    match unsafe {
        decrypt_sq(
            &home,
            ctx_ref.passphrase_cb,
            ctx_ref.passphrase_hook,
            &cipher_ref.buf,
        )
    } {
        Ok((plaintext, _)) => {
            plain_ref.buf = plaintext;
            plain_ref.pos = 0;
            GPG_ERR_NO_ERROR
        }
        Err(_) => gpg_error(GPG_ERR_NO_SECKEY),
    }
}

/// Asynchronous variant of `gpgme_op_decrypt`.
///
/// # Safety
/// Same requirements as `gpgme_op_decrypt`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_decrypt_start(
    ctx: *mut GpgmeCtx,
    cipher: *mut GpgmeData,
    plain: *mut GpgmeData,
) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_op_decrypt(ctx, cipher, plain) }
}

/// Return a pointer to the decrypt result stored in `ctx`.
///
/// # Safety
/// `ctx` must point to a valid `GpgmeCtx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_decrypt_result(ctx: *mut GpgmeCtx) -> *mut GpgmeDecryptResult {
    // SAFETY: caller guarantees ctx points to a valid GpgmeCtx.
    unsafe { &raw mut *(*ctx).decrypt_result }
}

/// Decrypt `cipher` and also verify any embedded signatures.
///
/// # Safety
/// `ctx`, `cipher`, and `plain` must all be valid, non-null pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_decrypt_verify(
    ctx: *mut GpgmeCtx,
    cipher: *mut GpgmeData,
    plain: *mut GpgmeData,
) -> u32 {
    // SAFETY: `ctx` may be null; `as_mut` handles the null check safely.
    let Some(ctx_ref) = (unsafe { ctx.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `cipher` may be null; `as_ref` handles the null check safely.
    let Some(cipher_ref) = (unsafe { cipher.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    // SAFETY: `plain` may be null; `as_mut` handles the null check safely.
    let Some(plain_ref) = (unsafe { plain.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };

    let home = ctx_ref.home_dir.to_string_lossy().to_string();
    // SAFETY: `passphrase_cb` and `passphrase_hook` are either null or valid for the duration of the call.
    match unsafe {
        decrypt_sq(
            &home,
            ctx_ref.passphrase_cb,
            ctx_ref.passphrase_hook,
            &cipher_ref.buf,
        )
    } {
        Ok((plaintext, sig_records)) => {
            plain_ref.buf = plaintext;
            plain_ref.pos = 0;
            // SAFETY: `signatures` is either null or a valid linked-list allocated by this library.
            unsafe { free_sig_list(ctx_ref.verify_result.signatures) };
            ctx_ref.verify_result.signatures = ptr::null_mut();

            let mut head: *mut GpgmeSig = ptr::null_mut();
            let mut tail = ptr::addr_of_mut!(head);
            for rec in &sig_records {
                let fpr_ptr = rec
                    .fpr
                    .as_deref()
                    .and_then(|fpr| CString::new(fpr).ok())
                    .map_or(ptr::null(), |cs: CString| cs.into_raw().cast_const());
                let node = Box::into_raw(Box::new(GpgmeSig {
                    next: ptr::null_mut(),
                    summary: rec.summary,
                    fpr: fpr_ptr,
                    status: rec.status,
                    notations: ptr::null_mut(),
                    timestamp: 0,
                    exp_timestamp: 0,
                    bitflags: 0,
                    validity: rec.validity,
                    validity_reason: 0,
                    pubkey_algo: 0,
                    hash_algo: 0,
                    pka_address: ptr::null(),
                    key: ptr::null_mut(),
                }));
                // SAFETY: `tail` always points to a valid `*mut GpgmeSig` field,
                // either `head` or `(*prev_node).next`.
                unsafe { *tail = node };
                // SAFETY: `node` is a valid, non-null pointer to a newly allocated `GpgmeSig`.
                tail = unsafe { ptr::addr_of_mut!((*node).next) };
            }
            ctx_ref.verify_result.signatures = head;
            GPG_ERR_NO_ERROR
        }
        Err(_) => gpg_error(GPG_ERR_NO_SECKEY),
    }
}

/// Asynchronous variant of `gpgme_op_decrypt_verify`.
///
/// # Safety
/// Same requirements as `gpgme_op_decrypt_verify`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_decrypt_verify_start(
    ctx: *mut GpgmeCtx,
    cipher: *mut GpgmeData,
    plain: *mut GpgmeData,
) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_op_decrypt_verify(ctx, cipher, plain) }
}

/// Not implemented: extended decrypt.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_decrypt_ext(
    _ctx: *mut GpgmeCtx,
    _flags: u32,
    _cipher: *mut GpgmeData,
    _plain: *mut GpgmeData,
) -> u32 {
    not_impl()
}

/// Not implemented: extended decrypt (async).
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_decrypt_ext_start(
    _ctx: *mut GpgmeCtx,
    _flags: u32,
    _cipher: *mut GpgmeData,
    _plain: *mut GpgmeData,
) -> u32 {
    not_impl()
}

// ─── Key generation ───────────────────────────────────────────────────────────

/// Generate a new key from an XML-style parameter string.
///
/// # Safety
/// `ctx` and `parms` must be valid, non-null pointers.  `_pub_data` and
/// `_sec_data` are unused.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_genkey(
    ctx: *mut GpgmeCtx,
    parms: *const c_char,
    _pub_data: *mut GpgmeData,
    _sec_data: *mut GpgmeData,
) -> u32 {
    // SAFETY: `ctx` may be null; `as_ref` handles the null check safely.
    let Some(ctx_ref) = (unsafe { ctx.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    if parms.is_null() {
        return gpg_error(GPG_ERR_INV_VALUE);
    }
    // SAFETY: `parms` is non-null and caller guarantees it is a valid nul-terminated C string.
    let parms_str = unsafe { CStr::from_ptr(parms) }
        .to_string_lossy()
        .to_string();

    let name = extract_parm(&parms_str, "Name-Real").unwrap_or_else(|| "Generated Key".to_owned());
    let email = extract_parm(&parms_str, "Name-Email").unwrap_or_default();
    let userid = if email.is_empty() {
        name
    } else {
        format!("{name} <{email}>")
    };
    let expire = extract_parm(&parms_str, "Expire-Date")
        .and_then(|val| val.parse::<u64>().ok())
        .unwrap_or(0);
    let home = ctx_ref.home_dir.to_string_lossy().to_string();
    match genkey_sq(&home, &userid, expire) {
        Ok(()) => GPG_ERR_NO_ERROR,
        Err(_) => gpg_error(1),
    }
}

/// Asynchronous variant of `gpgme_op_genkey`.
///
/// # Safety
/// Same requirements as `gpgme_op_genkey`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_genkey_start(
    ctx: *mut GpgmeCtx,
    parms: *const c_char,
    pub_data: *mut GpgmeData,
    sec_data: *mut GpgmeData,
) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_op_genkey(ctx, parms, pub_data, sec_data) }
}

/// Return null (genkey result not stored).
///
/// # Safety
/// `_ctx` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_op_genkey_result(_ctx: *mut GpgmeCtx) -> *mut u8 {
    ptr::null_mut()
}

/// Generate a new key for `userid` with the given expiry.
///
/// # Safety
/// `ctx` and `userid` must be valid, non-null pointers.  `_algo`, `_reserved`,
/// and `_link_key` are unused.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_createkey(
    ctx: *mut GpgmeCtx,
    userid: *const c_char,
    _algo: *const c_char,
    _reserved: c_ulong,
    expire: c_ulong,
    _link_key: *mut GpgmeKey,
    _flags: u32,
) -> u32 {
    // SAFETY: `ctx` may be null; `as_ref` handles the null check safely.
    let Some(ctx_ref) = (unsafe { ctx.as_ref() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    if userid.is_null() {
        return gpg_error(GPG_ERR_INV_VALUE);
    }
    // SAFETY: `userid` is non-null and caller guarantees it is a valid nul-terminated C string.
    let uid = unsafe { CStr::from_ptr(userid) }
        .to_string_lossy()
        .to_string();
    let home = ctx_ref.home_dir.to_string_lossy().to_string();
    match genkey_sq(&home, &uid, expire) {
        Ok(()) => GPG_ERR_NO_ERROR,
        Err(_) => gpg_error(1),
    }
}

/// Asynchronous variant of `gpgme_op_createkey`.
///
/// # Safety
/// Same requirements as `gpgme_op_createkey`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_op_createkey_start(
    ctx: *mut GpgmeCtx,
    userid: *const c_char,
    algo: *const c_char,
    reserved: c_ulong,
    expire: c_ulong,
    link_key: *mut GpgmeKey,
    flags: u32,
) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe { gpgme_op_createkey(ctx, userid, algo, reserved, expire, link_key, flags) }
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Build a linked list of `GpgmeSig` nodes from verify-operation records.
///
/// The returned head pointer must be freed via `free_sig_list`.
unsafe fn build_sig_list(records: &[SigRecord]) -> *mut GpgmeSig {
    let mut head: *mut GpgmeSig = ptr::null_mut();
    let mut tail = ptr::addr_of_mut!(head);
    for rec in records {
        let fpr_ptr = rec
            .fpr
            .as_deref()
            .and_then(|fpr| CString::new(fpr).ok())
            .map_or(ptr::null(), |cs: CString| cs.into_raw().cast_const());
        let node = Box::into_raw(Box::new(GpgmeSig {
            next: ptr::null_mut(),
            summary: rec.summary,
            fpr: fpr_ptr,
            status: rec.status,
            notations: ptr::null_mut(),
            timestamp: rec.timestamp,
            exp_timestamp: rec.exp_timestamp,
            bitflags: 0,
            validity: rec.validity,
            validity_reason: 0,
            pubkey_algo: 0,
            hash_algo: 0,
            pka_address: ptr::null(),
            key: ptr::null_mut(),
        }));
        // SAFETY: `tail` always points to a valid `*mut GpgmeSig` field,
        // either `head` or `(*prev_node).next`.
        unsafe { *tail = node };
        // SAFETY: `node` is a valid, non-null pointer to a newly allocated `GpgmeSig`.
        tail = unsafe { ptr::addr_of_mut!((*node).next) };
    }
    head
}
