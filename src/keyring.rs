//! Keyring loading, certificate utilities, and memory-management helpers.

use alloc::ffi::CString;
use core::ffi::CStr;
use core::ffi::c_char;
use core::ptr;
use std::path::PathBuf;
use std::process::Command;
use std::time::UNIX_EPOCH;

use sequoia_openpgp::Cert;
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::parse::Parse as _;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::RevocationStatus;

use crate::crypto::Password;
use crate::ffi_types::{
    GPGME_KEYLIST_MODE_LOCAL, GPGME_PROTOCOL_OPENPGP, GPGME_VALIDITY_UNKNOWN, GpgmeKey, GpgmeSig,
    GpgmeSubkey, GpgmeUserId, PassphraseCbFn,
};

/// Load all public certificates from `home_dir`.
///
/// First attempts to read `pubring.gpg` directly; falls back to invoking
/// `gpg-sq --export`.
pub fn load_certs(home_dir: &str) -> Vec<Cert> {
    let pgp_path = PathBuf::from(home_dir).join("pubring.gpg");
    if pgp_path.exists() {
        let certs: Vec<Cert> = CertParser::from_file(&pgp_path)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .collect();
        if !certs.is_empty() {
            return certs;
        }
    }
    if let Ok(out) = Command::new("/usr/bin/gpg-sq")
        .args(["--homedir", home_dir, "--export", "--batch", "--no-tty"])
        .output()
        && !out.stdout.is_empty()
    {
        return CertParser::from_bytes(&out.stdout)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .collect();
    }

    Vec::new()
}

/// Load all secret certificates (TSKs) from `home_dir`.
///
/// First attempts to read `secring.gpg` directly; falls back to invoking
/// `gpg-sq --export-secret-keys`.
pub fn load_secret_certs(home_dir: &str) -> Vec<Cert> {
    let sec_path = PathBuf::from(home_dir).join("secring.gpg");
    if sec_path.exists() {
        let certs: Vec<Cert> = CertParser::from_file(&sec_path)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter(sequoia_openpgp::Cert::is_tsk)
            .collect();
        if !certs.is_empty() {
            return certs;
        }
    }
    if let Ok(out) = Command::new("/usr/bin/gpg-sq")
        .args([
            "--homedir",
            home_dir,
            "--export-secret-keys",
            "--batch",
            "--no-tty",
        ])
        .output()
        && !out.stdout.is_empty()
    {
        return CertParser::from_bytes(&out.stdout)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter(sequoia_openpgp::Cert::is_tsk)
            .collect();
    }

    Vec::new()
}

/// Invoke the application-supplied passphrase callback and return the result.
///
/// Creates a pipe, passes the write end to `cb`, then reads the passphrase
/// from the read end. Returns `None` on any error.
///
/// # Safety
/// `cb` must be a valid function pointer and `hook` must satisfy the callback's
/// contract for the duration of the call.
pub unsafe fn call_passphrase_cb(
    cb: PassphraseCbFn,
    hook: *mut u8,
    hint: &str,
) -> Option<Password> {
    let mut fds = [0_i32; 2];
    // SAFETY: `fds` is a valid two-element array for `pipe` to fill.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0_i32 {
        return None;
    }
    let [read_fd, write_fd] = fds;
    let Some(hint_cstr) = CString::new(hint).ok() else {
        return None;
    };
    let Some(info_cstr) = CString::new("").ok() else {
        return None;
    };
    // SAFETY: `cb` is a valid function pointer; `hook` satisfies the callback's contract;
    // `hint_cstr` and `info_cstr` are valid nul-terminated C strings; `write_fd` is open and writable.
    let err = unsafe { cb(hook, hint_cstr.as_ptr(), info_cstr.as_ptr(), 0, write_fd) };
    // SAFETY: `write_fd` is a valid open file descriptor.
    unsafe { libc::close(write_fd) };
    if err != 0 {
        // SAFETY: `read_fd` is a valid open file descriptor.
        unsafe { libc::close(read_fd) };
        return None;
    }
    let mut pass_bytes = Vec::new();
    let mut byte_buf = [0_u8; 1];
    loop {
        // SAFETY: `read_fd` is open and readable; `byte_buf` is a valid single-byte buffer.
        let count = unsafe { libc::read(read_fd, byte_buf.as_mut_ptr().cast::<libc::c_void>(), 1) };
        if count <= 0 || byte_buf.first() == Some(&b'\n') {
            break;
        }
        if let Some(&byte) = byte_buf.first() {
            pass_bytes.push(byte);
        }
    }
    // SAFETY: `read_fd` is a valid open file descriptor.
    unsafe { libc::close(read_fd) };
    let Some(pass_str) = String::from_utf8(pass_bytes).ok() else {
        return None;
    };
    Some(Password::from(pass_str.as_str()))
}

/// Leak a `CString` as a `*const c_char`, or return null for empty strings.
///
/// The caller is responsible for eventually reclaiming the memory via
/// `CString::from_raw`.
pub fn opt_cstring(src: &str) -> *const c_char {
    if src.is_empty() {
        ptr::null()
    } else {
        CString::new(src).map_or(ptr::null(), |cs| cs.into_raw().cast_const())
    }
}

/// Free a linked list of [`GpgmeSig`] nodes, including their `fpr` strings.
///
/// # Safety
/// `head` must be either null or a pointer to a valid, heap-allocated
/// `GpgmeSig` chain where every `fpr` field (if non-null) was produced by
/// `CString::into_raw`.
pub unsafe fn free_sig_list(mut head: *mut GpgmeSig) {
    while !head.is_null() {
        let (next, fpr) = {
            // SAFETY: `head` is non-null and points to a valid `GpgmeSig` per loop invariant.
            let node = unsafe { &*head };
            (node.next, node.fpr)
        };
        if !fpr.is_null() {
            // SAFETY: `fpr` is non-null and was produced by `CString::into_raw`.
            drop(unsafe { CString::from_raw(fpr.cast_mut()) });
        }
        // SAFETY: `head` is a valid, non-null, heap-allocated `GpgmeSig`.
        drop(unsafe { Box::from_raw(head) });
        head = next;
    }
}

/// Free a heap-allocated [`GpgmeKey`] and all its child objects.
///
/// # Safety
/// `key_ptr` must be either null or a pointer to a valid, heap-allocated
/// `GpgmeKey` produced by [`cert_to_key`].
pub unsafe fn free_key(key_ptr: *mut GpgmeKey) {
    if key_ptr.is_null() {
        return;
    }

    let (subkeys_ptr, uids_ptr, fpr) = {
        // SAFETY: `key_ptr` is non-null and points to a valid `GpgmeKey`.
        let key_ref = unsafe { &*key_ptr };
        (key_ref.subkeys, key_ref.uids, key_ref.fpr)
    };

    if !subkeys_ptr.is_null() {
        let fields = {
            // SAFETY: `subkeys_ptr` is non-null and points to a valid `GpgmeSubkey`.
            let subkey = unsafe { &*subkeys_ptr };
            [
                subkey.keyid,
                subkey.fpr,
                subkey.card_number,
                subkey.curve,
                subkey.keygrip,
            ]
        };
        for field in fields {
            if !field.is_null() {
                // SAFETY: `field` is non-null and was produced by `CString::into_raw`.
                drop(unsafe { CString::from_raw(field.cast_mut()) });
            }
        }
        // SAFETY: `subkeys_ptr` is a valid, non-null, heap-allocated `GpgmeSubkey`.
        drop(unsafe { Box::from_raw(subkeys_ptr) });
    }

    if !uids_ptr.is_null() {
        let fields = {
            // SAFETY: `uids_ptr` is non-null and points to a valid `GpgmeUid`.
            let uid = unsafe { &*uids_ptr };
            [uid.uid, uid.name, uid.email, uid.comment]
        };
        for field in fields {
            if !field.is_null() {
                // SAFETY: `field` is non-null and was produced by `CString::into_raw`.
                drop(unsafe { CString::from_raw(field.cast_mut()) });
            }
        }
        // SAFETY: `uids_ptr` is a valid, non-null, heap-allocated `GpgmeUid`.
        drop(unsafe { Box::from_raw(uids_ptr) });
    }

    if !fpr.is_null() {
        // SAFETY: `fpr` is non-null and was produced by `CString::into_raw`.
        drop(unsafe { CString::from_raw(fpr.cast_mut()) });
    }

    // SAFETY: `key_ptr` is a valid, non-null, heap-allocated `GpgmeKey`.
    drop(unsafe { Box::from_raw(key_ptr) });
}

/// Convert a Sequoia [`Cert`] into a heap-allocated [`GpgmeKey`].
///
/// The returned pointer must eventually be freed via [`free_key`] (or by
/// decrementing the ref-count through `gpgme_key_unref`).
pub fn cert_to_key(cert: &Cert) -> *mut GpgmeKey {
    let policy = StandardPolicy::new();
    let primary = cert.primary_key();
    let fpr_str = primary.key().fingerprint().to_hex();
    let keyid_str = primary.key().keyid().to_hex();
    let ts = primary
        .key()
        .creation_time()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |dur| i64::try_from(dur.as_secs()).unwrap_or(i64::MAX));

    let subkey = Box::new(GpgmeSubkey {
        next: ptr::null_mut(),
        bitflags: 0,
        pubkey_algo: 0,
        length: 0,
        keyid: opt_cstring(&keyid_str),
        fpr: opt_cstring(&fpr_str),
        timestamp: ts,
        expires: 0,
        card_number: ptr::null(),
        curve: ptr::null(),
        keygrip: ptr::null(),
    });

    let uid = cert.userids().next().map_or_else(
        || {
            Box::new(GpgmeUserId {
                next: ptr::null_mut(),
                bitflags: 0,
                validity: 0,
                uid: ptr::null(),
                name: ptr::null(),
                email: ptr::null(),
                comment: ptr::null(),
                signatures: ptr::null_mut(),
                _last_keysig: ptr::null_mut(),
                address: ptr::null(),
                tofu: ptr::null_mut(),
                last_update: 0,
                uidhash: ptr::null(),
            })
        },
        |uid_ref| {
            let uid_str = String::from_utf8_lossy(uid_ref.component().value()).to_string();
            let name_str = uid_ref
                .component()
                .name()
                .ok()
                .flatten()
                .unwrap_or("")
                .to_owned();
            let email_str = uid_ref
                .component()
                .email()
                .ok()
                .flatten()
                .unwrap_or("")
                .to_owned();
            Box::new(GpgmeUserId {
                next: ptr::null_mut(),
                bitflags: 0,
                validity: GPGME_VALIDITY_UNKNOWN,
                uid: opt_cstring(&uid_str),
                name: opt_cstring(&name_str),
                email: opt_cstring(&email_str),
                comment: ptr::null(),
                signatures: ptr::null_mut(),
                _last_keysig: ptr::null_mut(),
                address: ptr::null(),
                tofu: ptr::null_mut(),
                last_update: 0,
                uidhash: ptr::null(),
            })
        },
    );

    let revoked = u32::from(matches!(
        cert.revocation_status(&policy, None),
        RevocationStatus::Revoked(_)
    ));

    let subkey_raw = Box::into_raw(subkey);
    let uid_raw = Box::into_raw(uid);
    Box::into_raw(Box::new(GpgmeKey {
        refs: 1,
        bitflags: revoked,
        protocol: GPGME_PROTOCOL_OPENPGP,
        issuer_serial: ptr::null(),
        issuer_name: ptr::null(),
        chain_id: ptr::null(),
        owner_trust: GPGME_VALIDITY_UNKNOWN,
        subkeys: subkey_raw,
        uids: uid_raw,
        _last_subkey: subkey_raw,
        _last_uid: uid_raw,
        keylist_mode: GPGME_KEYLIST_MODE_LOCAL,
        fpr: opt_cstring(&fpr_str),
        last_update: 0,
    }))
}

/// Walk a null-terminated array of `*mut GpgmeKey` and return each primary fingerprint.
///
/// # Safety
/// `keys` must be either null or a pointer to a null-terminated array of
/// valid `GpgmeKey` pointers.
pub unsafe fn collect_recipient_fprs(keys: *mut *mut GpgmeKey) -> Vec<String> {
    let mut fprs = Vec::new();
    if keys.is_null() {
        return fprs;
    }
    let mut index: usize = 0;
    loop {
        // SAFETY: `keys` is non-null; `index` advances only within the null-terminated array.
        let key_ptr_ptr = unsafe { keys.add(index) };
        // SAFETY: `key_ptr_ptr` points to a valid element of the array.
        let key_ptr = unsafe { *key_ptr_ptr };
        if key_ptr.is_null() {
            break;
        }
        // SAFETY: `key_ptr` is non-null and points to a valid `GpgmeKey`.
        let key_ref = unsafe { &*key_ptr };
        let fpr_str = if key_ref.fpr.is_null() {
            // SAFETY: `subkeys` is either null or a valid pointer to a `GpgmeSubkey`.
            let subkey_opt = unsafe { key_ref.subkeys.as_ref() };
            if let Some(subkey) = subkey_opt
                && !subkey.fpr.is_null()
            {
                // SAFETY: `subkey.fpr` is non-null and points to a valid nul-terminated C string.
                Some(
                    unsafe { CStr::from_ptr(subkey.fpr) }
                        .to_string_lossy()
                        .to_string(),
                )
            } else {
                None
            }
        } else {
            // SAFETY: `key_ref.fpr` is non-null and points to a valid nul-terminated C string.
            Some(
                unsafe { CStr::from_ptr(key_ref.fpr) }
                    .to_string_lossy()
                    .to_string(),
            )
        };
        if let Some(fpr) = fpr_str {
            fprs.push(fpr);
        }
        index = index.saturating_add(1);
    }
    fprs
}

/// Extract a simple XML-style `<key>…</key>` value from a parameter string.
///
/// Returns `None` if the opening or closing tag is absent.
pub fn extract_parm(parms: &str, key: &str) -> Option<String> {
    let open_tag = format!("<{key}>");
    let close_tag = format!("</{key}>");
    let start = match parms.find(&open_tag) {
        Some(val) => val.saturating_add(open_tag.len()),
        None => return None,
    };
    let rest = match parms.get(start..) {
        Some(val) => val,
        None => return None,
    };
    let end_rel = match rest.find(&close_tag) {
        Some(val) => val,
        None => return None,
    };
    let inner = match rest.get(..end_rel) {
        Some(val) => val,
        None => return None,
    };
    Some(inner.trim().to_owned())
}
