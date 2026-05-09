//! GPGME engine-info and version-check functions.

use alloc::ffi::CString;
use core::ffi::CStr;
use core::ffi::c_char;
use std::fs;

use crate::error::{GPG_ERR_INV_ENGINE, GPG_ERR_NO_ERROR, gpg_error};
use crate::ffi_types::{GPGME_PROTOCOL_OPENPGP, GpgmeEngineInfo};
use crate::global::{ENGINE_INFO, GLOBAL_HOME_DIR};

/// Return the GPGME library version string.
///
/// # Safety
/// `_req_version` is unused; the returned pointer is valid for the process lifetime.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_check_version(_req_version: *const c_char) -> *const c_char {
    c"1.23.2".as_ptr()
}

/// Return the GPGME library version string (internal variant).
///
/// # Safety
/// `_req_version` and `_offset` are unused; the returned pointer is valid for the process lifetime.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_check_version_internal(
    _req_version: *const c_char,
    _offset: usize,
) -> *const c_char {
    c"1.23.2".as_ptr()
}

/// Verify that the engine for `proto` is available.
///
/// # Safety
/// No pointers are dereferenced; safe to call from any context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_engine_check_version(proto: u32) -> u32 {
    if proto != GPGME_PROTOCOL_OPENPGP {
        return gpg_error(GPG_ERR_INV_ENGINE);
    }
    if fs::metadata("/usr/bin/gpg-sq").is_ok() {
        GPG_ERR_NO_ERROR
    } else {
        gpg_error(GPG_ERR_INV_ENGINE)
    }
}

/// Write a pointer to the global engine info into `*info`.
///
/// # Safety
/// `info` must be a valid, non-null pointer to a `*mut GpgmeEngineInfo`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_get_engine_info(info: *mut *mut GpgmeEngineInfo) -> u32 {
    // SAFETY: caller guarantees the pointer is valid and non-null.
    unsafe {
        *info = core::ptr::addr_of!(ENGINE_INFO).cast_mut();
        GPG_ERR_NO_ERROR
    }
}

/// Set the global engine home directory for `proto`.
///
/// # Safety
/// `home_dir`, if non-null, must point to a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_set_engine_info(
    proto: u32,
    _file_name: *const c_char,
    home_dir: *const c_char,
) -> u32 {
    // SAFETY: caller upholds the same preconditions.
    unsafe {
        if proto != GPGME_PROTOCOL_OPENPGP {
            return gpg_error(GPG_ERR_INV_ENGINE);
        }
        if !home_dir.is_null()
            && let Ok(str_ref) = CStr::from_ptr(home_dir).to_str()
            && let Ok(cstr) = CString::new(str_ref)
            && let Ok(mut guard) = GLOBAL_HOME_DIR.lock()
        {
            *guard = Some(cstr);
        }
        GPG_ERR_NO_ERROR
    }
}
