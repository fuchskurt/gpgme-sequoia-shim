//! Process-global state: the singleton engine-info record and the default home directory.

use alloc::ffi::CString;
use core::ptr;
use std::sync::Mutex;

use crate::ffi_types::{GPGME_PROTOCOL_OPENPGP, GpgmeEngineInfo};

/// Singleton engine-info record returned by `gpgme_get_engine_info`.
///
/// All string fields point to static `CStr` literals that are valid for the
/// lifetime of the process.
pub static ENGINE_INFO: GpgmeEngineInfo = GpgmeEngineInfo {
    next: ptr::null_mut(),
    protocol: GPGME_PROTOCOL_OPENPGP,
    file_name: c"/usr/bin/gpg-sq".as_ptr(),
    version: c"2.2.40".as_ptr(),
    req_version: c"2.0.0".as_ptr(),
    home_dir: ptr::null(),
};

/// Globally-overridden `GnuPG` home directory, set by `gpgme_set_engine_info`.
///
/// When `None`, [`default_home_dir`] falls back to `/etc/pacman.d/gnupg`.
pub static GLOBAL_HOME_DIR: Mutex<Option<CString>> = Mutex::new(None);

/// Return the active global home directory, or the pacman default if none is set.
pub fn default_home_dir() -> CString {
    GLOBAL_HOME_DIR
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(|| {
            CString::new("/etc/pacman.d/gnupg").unwrap_or_else(|_| CString::default())
        })
}
