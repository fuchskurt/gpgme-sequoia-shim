//! Error-string helpers, I/O wrappers, and miscellaneous GPGME functions.

use core::ffi::CStr;
use core::ffi::{c_char, c_int};
use core::ptr;

use crate::error::{gpg_error, not_impl};
use crate::ffi_types::{GPGME_PROTOCOL_OPENPGP, GpgmeSubkey};

/// Return a human-readable description for a GPGME error code.
///
/// The returned pointer is valid for the lifetime of the process.
///
/// # Safety
/// No pointers are dereferenced.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_strerror(err: u32) -> *const c_char {
    match err & 0x00FF_FFFF {
        0 => c"Success".as_ptr(),
        7 => c"No public key".as_ptr(),
        8 => c"Bad signature".as_ptr(),
        17 => c"No secret key".as_ptr(),
        55 => c"Invalid value".as_ptr(),
        63 => c"Key expired".as_ptr(),
        65 => c"Signature expired".as_ptr(),
        69 => c"Not implemented".as_ptr(),
        86 => c"Out of memory".as_ptr(),
        108 => c"Invalid crypto engine".as_ptr(),
        16383 => c"End of file".as_ptr(),
        _ => c"Unknown error".as_ptr(),
    }
}

/// Write the human-readable description for `err` into `buf`.
///
/// Returns 0 on success, -1 if `buflen` is zero.
///
/// # Safety
/// `buf` must be writable for at least `buflen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_strerror_r(err: u32, buf: *mut c_char, buflen: usize) -> c_int {
    if buflen == 0 {
        return -1;
    }
    // SAFETY: `gpgme_strerror` always returns a valid, non-null, nul-terminated C string.
    let err_ptr = unsafe { gpgme_strerror(err) };
    // SAFETY: `err_ptr` is a valid nul-terminated C string returned by `gpgme_strerror`.
    let bytes = unsafe { CStr::from_ptr(err_ptr) }.to_bytes_with_nul();

    let copy_len = bytes.len().min(buflen);
    // SAFETY: `bytes` has `copy_len` initialised bytes; `buf` is caller-guaranteed
    // writable for at least `buflen` bytes.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), copy_len) };
    // SAFETY: `buf.add(copy_len - 1)` is within the writable region guaranteed by the caller.
    let nul = unsafe { buf.add(copy_len.saturating_sub(1)) };
    // SAFETY: `nul` points to valid writable storage within `buf`.
    unsafe { ptr::write(nul.cast::<u8>(), 0) };
    0
}

/// Return the name of the GPGME error source ("GPGME").
///
/// # Safety
/// `_err` is unused; the returned pointer is valid for the process lifetime.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_strsource(_err: u32) -> *const c_char {
    c"GPGME".as_ptr()
}

/// Convert an `errno` value to a GPGME error code.
///
/// # Safety
/// No pointers are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_err_code_from_errno(errno_val: c_int) -> u32 {
    u32::try_from(errno_val).unwrap_or(0)
}

/// Convert a GPGME error code back to an `errno` value.
///
/// # Safety
/// No pointers are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_err_code_to_errno(code: u32) -> c_int {
    c_int::try_from(code).unwrap_or(-1)
}

/// Build a GPGME error from a source and an `errno` value.
///
/// `_source` is ignored; the errno is used as the error code.
///
/// # Safety
/// No pointers are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_err_make_from_errno(_source: u32, errno_val: c_int) -> u32 {
    u32::try_from(errno_val).unwrap_or(0)
}

/// Return the current `errno` as a GPGME error code.
///
/// # Safety
/// Reads the thread-local `errno`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_err_code_from_syserror() -> u32 {
    // SAFETY: `__errno_location` returns a valid thread-local pointer.
    let errno_ptr = unsafe { libc::__errno_location() };
    // SAFETY: `errno_ptr` is a valid, readable thread-local pointer.
    let errno = unsafe { *errno_ptr };
    u32::try_from(errno).unwrap_or(u32::MAX)
}

/// Wrap an `errno` value as a GPGME error.
///
/// # Safety
/// No pointers are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_error_from_errno(errno_val: c_int) -> u32 {
    gpg_error(u32::try_from(errno_val).unwrap_or(0))
}

/// Wrap the current `errno` as a GPGME error.
///
/// # Safety
/// Reads the thread-local `errno`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_error_from_syserror() -> u32 {
    // SAFETY: `__errno_location` returns a valid thread-local pointer.
    let errno_ptr = unsafe { libc::__errno_location() };
    // SAFETY: `errno_ptr` is a valid, readable thread-local pointer.
    let errno = unsafe { *errno_ptr };
    gpg_error(u32::try_from(errno).unwrap_or(0))
}

/// Set `errno` to `errno_val`.
///
/// # Safety
/// Writes to the thread-local `errno`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_err_set_errno(errno_val: c_int) {
    // SAFETY: `__errno_location` returns a valid thread-local pointer.
    let errno_ptr = unsafe { libc::__errno_location() };
    // SAFETY: `errno_ptr` is a valid, writable thread-local pointer.
    unsafe { *errno_ptr = errno_val };
}

/// Read up to `count` bytes from file descriptor `fd` into `buf`.
///
/// # Safety
/// `buf` must be writable for at least `count` bytes.  `fd` must be open.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_io_read(fd: c_int, buf: *mut u8, count: usize) -> libc::ssize_t {
    // SAFETY: buf is valid for the given size, as required by the caller.
    unsafe { libc::read(fd, buf.cast::<libc::c_void>(), count) }
}

/// Write up to `count` bytes from `buf` to file descriptor `fd`.
///
/// # Safety
/// `buf` must be readable for at least `count` bytes.  `fd` must be open and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_io_write(fd: c_int, buf: *const u8, count: usize) -> libc::ssize_t {
    // SAFETY: buf is valid for the given size, as required by the caller.
    unsafe { libc::write(fd, buf.cast::<libc::c_void>(), count) }
}

/// Write exactly `count` bytes from `buf` to file descriptor `fd`.
///
/// Retries partial writes until all bytes are written or an error occurs.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `buf` must be readable for at least `count` bytes.  `fd` must be open and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_io_writen(fd: c_int, buf: *const u8, count: usize) -> c_int {
    let mut written: usize = 0;
    while written < count {
        let remaining = count.saturating_sub(written);
        // SAFETY: `written < count` guarantees `buf.add(written)` is within the readable region.
        let ptr = unsafe { buf.add(written) };
        // SAFETY: `ptr` is valid for `remaining` bytes; `fd` is open and writable per caller contract.
        let result = unsafe { libc::write(fd, ptr.cast::<libc::c_void>(), remaining) };
        if result < 0 {
            return -1;
        }
        written = written.saturating_add(usize::try_from(result).unwrap_or(remaining));
    }
    0
}

/// Return "?" for any public-key algorithm identifier.
///
/// # Safety
/// `_algo` is ignored; returned pointer is valid for the process lifetime.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_pubkey_algo_name(_algo: u32) -> *const c_char {
    c"?".as_ptr()
}

/// Return null (algorithm string from subkey not implemented).
///
/// # Safety
/// `_subkey` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_pubkey_algo_string(_subkey: *mut GpgmeSubkey) -> *mut c_char {
    ptr::null_mut()
}

/// Return "?" for any hash algorithm identifier.
///
/// # Safety
/// `_algo` is ignored; returned pointer is valid for the process lifetime.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_hash_algo_name(_algo: u32) -> *const c_char {
    c"?".as_ptr()
}

/// Return the name of a GPGME protocol, or null for unknown protocols.
///
/// # Safety
/// `proto` is a plain integer; no pointers are dereferenced.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_protocol_name(proto: u32) -> *const c_char {
    if proto == GPGME_PROTOCOL_OPENPGP {
        c"OpenPGP".as_ptr()
    } else {
        ptr::null()
    }
}

/// Return null (directory info not implemented).
///
/// # Safety
/// `_what` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_get_dirinfo(_what: *const c_char) -> *const c_char {
    ptr::null()
}

/// Return null (addrspec extraction not implemented).
///
/// # Safety
/// `_uid` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_addrspec_from_uid(_uid: *const c_char) -> *mut c_char {
    ptr::null_mut()
}

/// No-op: release a config object.
///
/// # Safety
/// `_conf` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_conf_release(_conf: *mut u8) {}

/// Not implemented: allocate a config argument.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_conf_arg_new(
    _r_arg: *mut *mut u8,
    _type_: c_int,
    _value: *const u8,
) -> u32 {
    not_impl()
}

/// No-op: release a config argument.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_conf_arg_release(_arg: *mut u8, _type_: c_int) {}

/// Not implemented: change a config option.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_conf_opt_change(
    _opt: *mut u8,
    _reset: c_int,
    _arg: *mut u8,
) -> u32 {
    not_impl()
}

/// No-op: increment the reference count of a result object.
///
/// # Safety
/// `_result` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_result_ref(_result: *mut u8) {}

/// No-op: decrement the reference count of a result object.
///
/// # Safety
/// `_result` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_result_unref(_result: *mut u8) {}
