//! GPGME data-object functions (`gpgme_data_*`).

use core::ffi::CStr;
use core::ffi::{c_char, c_int};
use core::ptr;
use core::slice;
use std::fs;

use crate::data::{GpgmeData, SqData};
use crate::error::{GPG_ERR_INV_VALUE, GPG_ERR_NO_ERROR, gpg_error, not_impl};
use crate::ffi_types::{GPGME_DATA_ENCODING_NONE, SEEK_CUR, SEEK_END, SEEK_SET};

/// Allocate an empty data object and write its address into `*r_dh`.
///
/// # Safety
/// `r_dh` must be a valid, non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_data_new(r_dh: *mut *mut GpgmeData) -> u32 {
    // SAFETY: caller guarantees the pointer is valid and non-null.
    unsafe {
        if r_dh.is_null() {
            return gpg_error(GPG_ERR_INV_VALUE);
        }
        *r_dh = Box::into_raw(Box::new(SqData {
            buf: Vec::new(),
            pos: 0,
        }));
        GPG_ERR_NO_ERROR
    }
}

/// Allocate a data object pre-filled with a copy of `buf[..size]`.
///
/// # Safety
/// `r_dh` and `buf` must be valid, non-null pointers.  `buf` must be readable
/// for at least `size` bytes.  `_copy` is ignored (data is always copied).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_data_new_from_mem(
    r_dh: *mut *mut GpgmeData,
    buf: *const c_char,
    size: usize,
    _copy: c_int,
) -> u32 {
    // SAFETY: `r_dh` may be null; `as_mut` handles the null check safely.
    let Some(out) = (unsafe { r_dh.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    if buf.is_null() {
        return gpg_error(GPG_ERR_INV_VALUE);
    }
    // SAFETY: `buf` is non-null and caller guarantees it points to a readable
    // buffer of at least `size` bytes that outlives this call.
    let data = unsafe { slice::from_raw_parts(buf.cast::<u8>(), size) }.to_vec();
    *out = Box::into_raw(Box::new(SqData { buf: data, pos: 0 }));
    GPG_ERR_NO_ERROR
}

/// Allocate a data object by reading all bytes from a C `FILE *`.
///
/// # Safety
/// `r_dh` and `fp` must be valid, non-null pointers.  `fp` must be a readable
/// C stdio stream.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_data_new_from_stream(
    r_dh: *mut *mut GpgmeData,
    fp: *mut libc::FILE,
) -> u32 {
    // SAFETY: `r_dh` may be null; `as_mut` handles the null check safely.
    let Some(out) = (unsafe { r_dh.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    if fp.is_null() {
        return gpg_error(GPG_ERR_INV_VALUE);
    }
    let mut buf = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        // SAFETY: `fp` is non-null and caller guarantees it is a valid readable C stdio stream.
        if unsafe { libc::fread(byte.as_mut_ptr().cast::<libc::c_void>(), 1, 1, fp) } == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    *out = Box::into_raw(Box::new(SqData { buf, pos: 0 }));
    GPG_ERR_NO_ERROR
}

/// Allocate a data object by reading all bytes from a file descriptor.
///
/// # Safety
/// `r_dh` must be a valid, non-null pointer.  `fd` must be an open, readable
/// file descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_data_new_from_fd(r_dh: *mut *mut GpgmeData, fd: c_int) -> u32 {
    if r_dh.is_null() {
        return gpg_error(GPG_ERR_INV_VALUE);
    }

    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        // SAFETY: `fd` is a valid open file descriptor per the caller contract;
        // `chunk` is a live stack buffer of exactly `chunk.len()` bytes.
        let bytes_read =
            unsafe { libc::read(fd, chunk.as_mut_ptr().cast::<libc::c_void>(), chunk.len()) };
        if bytes_read <= 0 {
            break;
        }
        let n = usize::try_from(bytes_read).unwrap_or(chunk.len());
        buf.extend_from_slice(chunk.get(..n).unwrap_or(&chunk));
    }

    // SAFETY: caller guarantees `r_dh` is a valid, aligned, non-null pointer
    // (null case returned early above).
    unsafe { *r_dh = Box::into_raw(Box::new(SqData { buf, pos: 0 })) };

    GPG_ERR_NO_ERROR
}

/// Allocate a data object by reading a file at `path`.
///
/// # Safety
/// `r_dh` and `path` must be valid, non-null pointers.  `path` must be a
/// null-terminated, UTF-8 encoded C string.  `_copy` is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_data_new_from_file(
    r_dh: *mut *mut GpgmeData,
    path: *const c_char,
    _copy: c_int,
) -> u32 {
    // SAFETY: `r_dh` may be null; `as_mut` handles the null check safely.
    let Some(out) = (unsafe { r_dh.as_mut() }) else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    if path.is_null() {
        return gpg_error(GPG_ERR_INV_VALUE);
    }
    // SAFETY: `path` is non-null and caller guarantees it is a valid nul-terminated C string.
    let Ok(path_str) = (unsafe { CStr::from_ptr(path) }).to_str() else {
        return gpg_error(GPG_ERR_INV_VALUE);
    };
    *out = Box::into_raw(Box::new(SqData {
        buf: fs::read(path_str).unwrap_or_default(),
        pos: 0,
    }));
    GPG_ERR_NO_ERROR
}

/// Not implemented: filepart constructor.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_data_new_from_filepart(
    _r_dh: *mut *mut GpgmeData,
    _fname: *const c_char,
    _fp: *mut libc::FILE,
    _offset: libc::off_t,
    _length: usize,
) -> u32 {
    not_impl()
}

/// Not implemented: estream constructor.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_data_new_from_estream(
    _r_dh: *mut *mut GpgmeData,
    _stream: *mut u8,
) -> u32 {
    not_impl()
}

/// Not implemented: callback-based constructor.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_data_new_from_cbs(
    _r_dh: *mut *mut GpgmeData,
    _cbs: *mut u8,
    _handle: *mut u8,
) -> u32 {
    not_impl()
}

/// Not implemented: read-callback constructor.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_data_new_with_read_cb(
    _r_dh: *mut *mut GpgmeData,
    _cb: *mut u8,
    _handle: *mut u8,
) -> u32 {
    not_impl()
}

/// Release a data object.
///
/// # Safety
/// `dh` must be either null or a valid, heap-allocated `GpgmeData`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_data_release(dh: *mut GpgmeData) {
    // SAFETY: caller guarantees dh was allocated by Box::into_raw.
    unsafe {
        if !dh.is_null() {
            drop(Box::from_raw(dh));
        }
    }
}

/// Release a data object and return its contents as a `malloc`-allocated buffer.
///
/// The caller must free the returned pointer with `gpgme_free`.  `*r_len` is
/// set to the number of data bytes (excluding the trailing NUL).
///
/// # Safety
/// `dh` must be either null or a valid, heap-allocated `GpgmeData`.  `r_len`,
/// if non-null, must point to valid writable storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_data_release_and_get_mem(
    dh: *mut GpgmeData,
    r_len: *mut usize,
) -> *mut c_char {
    if dh.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `dh` is non-null and caller guarantees it was allocated by `Box::into_raw`.
    let data = unsafe { Box::from_raw(dh) };
    let len = data.buf.len();

    // SAFETY: `r_len` may be null; `as_mut` handles the null check safely.
    if let Some(len_out) = unsafe { r_len.as_mut() } {
        *len_out = len;
    }

    // SAFETY: `len + 1` is a valid allocation size; malloc returns null on failure (checked below).
    let out: *mut u8 = unsafe { libc::malloc(len.saturating_add(1)).cast::<u8>() };
    if out.is_null() {
        return ptr::null_mut();
    }

    if len > 0 {
        // SAFETY: `data.buf` contains `len` initialised bytes; `out` is a valid
        // allocation of at least `len` bytes.
        unsafe { ptr::copy_nonoverlapping(data.buf.as_ptr(), out, len) };
    }

    // SAFETY: `out` points to an allocation of `len + 1` bytes, so `out.add(len)` is in bounds.
    let nul = unsafe { out.add(len) };
    // SAFETY: `nul` points to valid writable storage within the allocation.
    unsafe { ptr::write(nul, 0) };

    out.cast::<c_char>()
}

/// Free a buffer returned by `gpgme_data_release_and_get_mem`.
///
/// # Safety
/// `ptr` must be either null or a pointer returned by `libc::malloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_free(ptr: *mut u8) {
    // SAFETY: ptr was allocated by libc::malloc.
    unsafe {
        if !ptr.is_null() {
            libc::free(ptr.cast::<libc::c_void>());
        }
    }
}

/// Read up to `size` bytes from the data object into `buf`.
///
/// Returns the number of bytes actually read.
///
/// # Safety
/// `dh` must point to a valid `GpgmeData`.  `buf` must be writable for at
/// least `size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_data_read(
    dh: *mut GpgmeData,
    buf: *mut u8,
    size: usize,
) -> libc::ssize_t {
    // SAFETY: caller guarantees `dh` is valid, aligned, and non-null.
    let data = unsafe { &mut *dh };

    let available = data.buf.len().saturating_sub(data.pos);
    let count = available.min(size);

    if count > 0
        && let Some(src) = data.buf.get(data.pos..)
    {
        // SAFETY: `src` is a valid slice of `data.buf` starting at `pos`;
        // `buf` is a caller-provided output buffer of at least `count` bytes.
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), buf, count) };
        data.pos = data.pos.saturating_add(count);
    }

    libc::ssize_t::try_from(count).unwrap_or(libc::ssize_t::MAX)
}

/// Write `size` bytes from `buf` into the data object at the current position.
///
/// Returns the number of bytes written.
///
/// # Safety
/// `dh` must point to a valid `GpgmeData`.  `buf` must be readable for at
/// least `size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_data_write(
    dh: *mut GpgmeData,
    buf: *const u8,
    size: usize,
) -> libc::ssize_t {
    // SAFETY: caller guarantees `dh` is valid, aligned, and non-null.
    let data = unsafe { &mut *dh };

    let end = data.pos.saturating_add(size);
    if end > data.buf.len() {
        data.buf.resize(end, 0);
    }

    // SAFETY: `buf` is a caller-provided readable buffer of exactly `size` bytes.
    let src = unsafe { slice::from_raw_parts(buf, size) };

    if let Some(dst) = data.buf.get_mut(data.pos..end) {
        dst.copy_from_slice(src);
        data.pos = end;
    }

    libc::ssize_t::try_from(size).unwrap_or(libc::ssize_t::MAX)
}

/// Seek within the data object.
///
/// `whence` follows the POSIX convention: `SEEK_SET`/`SEEK_CUR`/`SEEK_END`.
/// Returns the new position on success, or -1 with errno set on error.
///
/// # Safety
/// `dh` must point to a valid `GpgmeData`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_data_seek(
    dh: *mut GpgmeData,
    offset: libc::off_t,
    whence: c_int,
) -> libc::off_t {
    // SAFETY: caller guarantees `dh` is valid, aligned, and non-null.
    let Some(data) = (unsafe { dh.as_mut() }) else {
        return -1;
    };

    let new_pos: i64 = match whence {
        SEEK_SET => offset,
        SEEK_CUR => i64::try_from(data.pos)
            .unwrap_or(i64::MAX)
            .saturating_add(offset),
        SEEK_END => i64::try_from(data.buf.len())
            .unwrap_or(i64::MAX)
            .saturating_add(offset),
        _ => {
            // SAFETY: `__errno_location` returns a valid thread-local pointer.
            let errno = unsafe { libc::__errno_location() };
            // SAFETY: `errno` is a valid, writable thread-local pointer.
            unsafe { *errno = libc::EINVAL };
            return -1;
        }
    };

    if new_pos < 0 {
        // SAFETY: `__errno_location` returns a valid thread-local pointer.
        let errno = unsafe { libc::__errno_location() };
        // SAFETY: `errno` is a valid, writable thread-local pointer.
        unsafe { *errno = libc::EINVAL };
        return -1;
    }

    data.pos = usize::try_from(new_pos).unwrap_or(usize::MAX);
    libc::off_t::try_from(data.pos).unwrap_or(-1)
}

/// Reset the read/write position of the data object to the beginning.
///
/// # Safety
/// `dh` must point to a valid `GpgmeData`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gpgme_data_rewind(dh: *mut GpgmeData) -> u32 {
    // SAFETY: caller guarantees the pointer is valid and non-null.
    unsafe {
        (*dh).pos = 0;
        GPG_ERR_NO_ERROR
    }
}

/// Return the encoding of a data object (always `GPGME_DATA_ENCODING_NONE`).
///
/// # Safety
/// `_dh` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_data_get_encoding(_dh: *mut GpgmeData) -> u32 {
    GPGME_DATA_ENCODING_NONE
}

/// No-op encoding setter; always returns success.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_data_set_encoding(_dh: *mut GpgmeData, _enc: u32) -> u32 {
    GPG_ERR_NO_ERROR
}

/// Return null (no file name is stored on data objects).
///
/// # Safety
/// `_dh` is ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_data_get_file_name(_dh: *mut GpgmeData) -> *const c_char {
    ptr::null()
}

/// No-op file-name setter; always returns success.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_data_set_file_name(
    _dh: *mut GpgmeData,
    _name: *const c_char,
) -> u32 {
    GPG_ERR_NO_ERROR
}

/// No-op data flag setter; always returns success.
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_data_set_flag(
    _dh: *mut GpgmeData,
    _name: *const c_char,
    _value: *const c_char,
) -> u32 {
    GPG_ERR_NO_ERROR
}

/// Return 0 (data type identification not implemented).
///
/// # Safety
/// Arguments are ignored.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn gpgme_data_identify(_dh: *mut GpgmeData, _reserved: c_int) -> u32 {
    0
}
