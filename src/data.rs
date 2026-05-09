//! In-memory data buffer used as the GPGME data object.

/// In-memory byte buffer used as the GPGME data object; aliased as `GpgmeData`.
pub struct SqData {
    /// Raw contents of the data object.
    pub buf: Vec<u8>,
    /// Current read/write position within `buf`.
    pub pos: usize,
}

/// C-ABI alias for [`SqData`].
pub type GpgmeData = SqData;
