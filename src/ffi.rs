//! FFI bindings for `crypter`

macro_rules! try_slice {
    ($slice:expr) => {
        if let Some(slice) = Option::<&[u8]>::from($slice) {
            slice
        } else {
            return CrypterRustSlice::null();
        }
    };
}

/// Represents a AES256 GCM SIV key.
pub type CrypterKey = [u8; 32];

/// Represents a slice of bytes owned by the caller.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CrypterCSlice {
    ptr: *const u8,
    len: usize,
}

impl From<CrypterCSlice> for Option<&[u8]> {
    fn from(slice: CrypterCSlice) -> Self {
        if slice.ptr.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(slice.ptr, slice.len) })
        }
    }
}

/// Represents a slice of bytes owned by Rust.
///
/// # Safety
///
/// To free the memory [`crypter_free_slice`](CrypterRustSlice::crypter_free_slice) must be called.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CrypterRustSlice {
    ptr: *const u8,
    len: usize,
    cap: usize,
}

impl CrypterRustSlice {
    pub fn null() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    /// Frees the slice of bytes owned by Rust.
    ///
    /// # Safety
    ///
    /// It may be unsafe to call `free()` on this slice as there is no guarantee of which allocator
    /// was used.
    #[unsafe(no_mangle)]
    pub extern "C" fn crypter_free_slice(&mut self) {
        if !self.ptr.is_null() {
            drop(unsafe { Vec::from_raw_parts(self.ptr.cast_mut(), self.len, self.cap) });
            self.ptr = std::ptr::null_mut();
            self.len = 0;
            self.cap = 0;
        }
    }
}

// TODO: Use Vec::into_raw_parts() when available
impl From<Vec<u8>> for CrypterRustSlice {
    fn from(vec: Vec<u8>) -> Self {
        let rust_slice = Self {
            ptr: vec.as_ptr(),
            len: vec.len(),
            cap: vec.capacity(),
        };
        std::mem::forget(vec);
        rust_slice
    }
}

/// Encrypts the payload with AES256 GCM SIV. The iv is randomly generated for each call.
///
/// A wrapper around [`encrypt`](../fn.encrypt.html)
///
/// # Safety
///
/// This method does not take ownership of the parameters.
#[unsafe(no_mangle)]
pub extern "C" fn crypter_encrypt(key: &CrypterKey, payload: CrypterCSlice) -> CrypterRustSlice {
    let payload = try_slice!(payload);
    super::encrypt(key, payload).map_or_else(CrypterRustSlice::null, CrypterRustSlice::from)
}

/// Encrypts the payload with AES256 GCM SIV using a key derived from password with Argon2.
/// The iv and the salt are randomly generated for each call.
///
/// A wrapper around [`encrypt_with_password`](../fn.encrypt_with_password.html)
///
/// # Safety
///
/// This method does not take ownership of the parameters.
#[cfg(feature = "argon")]
#[unsafe(no_mangle)]
pub extern "C" fn crypter_encrypt_with_password(
    password: CrypterCSlice,
    payload: CrypterCSlice,
) -> CrypterRustSlice {
    let password = try_slice!(password);
    let payload = try_slice!(payload);
    super::encrypt_with_password(password, payload)
        .map_or_else(CrypterRustSlice::null, CrypterRustSlice::from)
}

/// Decrypts the payload with AES256 GCM SIV.
///
/// A wrapper around [`decrypt`](../fn.decrypt.html).
///
/// # Safety
///
/// This method does not take ownership of the parameters.
#[unsafe(no_mangle)]
pub extern "C" fn crypter_decrypt(key: &CrypterKey, payload: CrypterCSlice) -> CrypterRustSlice {
    let payload = try_slice!(payload);
    super::decrypt(key, payload).map_or_else(CrypterRustSlice::null, CrypterRustSlice::from)
}

/// Decrypts the payload with AES256 GCM SIV using a key derived from password with Argon2.
///
/// A wrapper around [`decrypt_with_password`](../fn.decrypt_with_password.html)
///
/// # Safety
///
/// This method does not take ownership of the parameters.
#[cfg(feature = "argon")]
#[unsafe(no_mangle)]
pub extern "C" fn crypter_decrypt_with_password(
    password: CrypterCSlice,
    payload: CrypterCSlice,
) -> CrypterRustSlice {
    let password = try_slice!(password);
    let payload = try_slice!(payload);
    super::decrypt_with_password(password, payload)
        .map_or_else(CrypterRustSlice::null, CrypterRustSlice::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_free_protection() {
        let mut slice = CrypterRustSlice::from(vec![1, 2, 3]);
        slice.crypter_free_slice();
        assert_eq!(slice.ptr, std::ptr::null());
        assert_eq!(slice.len, 0);
        assert_eq!(slice.cap, 0);

        slice.crypter_free_slice();
        assert_eq!(slice.ptr, std::ptr::null());
        assert_eq!(slice.len, 0);
        assert_eq!(slice.cap, 0);
    }

    #[test]
    fn free_empty_rust_slice() {
        let mut slice = CrypterRustSlice::from(Vec::new());
        slice.crypter_free_slice();
        assert_eq!(slice.ptr, std::ptr::null());
        assert_eq!(slice.len, 0);
        assert_eq!(slice.cap, 0);
    }
}
