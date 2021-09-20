#![deny(warnings, clippy::pedantic, clippy::all, rust_2018_idioms)]

type Nonce = [u8; 12];

fn nonce() -> Nonce {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// Encrypts the payload with AES256 GCM. The iv is randomly generated for each call
///
/// # Example
/// ```
/// let pass = "mysecret";
/// let payload = "supersecretpayload";
///
/// let encrypted = encrypt(pass.as_bytes(), payload.as_bytes());
/// ```
#[must_use]
pub fn encrypt(pass: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::Aead;
    use aes_gcm::aead::NewAead;
    use sha2::Digest;

    let secret = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(pass);
        hasher.finalize()
    };

    let nonce = GenericArray::from(nonce());
    let cipher = aes_gcm::Aes256Gcm::new(GenericArray::from_slice(&secret));

    cipher.encrypt(&nonce, payload).ok().map(|mut v| {
        v.extend(&nonce);
        v
    })
}

/// Decrypts the payload with AES256 GCM
///
/// # Example
/// ```
/// # fn get_encrypted_payload() -> &[u8] { &[] }
/// let pass = "mysecret";
/// let payload = get_encrypted_payload();
///
/// let encrypted = encrypt(pass.as_bytes(), payload);
/// ```
#[must_use]
pub fn decrypt(pass: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::Aead;
    use aes_gcm::aead::NewAead;
    use sha2::Digest;

    let secret = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(pass);
        hasher.finalize()
    };

    let mut nonce = [0; 12];
    nonce.copy_from_slice(&payload[payload.len() - 12..]);
    let nonce = GenericArray::from(nonce);

    let cipher = aes_gcm::Aes256Gcm::new(GenericArray::from_slice(&secret));

    cipher.decrypt(&nonce, &payload[..payload.len() - 12]).ok()
}

/// cbindgen:ignore-feature
#[cfg(feature = "ffi")]
pub mod ffi {

    macro_rules! try_slice {
        ($slice:expr) => {
            if let Some(slice) = $slice {
                slice
            } else {
                return CrypterRustSlice::null();
            }
        };
    }

    pub struct NullPointer;

    /// Represents a slice of bytes owned by the caller
    #[repr(C)]
    #[derive(Copy, Clone, Debug)]
    pub struct CrypterCSlice<'a> {
        ptr: *const u8,
        len: usize,
        _lifetime: std::marker::PhantomData<&'a ()>,
    }

    impl<'a> From<CrypterCSlice<'a>> for Option<&'a [u8]> {
        fn from(slice: CrypterCSlice<'a>) -> Self {
            if slice.ptr.is_null() {
                None
            } else {
                Some(unsafe { std::slice::from_raw_parts(slice.ptr, slice.len) })
            }
        }
    }

    /// Represents a slice of bytes owned by Rust
    ///
    /// # Safety
    ///
    /// To free the memory [`crypter_free_slice`](fn.crypter_free_slice.html) must be called
    #[repr(C)]
    #[derive(Copy, Clone, Debug)]
    pub struct CrypterRustSlice {
        ptr: *mut u8,
        len: usize,
        capacity: usize,
    }

    impl CrypterRustSlice {
        #[must_use]
        pub fn null() -> Self {
            Self {
                ptr: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
            }
        }
    }

    /// Frees the slice of bytes owned by Rust
    ///
    /// # Safety
    ///
    /// It may be unsafe to call `free()` on this slice as there is no guarantee of which allocator
    /// was used
    #[no_mangle]
    pub extern "C" fn crypter_free_slice(slice: CrypterRustSlice) {
        if !slice.ptr.is_null() {
            std::mem::drop(unsafe { Vec::from_raw_parts(slice.ptr, slice.len, slice.capacity) });
        }
    }

    // TODO: Use Vec::into_raw_parts() when available
    impl From<Vec<u8>> for CrypterRustSlice {
        fn from(mut vec: Vec<u8>) -> Self {
            let rust_slice = Self {
                ptr: vec.as_mut_ptr(),
                len: vec.len(),
                capacity: vec.capacity(),
            };
            std::mem::forget(vec);
            rust_slice
        }
    }

    /// Encrypts the payload with AES256 GCM. The iv is randomly generated for each call
    ///
    /// A wrapper around [`encrypt`](../fn.encrypt.html)
    ///
    /// # Safety
    ///
    /// This method does not take ownership of the parameters
    #[no_mangle]
    pub extern "C" fn crypter_encrypt<'a>(
        pass: CrypterCSlice<'a>,
        payload: CrypterCSlice<'a>,
    ) -> CrypterRustSlice {
        let pass = try_slice!(pass.into());
        let payload = try_slice!(payload.into());
        super::encrypt(pass, payload).map_or_else(CrypterRustSlice::null, CrypterRustSlice::from)
    }

    /// Decrypts the payload with AES256 GCM
    ///
    /// A wrapper around [`decrypt`](../fn.decrypt.html)
    ///
    /// # Safety
    ///
    /// This method does not take ownership of the parameters
    #[no_mangle]
    pub extern "C" fn crypter_decrypt<'a>(
        pass: CrypterCSlice<'a>,
        payload: CrypterCSlice<'a>,
    ) -> CrypterRustSlice {
        let pass = try_slice!(pass.into());
        let payload = try_slice!(payload.into());
        super::decrypt(pass, payload).map_or_else(CrypterRustSlice::null, CrypterRustSlice::from)
    }
}

#[cfg(feature = "wasm")]
pub mod wasm {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    #[must_use]
    pub fn encrypt(pass: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        super::encrypt(pass, payload)
    }

    #[wasm_bindgen]
    #[must_use]
    #[allow(clippy::option_if_let_else)]
    pub fn decrypt(pass: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        super::decrypt(pass, payload)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn round_trip() {
        let pass = "secret_string";
        let payload = "super secret payload";

        let encrypted = encrypt(pass.as_bytes(), payload.as_bytes()).unwrap();
        let decrypted = decrypt(pass.as_bytes(), &encrypted).unwrap();

        let recovered = String::from_utf8(decrypted).unwrap();

        assert_eq!(recovered, payload);
    }

    #[test]
    fn corrupted_byte() {
        let pass = "secret_string";
        let payload = "super secret payload";

        let encrypted = encrypt(pass.as_bytes(), payload.as_bytes()).unwrap();

        for i in 0..encrypted.len() {
            let mut corrupted = encrypted.clone();
            corrupted[i] = !corrupted[i];
            assert_eq!(decrypt(pass.as_bytes(), &corrupted), None);
        }
    }
}
