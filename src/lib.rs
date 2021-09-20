type Nonce = [u8; 12];

// TODO: Test no_std
// TODO: Wrap panics (check warp c API)

fn nonce() -> Nonce {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// Encrypts the pyaload with AES256 GCM. The iv is randomly generated for each call
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

/// Decrypts the pyaload with AES256 GCM
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

pub mod c {

    macro_rules! try_slice {
        ($slice:expr) => {
            if let Some(slice) = $slice {
                slice
            } else {
                return RustSlice::null();
            }
        };
    }

    pub struct NullPointer;

    #[repr(C)]
    #[derive(Copy, Clone, Debug)]
    pub struct CSlice<'a> {
        ptr: *const u8,
        len: usize,
        _lifetime: std::marker::PhantomData<&'a ()>,
    }

    impl<'a> From<CSlice<'a>> for Option<&'a [u8]> {
        fn from(slice: CSlice<'a>) -> Self {
            if slice.ptr.is_null() {
                None
            } else {
                Some(unsafe { std::slice::from_raw_parts(slice.ptr, slice.len) })
            }
        }
    }

    #[repr(C)]
    #[derive(Copy, Clone, Debug)]
    pub struct RustSlice {
        ptr: *mut u8,
        len: usize,
        capacity: usize,
    }

    impl RustSlice {
        #[must_use]
        pub fn null() -> Self {
            Self {
                ptr: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn rust_slice_free(slice: RustSlice) {
        if !slice.ptr.is_null() {
            std::mem::drop(unsafe { Vec::from_raw_parts(slice.ptr, slice.len, slice.capacity) });
        }
    }

    // TODO: Use Vec::into_raw_parts() when available
    impl From<Vec<u8>> for RustSlice {
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

    #[no_mangle]
    pub extern "C" fn encrypt<'a>(pass: CSlice<'a>, payload: CSlice<'a>) -> RustSlice {
        let pass = try_slice!(pass.into());
        let payload = try_slice!(payload.into());
        super::encrypt(pass, payload).map_or_else(RustSlice::null, RustSlice::from)
    }

    #[no_mangle]
    pub extern "C" fn decrypt<'a>(pass: CSlice<'a>, payload: CSlice<'a>) -> RustSlice {
        let pass = try_slice!(pass.into());
        let payload = try_slice!(payload.into());
        super::decrypt(pass, payload).map_or_else(RustSlice::null, RustSlice::from)
    }
}

pub mod wasm {}

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
