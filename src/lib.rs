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
                return Slice::null();
            }
        };
    }

    pub struct NullPointer;

    #[repr(C)]
    #[derive(Copy, Clone, Debug)]
    pub struct Slice<'a, T> {
        ptr: *const T,
        len: usize,
        _lifetime: std::marker::PhantomData<&'a ()>,
    }

    impl<T> Slice<'_, T> {
        #[must_use]
        pub fn null() -> Self {
            Self {
                ptr: std::ptr::null(),
                len: 0,
                _lifetime: std::marker::PhantomData::default(),
            }
        }
    }

    impl<'a, T> From<Slice<'a, T>> for Option<&'a [T]> {
        fn from(slice: Slice<'a, T>) -> Self {
            if slice.ptr.is_null() {
                None
            } else {
                Some(unsafe { std::slice::from_raw_parts(slice.ptr, slice.len) })
            }
        }
    }

    impl<'a, T> From<Vec<T>> for Slice<'a, T> {
        fn from(vec: Vec<T>) -> Self {
            Self {
                ptr: vec.as_ptr(),
                len: vec.len(),
                _lifetime: std::marker::PhantomData::default(),
            }
        }
    }

    // Not used
    impl<'a, T> From<&'a [T]> for Slice<'a, T> {
        fn from(slice: &'a [T]) -> Self {
            Self {
                ptr: slice.as_ptr(),
                len: slice.len(),
                _lifetime: std::marker::PhantomData::default(),
            }
        }
    }

    // Not used
    impl<'a, T> std::convert::TryInto<&'a [T]> for Slice<'a, T> {
        type Error = NullPointer;

        fn try_into(self) -> Result<&'a [T], Self::Error> {
            if self.ptr.is_null() {
                Err(NullPointer)
            } else {
                Ok(unsafe { std::slice::from_raw_parts(self.ptr, self.len) })
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn encrypt<'a, 'r>(
        pass: Slice<'a, u8>,
        payload: Slice<'a, u8>,
    ) -> Slice<'r, u8> {
        let pass = try_slice!(pass.into());
        let payload = try_slice!(payload.into());

        {
            let pass = unsafe { String::from_utf8_unchecked(Vec::from(pass)) };
            let payload = unsafe { String::from_utf8_unchecked(Vec::from(payload)) };
            println!("Encrypt");
            println!("Pass: {:?}", pass);
            println!("Payload: {:?}", payload);
        }
        super::encrypt(pass, payload).map_or_else(Slice::null, Slice::from)
    }

    #[no_mangle]
    pub extern "C" fn decrypt<'a, 'r>(
        pass: Slice<'a, u8>,
        payload: Slice<'a, u8>,
    ) -> Slice<'r, u8> {
        let pass = try_slice!(pass.into());
        let payload = try_slice!(payload.into());
        super::decrypt(pass, payload).map_or_else(Slice::null, Slice::from)
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
