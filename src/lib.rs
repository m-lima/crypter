#![deny(warnings, clippy::pedantic, clippy::all, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! The crypter crate provides Rust and FFI for encryption and decryption using AES-GCM-SIV 256-bits.
//!
//! To enable the C api, the feature `ffi` must be enabled.
//! To enable the WASM api, the feature `wasm` must be enabled.
//! See the [examples](../../blob/master/ffi/examples) for working FFI applications.
//!
//! # Examples
//!
//! ```
//! # fn get_key() -> &'static [u8] { &[] }
//! let key = get_key();
//! let payload = "mega ultra safe payload";
//!
//! let encrypted = crypter::encrypt(key, payload).expect("Failed to encrypt");
//! let decrypted = crypter::decrypt(key, encrypted).expect("Failed to decrypt");
//! println!("{}", String::from_utf8(decrypted).expect("Invalid decrypted string"));
//! ```
//!
//! # FFI examples
//! ## C example: [example.c](../../blob/master/ffi/examples/c/example.c)
//! ```c
//! #include <stdio.h>
//! #include <string.h>
//!
//! #include <crypter.h>
//!
//! const char * get_key();
//!
//! int main() {
//!   const char *key = get_key();
//!   const char *payload = "mega ultra safe payload";
//!
//!   CrypterCSlice key_slice = {.ptr = (const unsigned char *)key, .len = strlen(key)};
//!
//!   CrypterRustSlice encrypted = crypter_encrypt(
//!       key_slice, (CrypterCSlice){.ptr = (const unsigned char *)payload,
//!                                  .len = strlen(payload)});
//!
//!   CrypterCSlice encrypted_slice = {.ptr = encrypted.ptr, .len = encrypted.len};
//!
//!   CrypterRustSlice decrypted = crypter_decrypt(key_slice, encrypted_slice);
//!
//!   if (decrypted.ptr) {
//!     for (int i = 0; i < decrypted.len; i++) {
//!       if (decrypted.ptr[i] == 0) {
//!         putchar('0');
//!       } else {
//!         putchar(decrypted.ptr[i]);
//!       }
//!     }
//!     putchar('\n');
//!   } else {
//!     puts("Null return");
//!   }
//!
//!   crypter_free_slice(encrypted);
//!   crypter_free_slice(decrypted);
//! }
//! ```
//!
//! ## Lua example: [example.lua](../../blob/master/ffi/examples/lua/example.lua)
//! ```lua
//! local ffi = require('ffi')
//!
//! ffi.cdef[[
//!   typedef struct Slice { uint8_t * ptr; size_t len; } Slice;
//!   typedef struct RustSlice { uint8_t * ptr; size_t len; size_t capacity; } RustSlice;
//!
//!   RustSlice crypter_encrypt(struct Slice key, struct Slice payload);
//!   RustSlice crypter_decrypt(struct Slice key, struct Slice payload);
//! ]]
//!
//! local function slice_from_str(text)
//!   local slice = ffi.new('Slice')
//!
//!   slice.ptr = ffi.cast('uint8_t *', text)
//!   slice.len = string.len(text)
//!   return slice
//! end
//!
//! local function relax_rust_slice(rust_slice)
//!   local slice = ffi.new('Slice')
//!
//!   slice.ptr = rust_slice.ptr
//!   slice.len = rust_slice.len
//!   return slice
//! end
//!
//! crypter = ffi.load('crypter')
//!
//! local key = require('my_key_getter').get_key()
//! local encrypted = crypter.crypter_encrypt(key, slice_from_str('mega ultra safe payload'))
//! local decrypted = crypter.crypter_decrypt(key, relax_rust_slice(encrypted))
//!
//! if decrypted.ptr ~= nil then
//!   print(ffi.string(decrypted.ptr, decrypted.len))
//! else
//!   print('Failed roud trip')
//! end
//! ```
//!
//! ## WASM example: [index.html](../../blob/master/ffi/examples/wasm/index.html)
//! ```html
//! <!DOCTYPE html>
//! <html>
//!   <head>
//!     <meta http-equiv="Content-type" content="text/html; charset=utf-8"/>
//!     <title>crypter</title>
//!   </head>
//!   <body>
//!     <script type="module">
//!       import init from "./crypter.js";
//!
//!       init("./crypter_bg.wasm").then(() => {
//!         const crypter = import('./crypter.js');
//!         crypter.then(c => {
//!           const encoder = new TextEncoder();
//!           const key = encoder.encode('supersecret'); // Bad key. Just as an example
//!           const encrypted = c.encrypt(key, encoder.encode('mega ultra safe payload'));
//!           const decrypted = c.decrypt(key, encrypted);
//!           console.log('Encrypted: ', new TextDecoder().decode(decrypted));
//!         });
//!       });
//!     </script>
//!   </body>
//! </html>
//! ```

/// Encrypts the payload with AES256 GCM SIV. The iv is randomly generated for each call
///
/// Returns [`None`] if an error occurred.
///
/// **Note:** There is no derivation of the key. It is simply hashed to allow variable lenghts.
/// It is assumed that all security precautions were taken with the `key` before calling this function.
///
/// # Example
/// ```
/// # fn get_key() -> &'static [u8] { &[] }
/// let key = get_key();
/// let payload = "supersecretpayload";
///
/// let encrypted = crypter::encrypt(key, payload);
/// ```
#[must_use]
pub fn encrypt<Key, Payload>(key: Key, payload: Payload) -> Option<Vec<u8>>
where
    Key: AsRef<[u8]>,
    Payload: AsRef<[u8]>,
{
    use aes_gcm_siv::aead::Aead;
    use aes_gcm_siv::aead::KeyInit;

    let key = key.as_ref();
    let payload = payload.as_ref();

    let nonce = nonce();
    let key = normalize_key(key);
    let cipher = aes_gcm_siv::Aes256GcmSiv::new(&key);

    cipher.encrypt(&nonce, payload).ok().map(|mut v| {
        v.extend(&nonce);
        v
    })
}

/// Decrypts the payload with AES256 GCM SIV
///
/// Returns [`None`] if an error occurred.
///
/// **Note:** There is no derivation of the key. It is simply hashed to allow variable lenghts.
/// It is assumed that all security precautions were taken with the `key` before calling this function.
///
/// # Example
/// ```
/// # fn get_key() -> &'static [u8] { &[] }
/// # fn get_encrypted_payload() -> &'static [u8] { &[] }
/// let key = get_key();
/// let payload = get_encrypted_payload();
///
/// let encrypted = crypter::encrypt(key, payload);
/// ```
#[must_use]
pub fn decrypt<Key, Payload>(key: Key, payload: Payload) -> Option<Vec<u8>>
where
    Key: AsRef<[u8]>,
    Payload: AsRef<[u8]>,
{
    use aes_gcm_siv::aead::Aead;
    use aes_gcm_siv::aead::KeyInit;

    let key = key.as_ref();
    let payload = payload.as_ref();

    let nonce = aes_gcm_siv::Nonce::from_slice(&payload[payload.len() - 12..]);
    let key = normalize_key(key);
    let cipher = aes_gcm_siv::Aes256GcmSiv::new(&key);

    cipher.decrypt(nonce, &payload[..payload.len() - 12]).ok()
}

/// Normalize the key into a 256 bit array
///
/// This is not a key derivation function, simply a convenience method to accept a &[u8] as input
/// for the key and normalizing it into the expected length.
fn normalize_key(key: &[u8]) -> aes_gcm_siv::Key<aes_gcm_siv::Aes256GcmSiv> {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(key);
    hasher.finalize()
}

fn nonce() -> aes_gcm_siv::Nonce {
    let mut nonce = [0; 12];
    aes_gcm_siv::aead::rand_core::RngCore::fill_bytes(&mut aes_gcm_siv::aead::OsRng, &mut nonce);
    aes_gcm_siv::Nonce::from(nonce)
}

#[cfg(feature = "stream")]
pub mod stream;

#[cfg(feature = "ffi")]
pub mod ffi {

    macro_rules! try_slice {
        ($slice:expr) => {
            if let Some(slice) = Option::<&[u8]>::from($slice) {
                slice
            } else {
                return CrypterRustSlice::null();
            }
        };
    }

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
            drop(unsafe { Vec::from_raw_parts(slice.ptr, slice.len, slice.capacity) });
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

    /// Encrypts the payload with AES256 GCM SIV. The iv is randomly generated for each call
    ///
    /// A wrapper around [`encrypt`](../fn.encrypt.html)
    ///
    /// # Safety
    ///
    /// This method does not take ownership of the parameters
    #[no_mangle]
    pub extern "C" fn crypter_encrypt<'a>(
        key: CrypterCSlice<'a>,
        payload: CrypterCSlice<'a>,
    ) -> CrypterRustSlice {
        let key = try_slice!(key);
        let payload = try_slice!(payload);
        super::encrypt(key, payload).map_or_else(CrypterRustSlice::null, CrypterRustSlice::from)
    }

    /// Decrypts the payload with AES256 GCM SIV
    ///
    /// A wrapper around [`decrypt`](../fn.decrypt.html)
    ///
    /// # Safety
    ///
    /// This method does not take ownership of the parameters
    #[no_mangle]
    pub extern "C" fn crypter_decrypt<'a>(
        key: CrypterCSlice<'a>,
        payload: CrypterCSlice<'a>,
    ) -> CrypterRustSlice {
        let key = try_slice!(key);
        let payload = try_slice!(payload);
        super::decrypt(key, payload).map_or_else(CrypterRustSlice::null, CrypterRustSlice::from)
    }
}

#[cfg(feature = "wasm")]
pub mod wasm {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    #[must_use]
    pub fn encrypt(key: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        super::encrypt(key, payload)
    }

    #[wasm_bindgen]
    #[must_use]
    #[allow(clippy::option_if_let_else)]
    pub fn decrypt(key: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        super::decrypt(key, payload)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn round_trip() {
        let key = "secret_string";
        let payload = "super secret payload";

        let encrypted = encrypt(key, payload).unwrap();
        let decrypted = decrypt(key, encrypted).unwrap();

        let recovered = String::from_utf8(decrypted).unwrap();

        assert_eq!(recovered, payload);
    }

    #[test]
    fn corrupted_byte() {
        let key = "secret_string";
        let payload = "super secret payload";

        let encrypted = encrypt(key, payload).unwrap();

        for i in 0..encrypted.len() {
            let mut corrupted = encrypted.clone();
            corrupted[i] = !corrupted[i];
            assert_eq!(decrypt(key, corrupted), None);
        }
    }
}
