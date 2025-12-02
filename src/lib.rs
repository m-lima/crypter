#![deny(warnings, clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! The crypter crate provides Rust and FFI easy encryption and decryption using AES-GCM-SIV 256-bits.
//!
//! To enable the C api, the feature `ffi` must be enabled.
//! To enable the WASM api, the feature `wasm` must be enabled.
//!
//! See the [examples](https://github.com/m-lima/crypter/blob/master/ffi/examples) for working FFI applications.
//!
//! # Examples
//!
//! ```
//! # fn get_key() -> aes_gcm_siv::Key<aes_gcm_siv::Aes256GcmSiv> { Default::default() }
//! let key = get_key();
//! let payload = "mega ultra safe payload";
//!
//! let encrypted = crypter::encrypt(&key, payload).expect("Failed to encrypt");
//! let decrypted = crypter::decrypt(&key, encrypted).expect("Failed to decrypt");
//! println!("{}", String::from_utf8(decrypted).expect("Invalid decrypted string"));
//! ```
//!
//! # FFI examples
//! ## C example: [example.c](https://github.com/m-lima/crypter/blob/master/ffi/examples/c/example.c)
//! ```c
//! #include <stdio.h>
//! #include <string.h>
//!
//! #include <crypter.h>
//!
//! CrypterKey get_key();
//!
//! int main() {
//! #include <stdio.h>
//!
//! #include <crypter.h>
//!
//! int main() {
//!   const char *payload = "mega ultra safe payload";
//!
//!   CrypterKey key = get_key();
//!
//!   CrypterRustSlice encrypted = crypter_encrypt(
//!       &key, (CrypterCSlice){.ptr = (const unsigned char *)payload,
//!                             .len = strlen(payload)});
//!
//!   CrypterCSlice encrypted_slice = {.ptr = encrypted.ptr, .len = encrypted.len};
//!
//!   CrypterRustSlice decrypted = crypter_decrypt(&key, encrypted_slice);
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
//!   crypter_free_slice(&encrypted);
//!   crypter_free_slice(&decrypted);
//! }
//! ```
//!
//! ## Lua example: [example.lua](https://github.com/m-lima/crypter/blob/master/ffi/examples/lua/example.lua)
//! ```lua
//! local ffi = require('ffi')
//!
//! ffi.cdef [[
//!   typedef uint8_t Key[32];
//!   typedef struct Slice { const uint8_t *ptr; uintptr_t len; } Slice;
//!   typedef struct RustSlice { const uint8_t *ptr; uintptr_t len; uintptr_t cap; } RustSlice;
//!
//!   RustSlice crypter_encrypt(const Key *key, struct Slice payload);
//!   RustSlice crypter_decrypt(const Key *key, struct Slice payload);
//!   void crypter_free_slice(struct RustSlice *slice);
//! ]]
//!
//! local function slice_from_str(text)
//!   return ffi.new('Slice', { ptr = ffi.cast('uint8_t *', text), len = #text })
//! end
//!
//! local function relax_rust_slice(rust_slice)
//!   return ffi.new('Slice', { ptr = rust_slice.ptr, len = rust_slice.len })
//! end
//!
//! crypter = ffi.load('crypter')
//!
//! local key = require('my_key_getter').get_key()
//! local payload = 'mega ultra safe payload'
//! local payload_slice = slice_from_str(payload)
//! local encrypted = crypter.crypter_encrypt(key, payload_slice)
//! local decrypted = crypter.crypter_decrypt(key, relax_rust_slice(encrypted))
//!
//! if decrypted.ptr ~= nil then
//!   print(ffi.string(decrypted.ptr, decrypted.len))
//! else
//!   print('Failed roud trip')
//! end
//!
//! crypter.crypter_free_slice(encrypted)
//! crypter.crypter_free_slice(decrypted)
//! ```
//!
//! ## WASM example: [index.html](https://github.com/m-lima/crypter/blob/master/ffi/examples/wasm/index.html)
//! ```html
//! <!DOCTYPE html>
//! <html>
//!   <head>
//!     <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
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
//!           const key = encoder.encode('super_mega_ultra_secret_01234567'); // Bad key. Just as an example
//!           const encrypted = c.encrypt(key, encoder.encode('mega ultra safe payload'));
//!           const decrypted = c.decrypt(key, encrypted);
//!           console.log('Encrypted: ', new TextDecoder().decode(decrypted));
//!         });
//!       });
//!     </script>
//!   </body>
//! </html>
//! ```

#[cfg(feature = "argon")]
mod argon;
#[cfg(feature = "argon")]
pub use argon::decrypt as decrypt_with_password;
#[cfg(feature = "argon")]
pub use argon::encrypt as encrypt_with_password;

#[cfg(feature = "stream")]
pub mod stream;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "wasm")]
pub mod wasm;

mod sizes {
    use aes_gcm_siv::aead::generic_array::typenum::Unsigned;
    use aes_gcm_siv::{AeadCore, Aes256GcmSiv};

    pub(crate) const TAG_LEN: usize = <Aes256GcmSiv as AeadCore>::TagSize::USIZE;
    pub(crate) const NONCE_LEN: usize = <Aes256GcmSiv as AeadCore>::NonceSize::USIZE;

    #[cfg(feature = "argon")]
    pub(crate) const SALT_LEN: usize = argon2::RECOMMENDED_SALT_LEN;
}

/// Encrypts the payload with AES256 GCM SIV. The iv is randomly generated for each call.
///
/// Returns [`None`] if an error occurred.
///
/// # Example
/// ```
/// # fn get_key() -> aes_gcm_siv::Key<aes_gcm_siv::Aes256GcmSiv> { Default::default() }
/// let key = get_key();
/// let payload = "supersecretpayload";
///
/// let encrypted = crypter::encrypt(&key, payload);
/// ```
#[must_use]
pub fn encrypt<'k, Key, Payload>(key: Key, payload: Payload) -> Option<Vec<u8>>
where
    Key: Into<&'k aes_gcm_siv::Key<aes_gcm_siv::Aes256GcmSiv>>,
    Payload: AsRef<[u8]>,
{
    use aes_gcm_siv::aead::AeadMutInPlace;
    use aes_gcm_siv::aead::KeyInit;

    let key = key.into();
    let payload = payload.as_ref();

    let nonce = <aes_gcm_siv::Aes256GcmSiv as aes_gcm_siv::aead::AeadCore>::generate_nonce(
        aes_gcm_siv::aead::rand_core::OsRng,
    );
    let mut cipher = aes_gcm_siv::Aes256GcmSiv::new(key);

    let mut buffer = Vec::with_capacity(payload.len() + sizes::NONCE_LEN + sizes::TAG_LEN);
    buffer.extend_from_slice(payload);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, &nonce, &mut buffer)
        .ok()?;
    buffer.extend_from_slice(&nonce);
    buffer.extend_from_slice(&tag);
    Some(buffer)
}

/// Decrypts the payload with AES256 GCM SIV.
///
/// Returns [`None`] if an error occurred.
///
/// # Example
/// ```
/// # fn get_key() -> aes_gcm_siv::Key<aes_gcm_siv::Aes256GcmSiv> { Default::default() }
/// # fn get_encrypted_payload() -> &'static [u8] { &[] }
/// let key = get_key();
/// let payload = get_encrypted_payload();
///
/// let encrypted = crypter::decrypt(&key, payload);
/// ```
#[must_use]
pub fn decrypt<'k, Key, Payload>(key: Key, payload: Payload) -> Option<Vec<u8>>
where
    Key: Into<&'k aes_gcm_siv::Key<aes_gcm_siv::Aes256GcmSiv>>,
    Payload: AsRef<[u8]>,
{
    use aes_gcm_siv::aead::AeadInPlace;
    use aes_gcm_siv::aead::KeyInit;

    let key = key.into();
    let mut payload = payload.as_ref();

    if payload.len() < sizes::TAG_LEN + sizes::NONCE_LEN {
        return None;
    }

    let tag = aes_gcm_siv::Tag::from_slice(payload.split_off(payload.len() - sizes::TAG_LEN..)?);
    let nonce =
        aes_gcm_siv::Nonce::from_slice(payload.split_off(payload.len() - sizes::NONCE_LEN..)?);

    let cipher = aes_gcm_siv::Aes256GcmSiv::new(key);
    let mut buffer = Vec::from(payload);
    if cipher
        .decrypt_in_place_detached(nonce, nonce, &mut buffer, tag)
        .is_ok()
    {
        Some(buffer)
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn make_key() -> aes_gcm_siv::Key<aes_gcm_siv::Aes256GcmSiv> {
        <aes_gcm_siv::Aes256GcmSiv as aes_gcm_siv::KeyInit>::generate_key(aes_gcm_siv::aead::OsRng)
    }

    #[test]
    fn round_trip() {
        let key = make_key();
        let payload = "super secret payload";

        let encrypted = encrypt(&key, payload).unwrap();
        let decrypted = decrypt(&key, encrypted).unwrap();

        let recovered = String::from_utf8(decrypted).unwrap();

        assert_eq!(recovered, payload);
    }

    #[test]
    fn corrupted_byte() {
        let key = make_key();
        let payload = "super secret payload";

        let encrypted = encrypt(&key, payload).unwrap();

        for i in 0..encrypted.len() {
            let mut corrupted = encrypted.clone();
            corrupted[i] = !corrupted[i];
            assert_eq!(decrypt(&key, corrupted), None);
        }
    }
}
