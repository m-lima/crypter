//! WASM bindings for `crypter`

use wasm_bindgen::prelude::*;

/// Encrypts the payload with AES256 GCM SIV. The iv is randomly generated for each call
/// The iv and the salt are randomly generated for each call.
///
/// A wrapper around [`encrypt`](../fn.encrypt.html)
#[wasm_bindgen]
pub fn encrypt(key: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    if key.len() != 32 {
        return None;
    }
    super::encrypt(key, payload)
}

/// Encrypts the payload with AES256 GCM SIV using a key derived from password with Argon2.
/// The iv and the salt are randomly generated for each call.
///
/// A wrapper around [`encrypt_with_password`](../fn.encrypt_with_password.html)
#[cfg(feature = "argon")]
#[wasm_bindgen]
pub fn encrypt_with_password(password: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    super::encrypt_with_password(password, payload)
}

/// Decrypts the payload with AES256 GCM SIV
///
/// A wrapper around [`decrypt`](../fn.decrypt.html)
#[wasm_bindgen]
pub fn decrypt(key: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    if key.len() != 32 {
        return None;
    }
    super::decrypt(key, payload)
}

/// Decrypts the payload with AES256 GCM SIV using a key derived from password with Argon2.
///
/// A wrapper around [`decrypt_with_password`](../fn.decrypt_with_password.html)
#[cfg(feature = "argon")]
#[wasm_bindgen]
pub fn crypter_decrypt_with_password(password: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    super::decrypt_with_password(password, payload)
}
