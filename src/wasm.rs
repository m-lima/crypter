//! WASM bindings for `crypter`

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[must_use]
/// Encrypts the payload with AES256 GCM SIV. The iv is randomly generated for each call
///
/// A wrapper around [`encrypt`](../fn.encrypt.html)
pub fn encrypt(key: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    super::encrypt(key, payload)
}

#[wasm_bindgen]
#[must_use]
/// Decrypts the payload with AES256 GCM SIV
///
/// A wrapper around [`decrypt`](../fn.decrypt.html)
pub fn decrypt(key: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    super::decrypt(key, payload)
}
