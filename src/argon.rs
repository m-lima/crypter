//! Key derivation support for AES-GCM-SIV 256-bits using Argon2id.
//!
//! # Examples
//!
//! ```
//! let key = b"super secret key";
//! let payload = "mega ultra safe payload";
//!
//! let encrypted = crypter::encrypt_with_password(key, payload).expect("Failed to encrypt");
//! let decrypted = crypter::decrypt_with_password(key, encrypted).expect("Failed to decrypt");
//! println!("{}", String::from_utf8(decrypted).expect("Invalid decrypted string"));
//! ```

use crate::sizes;

fn derive_key<Key>(
    key: Key,
) -> Option<(
    aes_gcm_siv::Key<aes_gcm_siv::Aes256GcmSiv>,
    [u8; sizes::SALT_LEN],
)>
where
    Key: AsRef<[u8]>,
{
    let key = key.as_ref();
    let mut salt = [0; sizes::SALT_LEN];
    aes_gcm_siv::aead::rand_core::RngCore::fill_bytes(&mut aes_gcm_siv::aead::OsRng, &mut salt);
    let mut out = aes_gcm_siv::Key::<aes_gcm_siv::Aes256GcmSiv>::default();

    argon2::Argon2::default()
        .hash_password_into(key, &salt, &mut out)
        .ok()?;

    Some((out, salt))
}

/// Encrypts the payload with AES256 GCM SIV using a key derived from password with Argon2.
/// The iv and the salt are randomly generated for each call.
///
/// Returns [`None`] if an error occurred.
///
/// # Example
/// ```
/// let key = b"super secret key";
/// let payload = "supersecretpayload";
///
/// let encrypted = crypter::encrypt_with_password(key, payload);
/// ```
pub fn encrypt<Key, Payload>(key: Key, payload: Payload) -> Option<Vec<u8>>
where
    Key: AsRef<[u8]>,
    Payload: AsRef<[u8]>,
{
    use aes_gcm_siv::aead::AeadMutInPlace;
    use aes_gcm_siv::aead::KeyInit;

    let (key, salt) = derive_key(key)?;
    let payload = payload.as_ref();

    let nonce = <aes_gcm_siv::Aes256GcmSiv as aes_gcm_siv::aead::AeadCore>::generate_nonce(
        aes_gcm_siv::aead::rand_core::OsRng,
    );
    let mut cipher = aes_gcm_siv::Aes256GcmSiv::new(&key);

    let mut aad = [0; sizes::SALT_LEN + sizes::NONCE_LEN];
    aad[..sizes::SALT_LEN].copy_from_slice(&salt);
    aad[sizes::SALT_LEN..].copy_from_slice(&nonce);

    let mut buffer =
        Vec::with_capacity(payload.len() + sizes::SALT_LEN + sizes::NONCE_LEN + sizes::TAG_LEN);
    buffer.extend_from_slice(payload);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, &aad, &mut buffer)
        .ok()?;
    buffer.extend_from_slice(&aad);
    buffer.extend_from_slice(&tag);
    Some(buffer)
}

/// Decrypts the payload with AES256 GCM SIV using a key derived from password with Argon2.
///
/// Returns [`None`] if an error occurred.
///
/// # Example
/// ```
/// # fn get_encrypted_payload() -> &'static [u8] { &[] }
/// let key = b"super secret key";
/// let payload = get_encrypted_payload();
///
/// let encrypted = crypter::decrypt_with_password(key, payload);
/// ```
pub fn decrypt<Key, Payload>(key: Key, payload: Payload) -> Option<Vec<u8>>
where
    Key: AsRef<[u8]>,
    Payload: AsRef<[u8]>,
{
    use aes_gcm_siv::aead::AeadInPlace;
    use aes_gcm_siv::aead::KeyInit;

    let key = key.as_ref();
    let mut payload = payload.as_ref();

    if payload.len() < sizes::TAG_LEN + sizes::NONCE_LEN + sizes::SALT_LEN {
        return None;
    }

    let tag = aes_gcm_siv::Tag::from_slice(payload.split_off(payload.len() - sizes::TAG_LEN..)?);
    let aad = payload.split_off(payload.len() - sizes::SALT_LEN - sizes::NONCE_LEN..)?;
    // Safety: Checked just above that the size matches
    let (salt, nonce) = unsafe { aad.split_at_unchecked(sizes::SALT_LEN) };
    let nonce = aes_gcm_siv::Nonce::from_slice(nonce);

    let key = {
        let mut out = aes_gcm_siv::Key::<aes_gcm_siv::Aes256GcmSiv>::default();
        argon2::Argon2::default()
            .hash_password_into(key, salt, &mut out)
            .ok()?;
        out
    };

    let cipher = aes_gcm_siv::Aes256GcmSiv::new(&key);
    let mut buffer = Vec::from(payload);

    if cipher
        .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
        .is_ok()
    {
        Some(buffer)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = "super_secret_key";
        let payload = "super secret payload";

        let encrypted = encrypt(key, payload).unwrap();
        let decrypted = decrypt(key, encrypted).unwrap();

        let recovered = String::from_utf8(decrypted).unwrap();

        assert_eq!(recovered, payload);
    }
}
