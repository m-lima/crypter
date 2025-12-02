//! Key derivation support for AES-GCM-SIV 256-bits using Argon2id.
//!
//! # Examples
//!
//! ```
//! let password = b"super secret password";
//! let payload = "mega ultra safe payload";
//!
//! let encrypted = crypter::encrypt_with_password(password, payload).expect("Failed to encrypt");
//! let decrypted = crypter::decrypt_with_password(password, encrypted).expect("Failed to decrypt");
//! println!("{}", String::from_utf8(decrypted).expect("Invalid decrypted string"));
//! ```

use crate::sizes;

pub(crate) type Salt = [u8; sizes::SALT_LEN];

pub(crate) fn derive_key<Password>(
    password: Password,
) -> Option<(aes_gcm_siv::Key<aes_gcm_siv::Aes256GcmSiv>, Salt)>
where
    Password: AsRef<[u8]>,
{
    let password = password.as_ref();
    let mut salt = [0; sizes::SALT_LEN];
    aes_gcm_siv::aead::rand_core::RngCore::fill_bytes(&mut aes_gcm_siv::aead::OsRng, &mut salt);
    let mut out = aes_gcm_siv::Key::<aes_gcm_siv::Aes256GcmSiv>::default();

    argon2::Argon2::default()
        .hash_password_into(password, &salt, &mut out)
        .ok()?;

    Some((out, salt))
}

pub(crate) fn derive_with_salt<Password>(
    password: Password,
    salt: &Salt,
) -> Option<aes_gcm_siv::Key<aes_gcm_siv::Aes256GcmSiv>>
where
    Password: AsRef<[u8]>,
    Salt: AsRef<[u8]>,
{
    let password = password.as_ref();

    let mut out = aes_gcm_siv::Key::<aes_gcm_siv::Aes256GcmSiv>::default();
    argon2::Argon2::default()
        .hash_password_into(password, salt, &mut out)
        .ok()?;

    Some(out)
}

/// Encrypts the payload with AES256 GCM SIV using a key derived from password with Argon2.
/// The iv and the salt are randomly generated for each call.
///
/// Returns [`None`] if an error occurred.
///
/// # Example
/// ```
/// let password = b"super secret password";
/// let payload = "supersecretpayload";
///
/// let encrypted = crypter::encrypt_with_password(password, payload);
/// ```
pub fn encrypt<Password, Payload>(password: Password, payload: Payload) -> Option<Vec<u8>>
where
    Password: AsRef<[u8]>,
    Payload: AsRef<[u8]>,
{
    use aes_gcm_siv::aead::AeadMutInPlace;
    use aes_gcm_siv::aead::KeyInit;

    let (key, salt) = derive_key(password)?;
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
/// let password = b"super secret password";
/// let payload = get_encrypted_payload();
///
/// let encrypted = crypter::decrypt_with_password(password, payload);
/// ```
pub fn decrypt<Password, Payload>(password: Password, payload: Payload) -> Option<Vec<u8>>
where
    Password: AsRef<[u8]>,
    Payload: AsRef<[u8]>,
{
    use aes_gcm_siv::aead::AeadInPlace;
    use aes_gcm_siv::aead::KeyInit;

    let mut payload = payload.as_ref();

    if payload.len() < sizes::TAG_LEN + sizes::NONCE_LEN + sizes::SALT_LEN {
        return None;
    }

    let tag = aes_gcm_siv::Tag::from_slice(payload.split_off(payload.len() - sizes::TAG_LEN..)?);
    let aad = payload.split_off(payload.len() - sizes::SALT_LEN - sizes::NONCE_LEN..)?;
    let mut salt = Salt::default();
    salt.copy_from_slice(&aad[..sizes::SALT_LEN]);
    let nonce = aes_gcm_siv::Nonce::from_slice(&aad[sizes::SALT_LEN..]);

    let key = derive_with_salt(password, &salt)?;

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
        let password = "super_secret_password";
        let payload = "super secret payload";

        let encrypted = encrypt(password, payload).unwrap();
        let decrypted = decrypt(password, encrypted).unwrap();

        let recovered = String::from_utf8(decrypted).unwrap();

        assert_eq!(recovered, payload);
    }
}
