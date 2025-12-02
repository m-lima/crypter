#pragma once

#include <stdint.h>

/**
 * Represents a slice of bytes owned by Rust.
 *
 * # Safety
 *
 * To free the memory [`crypter_free_slice`](CrypterRustSlice::crypter_free_slice) must be called.
 */
typedef struct CrypterRustSlice {
  const uint8_t *ptr;
  uintptr_t len;
  uintptr_t cap;
} CrypterRustSlice;

/**
 * Represents a AES256 GCM SIV key.
 */
typedef uint8_t CrypterKey[32];

/**
 * Represents a slice of bytes owned by the caller.
 */
typedef struct CrypterCSlice {
  const uint8_t *ptr;
  uintptr_t len;
} CrypterCSlice;

/**
 * Frees the slice of bytes owned by Rust.
 *
 * # Safety
 *
 * It may be unsafe to call `free()` on this slice as there is no guarantee of which allocator
 * was used.
 */
void crypter_free_slice(struct CrypterRustSlice *self);

/**
 * Encrypts the payload with AES256 GCM SIV. The iv is randomly generated for each call.
 *
 * A wrapper around [`encrypt`](../fn.encrypt.html)
 *
 * # Safety
 *
 * This method does not take ownership of the parameters.
 */
struct CrypterRustSlice crypter_encrypt(const CrypterKey *key, struct CrypterCSlice payload);

#if defined(CRYTER_ARGON)
/**
 * Encrypts the payload with AES256 GCM SIV using a key derived from password with Argon2.
 * The iv and the salt are randomly generated for each call.
 *
 * A wrapper around [`encrypt_with_password`](../fn.encrypt_with_password.html)
 *
 * # Safety
 *
 * This method does not take ownership of the parameters.
 */
struct CrypterRustSlice crypter_encrypt_with_password(struct CrypterCSlice password,
                                                      struct CrypterCSlice payload);
#endif

/**
 * Decrypts the payload with AES256 GCM SIV.
 *
 * A wrapper around [`decrypt`](../fn.decrypt.html).
 *
 * # Safety
 *
 * This method does not take ownership of the parameters.
 */
struct CrypterRustSlice crypter_decrypt(const CrypterKey *key, struct CrypterCSlice payload);

#if defined(CRYTER_ARGON)
/**
 * Decrypts the payload with AES256 GCM SIV using a key derived from password with Argon2.
 *
 * A wrapper around [`decrypt_with_password`](../fn.decrypt_with_password.html)
 *
 * # Safety
 *
 * This method does not take ownership of the parameters.
 */
struct CrypterRustSlice crypter_decrypt_with_password(struct CrypterCSlice password,
                                                      struct CrypterCSlice payload);
#endif
