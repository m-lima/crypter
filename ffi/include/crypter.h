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
