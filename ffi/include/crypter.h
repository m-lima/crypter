#pragma once

#include <stdint.h>

/**
 * Represents a slice of bytes owned by Rust
 *
 * # Safety
 *
 * To free the memory [`crypter_free_slice`](fn.crypter_free_slice.html) must be called
 */
typedef struct CrypterRustSlice {
  uint8_t *ptr;
  uintptr_t len;
  uintptr_t capacity;
} CrypterRustSlice;

/**
 * Represents a slice of bytes owned by the caller
 */
typedef struct CrypterCSlice {
  const uint8_t *ptr;
  uintptr_t len;
} CrypterCSlice;

/**
 * Frees the slice of bytes owned by Rust
 *
 * # Safety
 *
 * It may be unsafe to call `free()` on this slice as there is no guarantee of which allocator
 * was used
 */
void crypter_free_slice(struct CrypterRustSlice slice);

/**
 * Encrypts the payload with AES256 GCM SIV. The iv is randomly generated for each call
 *
 * A wrapper around [`encrypt`](../fn.encrypt.html)
 *
 * # Safety
 *
 * This method does not take ownership of the parameters
 */
struct CrypterRustSlice crypter_encrypt(struct CrypterCSlice pass, struct CrypterCSlice payload);

/**
 * Decrypts the payload with AES256 GCM SIV
 *
 * A wrapper around [`decrypt`](../fn.decrypt.html)
 *
 * # Safety
 *
 * This method does not take ownership of the parameters
 */
struct CrypterRustSlice crypter_decrypt(struct CrypterCSlice pass, struct CrypterCSlice payload);
