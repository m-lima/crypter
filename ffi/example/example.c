#include <stdio.h>
#include <string.h>

#include "crypter.h"

int main() {
  const char *pass = "1234567890123456";
  const char *payload = "bla ble bli blo blu";

  CSlice pass_slice = {.ptr = (const unsigned char *)pass, .len = strlen(pass)};

  RustSlice encrypted =
      encrypt(pass_slice, (CSlice){.ptr = (const unsigned char *)payload,
                                   .len = strlen(payload)});

  CSlice encrypted_slice = {.ptr = encrypted.ptr, .len = encrypted.len};

  RustSlice decrypted = decrypt(pass_slice, encrypted_slice);

  if (decrypted.ptr) {
    for (int i = 0; i < decrypted.len; i++) {
      if (decrypted.ptr[i] == 0) {
        putchar('0');
      } else {
        putchar(decrypted.ptr[i]);
      }
    }
    putchar('\n');
  } else {
    puts("Null return");
  }

  rust_slice_free(encrypted);
  rust_slice_free(decrypted);

  if (decrypted.ptr) {
    puts("Freed successfully");
  }
}
