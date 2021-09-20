#include <stdio.h>
#include <string.h>

#include "crypter.h"

int main() {
  const char *pass = "1234567890123456";
  const char *payload = "bla ble bli blo blu";

  Slice_u8 pass_slice = {.ptr = pass, .len = strlen(pass)};

  Slice_u8 encrypted =
      encrypt(pass_slice, (Slice_u8){.ptr = payload, .len = strlen(payload)});

  Slice_u8 decrypted = decrypt(pass_slice, encrypted);

  if (decrypted.ptr) {
    for (int i = 0; i <= decrypted.len; i++) {
      if (decrypted.ptr[i] == 0) {
        putchar('0');
      } else {
        putchar(decrypted.ptr[i]);
      }
    }
    free(decrypted.ptr);
  } else {
    puts("Null return");
  }
}
