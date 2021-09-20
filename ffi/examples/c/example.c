#include <stdio.h>
#include <string.h>

#include <crypter.h>

int main() {
  const char *pass = "supersecret";
  const char *payload = "mega ultra safe payload";

  CrypterCSlice pass_slice = {.ptr = (const unsigned char *)pass,
                              .len = strlen(pass)};

  CrypterRustSlice encrypted = crypter_encrypt(
      pass_slice, (CrypterCSlice){.ptr = (const unsigned char *)payload,
                                  .len = strlen(payload)});

  CrypterCSlice encrypted_slice = {.ptr = encrypted.ptr, .len = encrypted.len};

  CrypterRustSlice decrypted = crypter_decrypt(pass_slice, encrypted_slice);

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

  crypter_free_slice(encrypted);
  crypter_free_slice(decrypted);
}
