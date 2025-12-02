#include <stdio.h>
#include <string.h>

#include <crypter.h>

int main() {
  const char *payload = "mega ultra safe payload";

  CrypterKey key = {0};

  CrypterRustSlice encrypted = crypter_encrypt(
      &key, (CrypterCSlice){.ptr = (const unsigned char *)payload,
                            .len = strlen(payload)});

  CrypterCSlice encrypted_slice = {.ptr = encrypted.ptr, .len = encrypted.len};

  CrypterRustSlice decrypted = crypter_decrypt(&key, encrypted_slice);

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

  crypter_free_slice(&encrypted);
  crypter_free_slice(&decrypted);
}
