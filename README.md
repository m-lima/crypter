# crypter

[![Github](https://github.com/m-lima/crypter/actions/workflows/check.yml/badge.svg)](https://github.com/m-lima/crypter/actions/workflows/check.yml)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cargo](https://img.shields.io/crates/v/crypter.svg)](https://crates.io/crates/crypter)
[![Documentation](https://docs.rs/crypter/badge.svg)](https://docs.rs/crypter)

The crypter crate provides Rust and FFI easy encryption and decryption using AES-GCM-SIV 256-bits.

## Features
| Name     | Description                                  |
| -------- | -------------------------------------------- |
| `ffi`    | Enables the C API                            |
| `wasm`   | Enables the WASM API                         |
| `stream` | Enables streamming for encryption/decryption |
| `argon`  | Enables key derivation using Argon2id        |

See the [examples](https://github.com/m-lima/crypter/blob/master/ffi/examples) for working FFI applications.

## Examples

```rust
let key = get_key();
let payload = "mega ultra safe payload";

let encrypted = crypter::encrypt(&key, payload).expect("Failed to encrypt");
let decrypted = crypter::decrypt(&key, encrypted).expect("Failed to decrypt");
println!("{}", String::from_utf8(decrypted).expect("Invalid decrypted string"));
```

## FFI examples
### C example: [example.c](https://github.com/m-lima/crypter/blob/master/ffi/examples/c/example.c)
```c
#include <stdio.h>
#include <string.h>

#include <crypter.h>

CrypterKey get_key();

int main() {
#include <stdio.h>

#include <crypter.h>

int main() {
  const char *payload = "mega ultra safe payload";

  CrypterKey key = get_key();

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
```

### Lua example: [example.lua](https://github.com/m-lima/crypter/blob/master/ffi/examples/lua/example.lua)
```lua
local ffi = require('ffi')

ffi.cdef [[
  typedef uint8_t Key[32];
  typedef struct Slice { const uint8_t *ptr; uintptr_t len; } Slice;
  typedef struct RustSlice { const uint8_t *ptr; uintptr_t len; uintptr_t cap; } RustSlice;

  RustSlice crypter_encrypt(const Key *key, struct Slice payload);
  RustSlice crypter_decrypt(const Key *key, struct Slice payload);
  void crypter_free_slice(struct RustSlice *slice);
]]

local function slice_from_str(text)
  return ffi.new('Slice', { ptr = ffi.cast('uint8_t *', text), len = #text })
end

local function relax_rust_slice(rust_slice)
  return ffi.new('Slice', { ptr = rust_slice.ptr, len = rust_slice.len })
end

crypter = ffi.load('crypter')

local key = require('my_key_getter').get_key()
local payload = 'mega ultra safe payload'
local payload_slice = slice_from_str(payload)
local encrypted = crypter.crypter_encrypt(key, payload_slice)
local decrypted = crypter.crypter_decrypt(key, relax_rust_slice(encrypted))

if decrypted.ptr ~= nil then
  print(ffi.string(decrypted.ptr, decrypted.len))
else
  print('Failed roud trip')
end

crypter.crypter_free_slice(encrypted)
crypter.crypter_free_slice(decrypted)
```

### WASM example: [index.html](https://github.com/m-lima/crypter/blob/master/ffi/examples/wasm/index.html)
```html
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <title>crypter</title>
  </head>
  <body>
    <script type="module">
      import init from "./crypter.js";

      init("./crypter_bg.wasm").then(() => {
        const crypter = import('./crypter.js');
        crypter.then(c => {
          const encoder = new TextEncoder();
          const key = encoder.encode('super_mega_ultra_secret_01234567'); // Bad key. Just as an example
          const encrypted = c.encrypt(key, encoder.encode('mega ultra safe payload'));
          const decrypted = c.decrypt(key, encrypted);
          console.log('Encrypted: ', new TextDecoder().decode(decrypted));
        });
      });
    </script>
  </body>
</html>
```
