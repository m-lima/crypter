# crypter
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cargo](https://img.shields.io/crates/v/crypter.svg)](https://crates.io/crates/crypter)
[![Documentation](https://docs.rs/crypter/badge.svg)](https://docs.rs/crypter)

The crypter crate provides Rust and FFI for encryption and decryption using AES-GCM 256-bits.

To enable the C api, the feature `ffi` must be enabled.
To enable the WASM api, the feature `wasm` must be enabled.
See the [examples](../../blob/master/ffi/examples) for working FFI applications.

## Examples

```rust
let pass = "superscret";
let payload = "mega ultra safe payload";

let encrypted = crypter::encrypt(pass.as_bytes(), payload.as_bytes()).expect("Failed to encrypt");
let decrypted = crypter::decrypt(pass.as_bytes(), &encrypted).expect("Failed to decrypt");
println!("{}", String::from_utf8(decrypted).expect("Invalid decrypted string"));
```

## FFI examples
### C example: [example.c](../../blob/master/ffi/examples/c/example.c)
```c
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
```

### Lua example: [example.lua](../../blob/master/ffi/examples/lua/example.lua)
```lua
local ffi = require('ffi')

ffi.cdef[[
  typedef struct Slice { uint8_t * ptr; size_t len; } Slice;
  typedef struct RustSlice { uint8_t * ptr; size_t len; size_t capacity; } RustSlice;

  RustSlice crypter_encrypt(struct Slice pass, struct Slice payload);
  RustSlice crypter_decrypt(struct Slice pass, struct Slice payload);
]]

local function slice_from_str(text)
  local slice = ffi.new('Slice')

  slice.ptr = ffi.cast('uint8_t *', text)
  slice.len = string.len(text)
  return slice
end

local function relax_rust_slice(rust_slice)
  local slice = ffi.new('Slice')

  slice.ptr = rust_slice.ptr
  slice.len = rust_slice.len
  return slice
end

crypter = ffi.load('crypter')

local pass = slice_from_str('supersecret')
local encrypted = crypter.crypter_encrypt(pass, slice_from_str('mega ultra safe payload'))
local decrypted = crypter.crypter_decrypt(pass, relax_rust_slice(encrypted))

if decrypted.ptr ~= nil then
  print(ffi.string(decrypted.ptr, decrypted.len))
else
  print('Failed roud trip')
end
```

### WASM example: [index.html](../../blob/master/ffi/examples/wasm/index.html)
```html
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-type" content="text/html; charset=utf-8"/>
    <title>crypter</title>
  </head>
  <body>
    <script type="module">
      import init from "./crypter.js";

      init("./crypter_bg.wasm").then(() => {
        const crypter = import('./crypter.js')
        crypter.then(c => {
          const encoder = new TextEncoder();
          const pass = encoder.encode('supersecret');
          const encrypted = c.encrypt(pass, encoder.encode('mega ultra safe payload'));
          const decrypted = c.decrypt(pass, encrypted);
          console.log('Encrypted: ', new TextDecoder().decode(decrypted));
        });
      });
    </script>
  </body>
</html>
```
