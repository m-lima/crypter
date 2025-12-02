local ffi = require('ffi')

ffi.cdef([[
  typedef uint8_t Key[32];
  typedef struct Slice { const uint8_t *ptr; uintptr_t len; } Slice;
  typedef struct RustSlice { const uint8_t *ptr; uintptr_t len; uintptr_t cap; } RustSlice;

  RustSlice crypter_encrypt(const Key *key, struct Slice payload);
  RustSlice crypter_decrypt(const Key *key, struct Slice payload);
  void crypter_free_slice(struct RustSlice *slice);
]])

local function slice_from_str(text)
  return ffi.new('Slice', { ptr = ffi.cast('uint8_t *', text), len = #text })
end

local function relax_rust_slice(rust_slice)
  return ffi.new('Slice', { ptr = rust_slice.ptr, len = rust_slice.len })
end

-- Adapt this to your OS dynamic library format
local crypter = ffi.load('../../../target/release/libcrypter.so')

local key = ffi.cast('const uint8_t (*)[32]', '0123456789abcdef0123456789abcdef')
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
