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

-- Adapt this to your OS dynamic library format
crypter = ffi.load('../../../target/release/libcrypter.dylib')

local pass = slice_from_str('supersecret')
local encrypted = crypter.crypter_encrypt(pass, slice_from_str('mega ultra safe payload'))
local decrypted = crypter.crypter_decrypt(pass, relax_rust_slice(encrypted))

if decrypted.ptr ~= nil then
  print(ffi.string(decrypted.ptr, decrypted.len))
else
  print('Failed roud trip')
end
