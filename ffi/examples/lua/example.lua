local ffi = require('ffi')

ffi.cdef [[
  typedef struct Slice { uint8_t * ptr; size_t len; } Slice;
  typedef struct RustSlice { uint8_t * ptr; size_t len; size_t capacity; } RustSlice;

  RustSlice crypter_encrypt(struct Slice pass, struct Slice payload);
  RustSlice crypter_decrypt(struct Slice pass, struct Slice payload);
  void crypter_free_slice(struct RustSlice slice);
]]

local function slice_from_str(text)
  local slice = ffi.new('Slice')
  slice.ptr = ffi.cast('uint8_t *', text)
  slice.len = #text
  return slice, text
end

local function relax_rust_slice(rust_slice)
  local slice = ffi.new('Slice')

  slice.ptr = rust_slice.ptr
  slice.len = rust_slice.len
  return slice
end

-- Adapt this to your OS dynamic library format
local crypter = ffi.load('../../../target/release/libcrypter.dylib')

local pass, pass_ptr = slice_from_str('supersecret')
local payload, payload_ptr = slice_from_str('mega ultra safe payload')
local encrypted = crypter.crypter_encrypt(pass, payload)
local decrypted = crypter.crypter_decrypt(pass, relax_rust_slice(encrypted))

if decrypted.ptr ~= nil then
  print(ffi.string(decrypted.ptr, decrypted.len))
else
  print('Failed roud trip')
end

crypter.crypter_free_slice(encrypted)
crypter.crypter_free_slice(decrypted)
