#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct RustSlice {
  uint8_t *ptr;
  uintptr_t len;
  uintptr_t capacity;
} RustSlice;

typedef struct CSlice {
  const uint8_t *ptr;
  uintptr_t len;
} CSlice;

void rust_slice_free(struct RustSlice slice);

struct RustSlice encrypt(struct CSlice pass, struct CSlice payload);

struct RustSlice decrypt(struct CSlice pass, struct CSlice payload);
