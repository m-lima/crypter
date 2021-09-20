#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Slice_u8 {
  const uint8_t *ptr;
  uintptr_t len;
} Slice_u8;

struct Slice_u8 encrypt(struct Slice_u8 pass, struct Slice_u8 payload);

struct Slice_u8 decrypt(struct Slice_u8 pass, struct Slice_u8 payload);
