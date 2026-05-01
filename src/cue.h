#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace cue {

using u8   = uint8_t;
using u16  = uint16_t;
using u32  = uint32_t;
using u64  = uint64_t;
using i32  = int32_t;
using b32  = int32_t;
using size = ptrdiff_t;

struct Arena {
  char* dat;
  char* beg;
  char* end;
};

struct Noun {
  union {
    struct { u64 val; u64 len; };
    struct { Noun* head; Noun* tail; };
  };
};

struct Map {
  Map*  child[4];
  u64   key;
  Noun* val;
};

enum CueRes : i32 {
  CUE_GOOD = 0,
  CUE_BACK = 1,
  CUE_GONE = 2,
  CUE_MEME = 3,
  CUE_FAIL = 4
};

Arena make_arena(size cap);
void  reset_arena(Arena* a);
void  free_arena(Arena* a);

bool  is_cell(const Noun* n);
Noun* head(Noun* n);
Noun* tail(Noun* n);

CueRes cue(const u8* buf, u64 len, Arena* perm, Arena* stack, Arena* scratch, Noun** out);

struct Timestamp {
  u64  day;
  u32  hour;
  u32  minute;
  u32  second;
  u64  fractions;
  size chunks;
};

struct Calendar {
  u64 year;
  b32 ad;
  u16 month;
  u16 day;
};

Timestamp to_timestamp(Noun* n);
Calendar  to_calendar(u64 day);
size      print_da(u8* buf, size cap, Noun* n);
size      print_cord(u8* buf, size cap, Noun* n);
size      print_wire(u8* buf, size cap, Noun* n);
size      print_noun(u8* buf, size cap, Noun* n);
size      print_request(u8* buf, size cap, Noun* n);

}  // namespace cue
