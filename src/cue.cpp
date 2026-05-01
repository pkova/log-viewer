// Port of the deserializer from log-explorer/main.c, cleaned up for C++.
// Implements jam/cue noun decoding plus the @da, cord, wire, and request
// pretty-printers used by the urbit event log viewer.

#include "cue.h"

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace cue {

namespace {

static Noun* const NONE = (Noun*)(uintptr_t)-1;

inline u32 mask3(u32 x) { return x & 0x7u; }

// Count trailing zeros of an 8-bit byte. clang/gcc have a builtin; MSVC
// has _BitScanForward which writes the index to its first arg and returns
// 0 when the input is 0 (undefined for our callers, who always pass nonzero).
inline u8 tz8(u8 x) {
#if defined(_MSC_VER)
  unsigned long idx;
  _BitScanForward(&idx, (unsigned long)x);
  return (u8)idx;
#else
  return (u8)__builtin_ctz((unsigned)x);
#endif
}
inline u64 mn(u64 a, u64 b) { return a < b ? a : b; }

void* arena_alloc(Arena* a, size objsize, size align, size count) {
  size padding = -(uintptr_t)a->beg & (align - 1);
  size avail   = a->end - a->beg - padding;
  if (avail < 0 || count > avail / objsize) {
    fprintf(stderr, "arena out of memory\n");
    abort();
  }
  void* p = a->beg + padding;
  a->beg += padding + count * objsize;
  memset(p, 0, count * objsize);
  return p;
}

#define NEW(a, T, n) (T*)arena_alloc((a), (size)sizeof(T), (size)alignof(T), (n))

void* arena_peek(Arena* a, size objsize) { return a->beg - objsize; }
void* arena_pop(Arena* a, size objsize)  { a->beg -= objsize; return a->beg - objsize; }

u64 hash64(u64 x) {
  x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
  x ^= x >> 27; x *= 0x94d049bb133111ebULL;
  x ^= x >> 31;
  return x;
}

bool map_get(Map** m, u64 key, Noun** out) {
  for (u64 h = hash64(key); *m; h <<= 2) {
    if (key == (*m)->key) { *out = (*m)->val; return true; }
    m = &(*m)->child[h >> 62];
  }
  return false;
}

bool map_upsert(Map** m, u64 key, Noun* val, Arena* a) {
  for (u64 h = hash64(key); *m; h <<= 2) {
    if (key == (*m)->key) return true;
    m = &(*m)->child[h >> 62];
  }
  *m = NEW(a, Map, 1);
  (*m)->key = key;
  (*m)->val = val;
  return false;
}

constexpr u64 CELL_BIT = 1ULL << 63;

enum CueTag { TAG_ATOM = 0, TAG_CELL = 1, TAG_BACK = 2 };

struct Reader {
  u64 left;
  u64 bits;
  u8  off;
  const u8* bytes;
};

struct CueFrame {
  Noun* ref;
  u64   bits;
};

CueRes bsr_meme(Reader* r) { r->bits += 256; r->bytes += 32; r->left -= 32; return CUE_MEME; }
CueRes bsr_gone(Reader* r, u8 bits) { r->bits += bits; r->bytes = nullptr; r->left = 0; r->off = 0; return CUE_GONE; }

CueRes bsr_log(Reader* r, u8* out) {
  u64 left = r->left;
  if (!left) return CUE_GONE;

  u8 off = r->off;
  const u8* b = r->bytes;
  u8 byt = b[0] >> off;
  u8 skip = 0;

  while (!byt) {
    if (skip == 32) return bsr_meme(r);
    byt = b[++skip];
    if (skip == left) return bsr_gone(r, (u8)((skip << 3) - off));
  }

  u32 zeros = tz8(byt) + (skip ? (u32)((skip << 3) - off) : 0);
  if (255 < zeros) return bsr_meme(r);

  u32 bits  = off + 1 + zeros;
  u8  bytes = (u8)(bits >> 3);
  left -= bytes;

  r->bytes = left ? (b + bytes) : nullptr;
  r->bits += 1 + zeros;
  r->left  = left;
  r->off   = (u8)mask3(bits);

  *out = (u8)zeros;
  return CUE_GOOD;
}

u64 bsr64_any(Reader* r, u8 len) {
  u64 left = r->left;
  if (len > 64) len = 64;
  r->bits += len;
  if (!left) return 0;

  u8 off  = r->off;
  u8 rest = (u8)(8 - off);
  u64 m   = r->bytes[0] >> off;

  if (len < rest) {
    r->off = (u8)(off + len);
    return m & (((u64)1 << len) - 1);
  }

  len -= rest;
  left--;
  const u8* b = ++r->bytes;

  u8 len_byt = (u8)(len >> 3);
  if (len_byt >= left) {
    len_byt   = (u8)left;
    r->off    = off = 0;
    r->left   = 0;
    r->bytes  = nullptr;
  } else {
    r->off    = off = (u8)mask3(len);
    r->left   = left - len_byt;
    r->bytes += len_byt;
  }

  u8 mask = (u8)((1 << off) - 1);
  u64 l = 0;
  switch (len_byt) {
    case 8: l = (u64)b[0] ^ (u64)b[1]<<8 ^ (u64)b[2]<<16 ^ (u64)b[3]<<24
                ^ (u64)b[4]<<32 ^ (u64)b[5]<<40 ^ (u64)b[6]<<48 ^ (u64)b[7]<<56; break;
    case 7: l = (u64)b[0] ^ (u64)b[1]<<8 ^ (u64)b[2]<<16 ^ (u64)b[3]<<24
                ^ (u64)b[4]<<32 ^ (u64)b[5]<<40 ^ (u64)b[6]<<48;
            if (mask) l ^= (u64)(b[7] & mask) << 56; break;
    case 6: l = (u64)b[0] ^ (u64)b[1]<<8 ^ (u64)b[2]<<16 ^ (u64)b[3]<<24
                ^ (u64)b[4]<<32 ^ (u64)b[5]<<40;
            if (mask) l ^= (u64)(b[6] & mask) << 48; break;
    case 5: l = (u64)b[0] ^ (u64)b[1]<<8 ^ (u64)b[2]<<16 ^ (u64)b[3]<<24
                ^ (u64)b[4]<<32;
            if (mask) l ^= (u64)(b[5] & mask) << 40; break;
    case 4: l = (u64)b[0] ^ (u64)b[1]<<8 ^ (u64)b[2]<<16 ^ (u64)b[3]<<24;
            if (mask) l ^= (u64)(b[4] & mask) << 32; break;
    case 3: l = (u64)b[0] ^ (u64)b[1]<<8 ^ (u64)b[2]<<16;
            if (mask) l ^= (u64)(b[3] & mask) << 24; break;
    case 2: l = (u64)b[0] ^ (u64)b[1]<<8;
            if (mask) l ^= (u64)(b[2] & mask) << 16; break;
    case 1: l = (u64)b[0];
            if (mask) l ^= (u64)(b[1] & mask) << 8;  break;
    case 0: l = mask ? (u64)(b[0] & mask) : 0;       break;
  }
  return m ^ (l << rest);
}

CueRes bsr_rub_len(Reader* r, u64* out) {
  u8 len;
  CueRes res = bsr_log(r, &len);
  if (res != CUE_GOOD) return res;
  if (len >= 64)       return CUE_MEME;
  switch (len) {
    case 0: *out = 0; break;
    case 1: *out = 1; break;
    default:
      len--;
      *out = bsr64_any(r, len) ^ (1ULL << len);
      break;
  }
  return CUE_GOOD;
}

void bsr_bytes_any(Reader* r, u64 len, u8* out) {
  u64 left = r->left;
  r->bits += len;
  if (!left) return;

  const u8* b   = r->bytes;
  u8  off       = r->off;
  u64 len_byt   = len >> 3;
  u8  len_bit   = (u8)mask3((u32)len);
  u64 need      = len_byt + (len_bit ? 1 : 0);

  if (!off) {
    if (need > left) {
      memcpy(out, b, left);
      left = 0;
      r->bytes = nullptr;
    } else {
      memcpy(out, b, len_byt);
      off = len_bit;
      if (off) out[len_byt] = b[len_byt] & ((1 << off) - 1);
      left -= len_byt;
      r->bytes = left ? b + len_byt : nullptr;
    }
  } else {
    u8  rest = (u8)(8 - off);
    u64 last = left - 1;
    u64 max  = mn(last, len_byt);
    u8  m;
    for (u64 i = 0; i < max; i++) out[i] = (u8)((b[i] >> off) ^ (b[i + 1] << rest));
    b += max;
    m = (u8)(*b >> off);

    if (need >= left) {
      u8 bits = (u8)(len - (last << 3));
      if (bits < rest) {
        out[max] = m & ((1 << len_bit) - 1);
        r->bytes = b;
        left = 1;
        off  = (u8)(off + len_bit);
      } else {
        out[max] = m;
        r->bytes = nullptr;
        left = 0;
        off  = 0;
      }
    } else {
      u8 bits = (u8)(off + len_bit);
      u8 step = (u8)(!!(bits >> 3));
      r->bytes = b + step;
      left -= len_byt + step;
      off   = (u8)mask3(bits);
      if (len_bit) {
        if (len_bit <= rest) out[max] = m & ((1 << len_bit) - 1);
        else {
          u8 l = (u8)(*++b & ((1 << off) - 1));
          out[max] = (m ^ (u8)(l << rest)) & ((1 << len_bit) - 1);
        }
      }
    }
  }

  r->off  = off;
  r->left = left;
}

CueRes bsr_tag(Reader* r, CueTag* out) {
  u64 left = r->left;
  if (!left) return CUE_GONE;

  const u8* b = r->bytes;
  u8 off = r->off;
  u8 bit = (u8)((b[0] >> off) & 1);
  u8 len = 1;

  if (bit == 0) {
    *out = TAG_ATOM;
  } else {
    if (off == 7) {
      if (left == 1) return bsr_gone(r, 1);
      bit = (u8)(b[1] & 1);
    } else {
      bit = (u8)((b[0] >> (off + 1)) & 1);
    }
    len++;
    *out = (bit == 0) ? TAG_CELL : TAG_BACK;
  }

  u8 bits  = (u8)(off + len);
  u8 bytes = (u8)(bits >> 3);
  left -= bytes;

  if (!left) {
    r->bytes = nullptr;
    r->left  = 0;
    r->off   = 0;
  } else {
    r->bytes += bytes;
    r->left   = left;
    r->off    = (u8)mask3(bits);
  }
  r->bits += len;
  return CUE_GOOD;
}

CueRes cue_next(Arena* stack, Arena* scratch, Arena* perm, Reader* r, Map** m, Noun** out) {
  while (true) {
    u64 len, bit = r->bits;
    CueTag tag;
    CueRes res = bsr_tag(r, &tag);
    if (res != CUE_GOOD) return res;

    switch (tag) {
      case TAG_CELL: {
        CueFrame* f = NEW(stack, CueFrame, 1);
        f->ref = NONE;
        f->bits = bit;
        continue;
      }
      case TAG_BACK: {
        if ((res = bsr_rub_len(r, &len)) != CUE_GOOD) return res;
        if (len > 62) return CUE_MEME;
        u64 bak = bsr64_any(r, (u8)len);
        Noun* found;
        if (!map_get(m, bak, &found)) return CUE_BACK;
        *out = found;
        return CUE_GOOD;
      }
      case TAG_ATOM: {
        if ((res = bsr_rub_len(r, &len)) != CUE_GOOD) return res;
        if (len <= 63) {
          Noun* n = NEW(perm, Noun, 1);
          n->val = bsr64_any(r, (u8)len);
          n->len = (len + 7) / 8;
          *out = n;
        } else {
          u64 byt = (len + 7) / 8;
          if (byt > 0xffffffffULL) return CUE_MEME;
          u8* buf = NEW(perm, u8, byt);
          bsr_bytes_any(r, len, buf);
          Noun* n = NEW(perm, Noun, 1);
          n->val = (u64)(uintptr_t)buf;
          n->len = byt;
          *out = n;
        }
        map_upsert(m, bit, *out, scratch);
        return CUE_GOOD;
      }
      default:
        return CUE_FAIL;
    }
  }
}

}  // namespace

Arena make_arena(size cap) {
  Arena a{};
  a.dat = (char*)malloc((size_t)cap);
  a.beg = a.dat;
  a.end = a.dat + cap;
  return a;
}

void reset_arena(Arena* a) { a->beg = a->dat; }
void free_arena(Arena* a)  { free(a->dat); a->dat = a->beg = a->end = nullptr; }

bool  is_cell(const Noun* n) { return (n->val & CELL_BIT) != 0; }
Noun* head(Noun* n)          { return (Noun*)((u64)n->head & ~CELL_BIT); }
Noun* tail(Noun* n)          { return n->tail; }

CueRes cue(const u8* buf, u64 len, Arena* perm, Arena* stack, Arena* scratch, Noun** out) {
  Reader r{};
  r.bytes = buf;
  r.left  = len;

  Map* m = nullptr;
  Noun* n = nullptr;
  CueRes res = cue_next(stack, scratch, perm, &r, &m, &n);

  if (stack->beg > stack->dat && res == CUE_GOOD) {
    CueFrame* f = (CueFrame*)arena_peek(stack, sizeof(CueFrame));
    do {
      if (f->ref == NONE) {
        f->ref = n;
        res = cue_next(stack, scratch, perm, &r, &m, &n);
        f = (CueFrame*)arena_peek(stack, sizeof(CueFrame));
      } else {
        Noun* cell = NEW(perm, Noun, 1);
        cell->head = (Noun*)((u64)f->ref ^ CELL_BIT);
        cell->tail = n;
        n = cell;
        map_upsert(&m, f->bits, n, scratch);
        f = (CueFrame*)arena_pop(stack, sizeof(CueFrame));
      }
    } while (stack->beg > stack->dat && res == CUE_GOOD);
  }

  *out = n;
  return res;
}

// --------- pretty printing ---------

Timestamp to_timestamp(Noun* n) {
  Timestamp t{};
  t.chunks = 4;

  // n->val for >8-byte atoms holds a pointer; for atoms <=8 bytes it's the value.
  // The @da timestamp is 16 bytes (two u64s). It must be the heap-allocated form.
  u64* w = (u64*)(uintptr_t)n->val;
  t.fractions = w[0];
  if (t.fractions > 0) {
    while ((t.fractions & 0xffff) == 0) {
      t.fractions >>= 16;
      t.chunks--;
    }
  } else {
    t.chunks = 0;
  }

  u64 seconds = w[1];
  t.day    = seconds / 86400;
  t.second = (u32)(seconds % 86400);
  t.hour   = t.second / 3600; t.second %= 3600;
  t.minute = t.second / 60;   t.second %= 60;
  return t;
}

Calendar to_calendar(u64 day) {
  Calendar ger{};
  u64 era = day / 146097;
  day %= 146097;

  b32 lep;
  u64 cet;
  if (day <= 36524) { lep = 1; cet = 0; }
  else {
    lep = 0; cet = 1;
    day -= (36542 + 1);
    cet += day / 36542;
    day = day % 36542;
    ger.year += cet * 100;
  }
  ger.year += era * 400;

  u64 ner = 0;
  u64 dis = lep ? 366 : 365;
  while (day >= dis) {
    ner++;
    day -= dis;
    if (!(ner % 4)) { lep = 1; dis = 366; }
    else            { lep = 0; dis = 365; }
  }
  ger.year += ner;

  static const u16 mo_yo[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
  static const u16 my_yo[12] = {31,29,31,30,31,30,31,31,30,31,30,31};
  const u16* cah = lep ? my_yo : mo_yo;

  ger.month = 0;
  ger.day = (u16)day;
  while (ger.day >= cah[ger.month]) {
    ger.day = (u16)(ger.day - cah[ger.month]);
    ger.month++;
  }
  ger.day++;
  ger.month++;

  if (ger.year <= 292277024400ULL) {
    ger.year = 1 + 292277024400ULL - ger.year;
    ger.ad = 1;
  } else {
    ger.year -= 292277024400ULL;
    ger.ad = 1;
  }
  return ger;
}

static size da_size(const Timestamp* rip, const Calendar* ger) {
  size len = 0;
  if (rip->fractions > 0) {
    len += 4 * rip->chunks + rip->chunks;  // hex chunks + dots
    len += 1;                              // .
    len += 8 + 2;                          // hh.mm.ss + ..
  } else if (!(rip->hour == 0 && rip->minute == 0 && rip->second == 0)) {
    len += 8 + 2;
  }
  len += (ger->day  < 10) ? 1 : 2;
  len += 1;
  len += (ger->month < 10) ? 1 : 2;
  len += 1;
  len += (size)ceil(log10((double)ger->year)) + 1;
  if (!ger->ad) len += 1;
  len += 1;  // ~
  return len;
}

static const u8 dadict[64] = {
  '0','1','2','3','4','5','6','7','8','9',
  'a','b','c','d','e','f','g','h','i','j','k','l','m',
  'n','o','p','q','r','s','t','u','v','w','x','y','z',
  'A','B','C','D','E','F','G','H','I','J','K','L','M',
  'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
  '-','~'
};

static size write_da(Timestamp* rip, Calendar* ger, size len, u8* bof) {
  u8* buf = bof + (len - 1);

  if (rip->fractions > 0) {
    while (rip->chunks > 0) {
      u16 paf = (u16)(rip->fractions & 0xffff);
      rip->fractions >>= 16;
      *buf-- = dadict[(paf >> 0) & 0xf];
      *buf-- = dadict[(paf >> 4) & 0xf];
      *buf-- = dadict[(paf >> 8) & 0xf];
      *buf-- = dadict[(paf >> 12) & 0xf];
      *buf-- = '.';
      rip->chunks--;
    }
    *buf-- = '.';
  }

  if (buf < (bof + len - 1) ||
      !(rip->fractions == 0 && rip->hour == 0 && rip->minute == 0 && rip->second == 0)) {
    *buf-- = (u8)('0' + (rip->second % 10));
    *buf-- = (u8)('0' + (rip->second / 10));
    *buf-- = '.';
    *buf-- = (u8)('0' + (rip->minute % 10));
    *buf-- = (u8)('0' + (rip->minute / 10));
    *buf-- = '.';
    *buf-- = (u8)('0' + (rip->hour % 10));
    *buf-- = (u8)('0' + (rip->hour / 10));
    *buf-- = '.';
    *buf-- = '.';
  }

  *buf-- = (u8)('0' + (ger->day % 10));
  ger->day = (u16)(ger->day / 10);
  if (ger->day > 0) *buf-- = (u8)('0' + ger->day);
  *buf-- = '.';

  *buf-- = (u8)('0' + (ger->month % 10));
  ger->month = (u16)(ger->month / 10);
  if (ger->month > 0) *buf-- = (u8)('0' + ger->month);
  *buf-- = '.';

  if (!ger->ad) *buf-- = '-';

  while (ger->year > 0) {
    *buf-- = (u8)('0' + ger->year % 10);
    ger->year /= 10;
  }
  *buf = '~';

  size diff = buf - bof;
  if (diff > 0) {
    len -= diff;
    memmove(bof, buf, (size_t)len);
    memset(bof + len, 0, (size_t)diff);
  }
  return len;
}

size print_da(u8* buf, size cap, Noun* n) {
  if (cap == 0) return 0;
  // @da is a 128-bit atom: 16 raw bytes living on the heap. Anything else
  // (cells, smaller atoms, oversized atoms) is not a real urbit timestamp.
  if (is_cell(n) || n->len != 16) {
    return print_noun(buf, cap, n);
  }
  Timestamp t = to_timestamp(n);
  Calendar  c = to_calendar(t.day);
  size s = da_size(&t, &c);
  if (s + 1 > cap) s = cap - 1;
  buf[s] = 0;
  return write_da(&t, &c, s, buf);
}

size print_cord(u8* buf, size cap, Noun* n) {
  if (is_cell(n)) { if (cap > 0) buf[0] = 0; return 0; }
  size sz = (size)n->len;
  if (sz > cap - 1) sz = cap - 1;
  const u8* src = (n->len > 8) ? (const u8*)(uintptr_t)n->val : (const u8*)&n->val;
  memcpy(buf, src, (size_t)sz);
  if (sz < cap) buf[sz] = 0;
  return sz;
}

size print_wire(u8* buf, size cap, Noun* n) {
  if (cap == 0) return 0;
  if (!is_cell(n)) { buf[0] = 0; return 0; }
  size off = 0;
  Noun* cur = n;
  while (is_cell(cur) && off + 1 < cap) {
    buf[off++] = '/';
    off += print_cord(buf + off, cap - off, head(cur));
    cur = tail(cur);
  }
  if (off >= cap) off = cap - 1;
  buf[off] = 0;
  return off;
}

// Inspect an atom and decide whether it looks like a printable @tas / cord.
// Returns true if every byte is in the @tas alphabet (lowercase letter,
// digit, '-') and the atom is at least 2 bytes long. We deliberately skip
// 1-byte atoms because a single 'g' is much more likely to be a small
// integer than a real cord.
static bool atom_looks_tas(const Noun* n) {
  if (n->len < 2 || n->len > 64) return false;
  const u8* src = (n->len > 8) ? (const u8*)(uintptr_t)n->val : (const u8*)&n->val;
  for (u64 i = 0; i < n->len; i++) {
    u8 c = src[i];
    bool ok = (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
               c == '-';
    if (!ok) return false;
  }
  return true;
}

size print_noun(u8* buf, size cap, Noun* n) {
  if (cap < 2) { if (cap) buf[0] = 0; return 0; }
  size off = 0;

  if (is_cell(n)) {
    if (off + 1 < cap) buf[off++] = '[';
    off += print_noun(buf + off, cap - off, head(n));
    if (off + 1 < cap) buf[off++] = ' ';
    off += print_noun(buf + off, cap - off, tail(n));
    if (off + 1 < cap) buf[off++] = ']';
    buf[off] = 0;
    return off;
  }

  // @tas / cord: render as %name when the bytes look textual.
  if (atom_looks_tas(n)) {
    const u8* src = (n->len > 8) ? (const u8*)(uintptr_t)n->val : (const u8*)&n->val;
    if (off < cap) buf[off++] = '%';
    for (u64 i = 0; i < n->len && off + 1 < cap; i++) buf[off++] = src[i];
    buf[off] = 0;
    return off;
  }

  if (n->len > 8) {
    // Long opaque atom (mug hash, jam blob, ed25519 key, …): hex.
    for (u64 i = 0; i < n->len && off + 2 < cap; i++) {
      u8 byt = ((const u8*)(uintptr_t)n->val)[i];
      off += (size)snprintf((char*)buf + off, (size_t)(cap - off), "%02x", byt);
    }
    buf[off < cap ? off : cap - 1] = 0;
    return off;
  }

  int written = snprintf((char*)buf + off, (size_t)(cap - off), "%llu",
                         (unsigned long long)n->val);
  if (written < 0) written = 0;
  off += (size)written;
  if (off >= cap) off = cap - 1;
  buf[off] = 0;
  return off;
}

size print_request(u8* buf, size cap, Noun* n) {
  // The bespoke %request layout in log-explorer/main.c was tied to a specific
  // event log; here we just dump the noun. Specialized printers can be
  // re-added once we re-validate them against this log shape.
  return print_noun(buf, cap, n);
}

}  // namespace cue
