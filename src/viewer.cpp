#include "viewer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <functional>
#include <iterator>
#include <vector>

#include "imgui.h"
#include "patp.h"
#include "crypto.h"
#include "api.h"

namespace {
constexpr size_t kArenaCap   = 1u << 30;  // 1 GiB scratch (reset per event)
constexpr size_t kFormatCap  = 1u << 22;  // 4 MiB max formatted output
constexpr size_t kMaxWorkers = 4;         // each worker holds 3x kArenaCap virtual

std::string fmt_path_lock_warning(int err) {
  char buf[256];
  snprintf(buf, sizeof(buf), "lmdb error %d (%s)", err, mdb_strerror(err));
  return buf;
}

}  // namespace

// Set by --probe to dump decrypt intermediates to stderr. Lives at file
// scope (not in the anon namespace) so main.mm can flip it via extern.
bool g_debug_decrypt = false;

namespace {

void dump_hex(const char* label, const uint8_t* data, size_t len) {
  fprintf(stderr, "  %s [%zu]:", label, len);
  size_t shown = len > 96 ? 96 : len;
  for (size_t i = 0; i < shown; i++) {
    if ((i & 31) == 0) fprintf(stderr, "\n    ");
    else if ((i & 3) == 0) fprintf(stderr, " ");
    fprintf(stderr, "%02x", data[i]);
  }
  if (shown < len) fprintf(stderr, "\n    ...(+%zu)", len - shown);
  fprintf(stderr, "\n");
}

// ---- helpers for noun-shape-aware formatters ------------------------------
inline bool atom_bool(cue::Noun* n) {
  return n && !cue::is_cell(n) && n->val != 0;
}

inline uint64_t atom_u64(cue::Noun* n) {
  if (!n || cue::is_cell(n)) return 0;
  if (n->len <= 8) return n->val;
  uint64_t v = 0;
  memcpy(&v, (const void*)(uintptr_t)n->val, 8);
  return v;
}

inline const uint8_t* atom_bytes(cue::Noun* n) {
  if (!n || cue::is_cell(n)) return nullptr;
  return (n->len > 8) ? (const uint8_t*)(uintptr_t)n->val
                      : (const uint8_t*)&n->val;
}

void append_cord(std::string* dst, cue::Noun* n) {
  if (!n || cue::is_cell(n) || n->len == 0) return;
  size_t cap = (size_t)n->len > 64 * 1024 ? 64 * 1024 : (size_t)n->len;
  dst->append((const char*)atom_bytes(n), cap);
}

// Walk a (list [key=@t value=@t]) and append "  k: v\n" lines.
void append_header_list(std::string* s, cue::Noun* headers) {
  int count = 0;
  for (cue::Noun* h = headers; cue::is_cell(h); h = cue::tail(h)) {
    cue::Noun* entry = cue::head(h);
    if (!cue::is_cell(entry)) break;
    *s += "  ";
    append_cord(s, cue::head(entry));
    *s += ": ";
    append_cord(s, cue::tail(entry));
    *s += "\n";
    if (++count > 200) { *s += "  ... (truncated)\n"; break; }
  }
  if (count == 0) *s += "  (none)\n";
}

// Walk a tape — (list @tD) — and append the bytes as a string.
void append_tape(std::string* s, cue::Noun* tape) {
  size_t count = 0;
  for (cue::Noun* t = tape; cue::is_cell(t); t = cue::tail(t)) {
    cue::Noun* c = cue::head(t);
    if (cue::is_cell(c)) break;
    uint8_t ch = (uint8_t)(c->val & 0xff);
    if (ch) *s += (char)ch;
    if (++count > 64 * 1024) { *s += "...(tape truncated)"; return; }
  }
}

// Render a tank — hoon's pretty-print tree. Atoms are cords; cells are
// [%leaf tape] | [%rose [mid open close] (list tank)] | [%palm [mid open
// flat-open flat-close] (list tank)]. Roses render flat, palms multi-line.
void append_tank(std::string* s, cue::Noun* tank, int indent, int depth) {
  if (depth > 64) { *s += "(too deep)"; return; }

  if (!cue::is_cell(tank)) { append_cord(s, tank); return; }

  cue::Noun* tag  = cue::head(tank);
  cue::Noun* body = cue::tail(tank);
  std::string tag_s;
  if (!cue::is_cell(tag)) append_cord(&tag_s, tag);

  if (tag_s == "leaf") {
    append_tape(s, body);
    return;
  }

  if (tag_s == "rose") {
    if (!cue::is_cell(body)) return;
    cue::Noun* fmt      = cue::head(body);
    cue::Noun* children = cue::tail(body);
    std::string mid, open, close;
    if (cue::is_cell(fmt)) {
      append_tape(&mid, cue::head(fmt));
      cue::Noun* f2 = cue::tail(fmt);
      if (cue::is_cell(f2)) {
        append_tape(&open,  cue::head(f2));
        append_tape(&close, cue::tail(f2));
      }
    }
    *s += open;
    bool first = true;
    for (cue::Noun* l = children; cue::is_cell(l); l = cue::tail(l)) {
      if (!first) *s += mid;
      append_tank(s, cue::head(l), indent, depth + 1);
      first = false;
    }
    *s += close;
    return;
  }

  if (tag_s == "palm") {
    if (!cue::is_cell(body)) return;
    cue::Noun* fmt      = cue::head(body);
    cue::Noun* children = cue::tail(body);
    std::string mid, open, flat_open, flat_close;
    if (cue::is_cell(fmt)) {
      append_tape(&mid, cue::head(fmt));
      cue::Noun* f2 = cue::tail(fmt);
      if (cue::is_cell(f2)) {
        append_tape(&open, cue::head(f2));
        cue::Noun* f3 = cue::tail(f2);
        if (cue::is_cell(f3)) {
          append_tape(&flat_open,  cue::head(f3));
          append_tape(&flat_close, cue::tail(f3));
        }
      }
    }
    *s += open;
    int   new_indent = indent + 2;
    std::string pad(new_indent, ' ');
    bool first = true;
    for (cue::Noun* l = children; cue::is_cell(l); l = cue::tail(l)) {
      *s += "\n";
      *s += pad;
      if (first) *s += flat_open;
      else       *s += mid;
      append_tank(s, cue::head(l), new_indent, depth + 1);
      first = false;
    }
    *s += flat_close;
    return;
  }

  // Unknown tag — fall back to a raw noun dump for visibility.
  std::vector<uint8_t> tmp(4096);
  cue::print_noun(tmp.data(), tmp.size(), tank);
  *s += (const char*)tmp.data();
}

// Render a (unit octs) — `~` or `[~ size data]`. Heuristically decides
// between text and hex preview, capped at 4 KiB.
void append_unit_octs(std::string* s, cue::Noun* body) {
  if (!cue::is_cell(body)) { *s += "(none)"; return; }
  cue::Noun* p = cue::tail(body);
  if (!cue::is_cell(p))    { *s += "(empty)"; return; }
  cue::Noun* size_n = cue::head(p);
  cue::Noun* data_n = cue::tail(p);
  uint64_t bsize = atom_u64(size_n);
  char b[64];
  snprintf(b, sizeof(b), "%llu bytes\n", (unsigned long long)bsize);
  *s += b;
  if (cue::is_cell(data_n) || bsize == 0 || data_n->len == 0) return;

  size_t shown = (size_t)data_n->len;
  const uint8_t* src = atom_bytes(data_n);
  bool text = true;
  // Only sniff the first ~16KB for the printable-text test; that's more
  // than enough to classify and avoids a wasted scan over megabyte HTTP
  // responses.
  size_t sniff = shown > 16384 ? 16384 : shown;
  for (size_t i = 0; i < sniff; i++) {
    uint8_t c = src[i];
    if (c == 0 || (c < 0x20 && c != '\n' && c != '\r' && c != '\t')) {
      text = false; break;
    }
  }
  if (text) {
    s->append((const char*)src, shown);
  } else {
    s->reserve(s->size() + shown * 3);  // 2 hex chars + separator per byte
    char hb[4];
    for (size_t i = 0; i < shown; i++) {
      snprintf(hb, sizeof(hb), "%02x", src[i]);
      *s += hb;
      if      ((i & 31) == 31) *s += '\n';
      else if ((i &  1) ==  1) *s += ' ';
    }
  }
}

// Format a %request task body:  [secure=? =address =request:http]
// where request:http = [method url header-list body=(unit octs)]
//       address      = [%ipv4 @if] | [%ipv6 @is]
//
// On any unexpected shape, falls back to a raw noun dump so the user can
// still see *something*.
bool format_request(cue::Noun* e, std::string* out) {
  std::string& s = *out;
  s.clear();

  auto fail = [&]() {
    std::vector<uint8_t> tmp(kFormatCap);
    cue::print_noun(tmp.data(), tmp.size(), e);
    s = "(unrecognized %request shape)\n\n";
    s += (const char*)tmp.data();
  };

  if (!cue::is_cell(e)) { fail(); return false; }
  cue::Noun* secure = cue::head(e);
  cue::Noun* r1 = cue::tail(e);
  if (!cue::is_cell(r1)) { fail(); return false; }
  cue::Noun* address = cue::head(r1);
  cue::Noun* r2 = cue::tail(r1);
  if (!cue::is_cell(r2)) { fail(); return false; }
  cue::Noun* method = cue::head(r2);
  cue::Noun* r3 = cue::tail(r2);
  if (!cue::is_cell(r3)) { fail(); return false; }
  cue::Noun* url = cue::head(r3);
  cue::Noun* r4 = cue::tail(r3);
  if (!cue::is_cell(r4)) { fail(); return false; }
  cue::Noun* headers = cue::head(r4);
  cue::Noun* body = cue::tail(r4);

  // method + url first — that's what most users want at a glance.
  s += "method:  ";
  append_cord(&s, method);
  s += "\nurl:     ";
  append_cord(&s, url);
  s += "\n";

  s += "secure:  ";
  s += atom_bool(secure) ? "yes (https)" : "no (http)";
  s += "\n";

  s += "address: ";
  if (cue::is_cell(address)) {
    cue::Noun* tag = cue::head(address);
    cue::Noun* val = cue::tail(address);
    std::string tag_s;
    append_cord(&tag_s, tag);
    if (tag_s == "ipv4" && !cue::is_cell(val)) {
      uint32_t v = (uint32_t)atom_u64(val);
      char b[32];
      snprintf(b, sizeof(b), "%u.%u.%u.%u",
               (v >> 24) & 0xff, (v >> 16) & 0xff,
               (v >> 8)  & 0xff,  v        & 0xff);
      s += b;
    } else if (tag_s == "ipv6" && !cue::is_cell(val)) {
      // 16-byte atom, LSB-first bytes -> print MSB-first hex groups.
      uint8_t bytes[16] = {0};
      size_t n = (size_t)val->len; if (n > 16) n = 16;
      memcpy(bytes, atom_bytes(val), n);
      char b[64];
      snprintf(b, sizeof(b),
               "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
               "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
               bytes[15], bytes[14], bytes[13], bytes[12],
               bytes[11], bytes[10], bytes[9],  bytes[8],
               bytes[7],  bytes[6],  bytes[5],  bytes[4],
               bytes[3],  bytes[2],  bytes[1],  bytes[0]);
      s += b;
    } else {
      s += "%" + tag_s;
    }
  }
  s += "\n";

  s += "headers:\n";
  append_header_list(&s, headers);

  s += "body:    ";
  append_unit_octs(&s, body);
  return true;
}

// Format a %receive task body: [id=@ud =http-event:http] where http-event is
//   [%start response-header data=(unit octs) complete=?]
//   [%continue data=(unit octs) complete=?]
//   [%cancel ~]
// and response-header = [status-code=@ud headers=header-list].
bool format_receive(cue::Noun* e, std::string* out) {
  std::string& s = *out;
  s.clear();

  auto fail = [&]() {
    std::vector<uint8_t> tmp(kFormatCap);
    cue::print_noun(tmp.data(), tmp.size(), e);
    s = "(unrecognized %receive shape)\n\n";
    s += (const char*)tmp.data();
  };

  if (!cue::is_cell(e)) { fail(); return false; }
  cue::Noun* id_n  = cue::head(e);
  cue::Noun* ev    = cue::tail(e);
  if (!cue::is_cell(ev)) { fail(); return false; }
  cue::Noun* tag_n = cue::head(ev);
  cue::Noun* rest  = cue::tail(ev);

  std::string tag;
  append_cord(&tag, tag_n);

  char buf[64];
  snprintf(buf, sizeof(buf), "id:       %llu\n", (unsigned long long)atom_u64(id_n));
  s += "event:    %"; s += tag; s += "\n"; s += buf;

  if (tag == "start") {
    if (!cue::is_cell(rest)) { fail(); return false; }
    cue::Noun* rh   = cue::head(rest);
    cue::Noun* tail = cue::tail(rest);
    if (!cue::is_cell(rh) || !cue::is_cell(tail)) { fail(); return false; }
    cue::Noun* status_n  = cue::head(rh);
    cue::Noun* headers   = cue::tail(rh);
    cue::Noun* data      = cue::head(tail);
    cue::Noun* complete  = cue::tail(tail);

    snprintf(buf, sizeof(buf), "status:   %llu\n", (unsigned long long)atom_u64(status_n));
    s += buf;
    s += "complete: ";
    s += atom_bool(complete) ? "yes" : "no";
    s += "\nheaders:\n";
    append_header_list(&s, headers);
    s += "body:    ";
    append_unit_octs(&s, data);
  } else if (tag == "continue") {
    if (!cue::is_cell(rest)) { fail(); return false; }
    cue::Noun* data     = cue::head(rest);
    cue::Noun* complete = cue::tail(rest);
    s += "complete: ";
    s += atom_bool(complete) ? "yes" : "no";
    s += "\nbody:    ";
    append_unit_octs(&s, data);
  } else if (tag == "cancel") {
    s += "(cancelled)";
  } else {
    fail();
    return false;
  }
  return true;
}

// Parse a hex string into bytes (in the order they appear).
// Returns parsed length on success, 0 on error. `0x` / dots / whitespace ignored.
size_t parse_hex_any(const std::string& s, uint8_t* out, size_t out_cap) {
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  std::string cleaned;
  cleaned.reserve(s.size());
  for (size_t i = 0; i < s.size(); i++) {
    char c = s[i];
    if (c == '.' || c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
    if (i + 1 < s.size() && c == '0' && (s[i+1] == 'x' || s[i+1] == 'X')) { i++; continue; }
    cleaned += c;
  }
  // @ux aura strips leading zero nibbles, not just bytes — an odd-length
  // hex run means the top nibble is implicitly 0. Prepend it so the byte
  // boundary aligns.
  if (cleaned.size() % 2) cleaned.insert(cleaned.begin(), '0');
  size_t n = cleaned.size() / 2;
  if (n > out_cap) return 0;
  for (size_t i = 0; i < n; i++) {
    int hi = nibble(cleaned[2*i]), lo = nibble(cleaned[2*i + 1]);
    if (hi < 0 || lo < 0) return 0;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return n;
}

// Old API kept for callers that want a fixed length.
bool parse_hex(const std::string& s, size_t expected, uint8_t* out) {
  uint8_t tmp[256];
  if (expected > sizeof(tmp)) return false;
  return parse_hex_any(s, tmp, sizeof(tmp)) == expected
      && (memcpy(out, tmp, expected), true);
}

// Extract the 32-byte ENCRYPTION seed from a hex string. Accepts either:
//   - 32 bytes  (raw seed, used as-is)
//   - 65 bytes  (full $ring: 'B' magic + 32B signing + 32B crypto)
// In atom byte order:
//   atom-byte[0]      = magic 'B'
//   atom-bytes[1..32] = bod[0..31]   = signing seed   (`(end 8 bod)`)
//   atom-bytes[33..64] = bod[32..63] = crypto/encryption seed (`(cut 8 [1 1] bod)`)
// We auto-detect display byte order:
//   - first byte 0x42 → atom-LSB order, crypto seed is buf[33..64].
//   - last  byte 0x42 → @ux MSB-first display, atom-byte[i] = buf[64-i].
//                       Crypto seed in atom-byte order = buf[31..0].
// @ux aura strips leading zero bytes (high atom-bytes). If we get a
// partial ring whose trailing byte is the magic 'B', front-pad with zero
// bytes to fill in the implicit leading zeros before reading the seed.
// Returns true on success.
bool parse_seed(const std::string& hex, uint8_t out[32]) {
  uint8_t buf[80];
  size_t n = parse_hex_any(hex, buf, sizeof(buf));
  if (n == 32) { memcpy(out, buf, 32); return true; }

  if (n > 1 && n < 65 && buf[n - 1] == 0x42) {
    size_t pad = 65 - n;
    memmove(buf + pad, buf, n);
    memset(buf, 0, pad);
    n = 65;
  }

  if (n == 65) {
    if (buf[0]  == 0x42) { memcpy(out, buf + 33, 32); return true; }
    if (buf[64] == 0x42) {
      for (int i = 0; i < 32; i++) out[i] = buf[31 - i];
      return true;
    }
  }
  return false;
}

// Render a 4-byte (or 6-byte) routable address: low 32 bits = IPv4 (in
// network order: high octet first), bits 32..47 = port. This matches
// vere's u3_ames_decode_lane and the on-wire $origin field.
void append_addr48(std::string* s, uint64_t v) {
  uint32_t ip   = (uint32_t)v;
  uint16_t port = (uint16_t)(v >> 32);
  char b[64];
  snprintf(b, sizeof(b), "%u.%u.%u.%u:%u",
           (ip >> 24) & 0xff, (ip >> 16) & 0xff,
           (ip >> 8)  & 0xff,  ip        & 0xff, port);
  *s += b;
}

// Render a ship from `n` raw bytes (LSB-first, as on the wire) as @p.
void append_ship(std::string* s, const uint8_t* bytes, int n) {
  *s += patp::from_bytes(bytes, n);
}

// Forward decls: defined further down but referenced earlier.
void append_noun(std::string* s, cue::Noun* n);
void append_noun_pretty(std::string* s, cue::Noun* n, const std::string& indent);
void format_mesa_gage(std::string* s, cue::Noun* gage, const std::string& indent);
struct ResolvedPeer {
  uint8_t     pub[32];
  int         life = 0;
  bool        ok = false;
  bool        pending = false;  // fetch is in flight; not a hard failure
  std::string note;
};
using PeerResolver = std::function<ResolvedPeer(const std::string& patp)>;
struct HearKeys {
  bool          have_seed = false;
  uint8_t       our_seed[32]{};
  PeerResolver  resolve;
};

// Decode hoon @uv (base32, dot-separated, leading "0v") into the atom-LSB
// byte representation. The base32 alphabet is `0..9,a..v` (32 chars).
// Returns false if a non-alphabet character is encountered.
bool decode_uv(const char* in, size_t in_len, std::vector<uint8_t>* out) {
  // Strip leading "0v".
  if (in_len >= 2 && in[0] == '0' && in[1] == 'v') { in += 2; in_len -= 2; }
  // Bit accumulator, LSB-first into `out`.
  uint64_t acc = 0;
  int      acc_bits = 0;
  // We need to read digits MSB-first into the value, but the value's atom
  // bytes are LSB-first. Easiest: walk RIGHT TO LEFT — the rightmost digit
  // is the lowest base-32 digit (least significant), which corresponds to
  // bits 0..4 of the value (= atom-byte 0 low nibble).
  out->clear();
  // intptr_t (signed, pointer-sized) instead of ssize_t — MSVC has no ssize_t.
  for (intptr_t i = (intptr_t)in_len - 1; i >= 0; i--) {
    char c = in[i];
    if (c == '.') continue;
    int d;
    if      (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'v') d = c - 'a' + 10;
    else return false;
    acc |= (uint64_t)d << acc_bits;
    acc_bits += 5;
    while (acc_bits >= 8) {
      out->push_back((uint8_t)(acc & 0xff));
      acc >>= 8;
      acc_bits -= 8;
    }
  }
  if (acc_bits > 0) out->push_back((uint8_t)(acc & 0xff));
  // Strip trailing zero bytes (atom convention).
  while (!out->empty() && out->back() == 0) out->pop_back();
  return true;
}

// ---- mesa (%heer) packet parsing ------------------------------------------
//
// Mirrors `mesa_sift_head` / `_mesa_sift_name` / `_mesa_sift_data` in
// vere/pkg/vere/io/mesa/pact.c. UIP 0113 specifies the over-the-wire layout:
// 4-byte header + 4-byte MESA_COOKIE + body. The body is per packet type
// (peek/poke/page) and uses variable-length integer encoding for fields.

constexpr uint32_t kMesaCookie = 0x67e00200u;

// Bit-stream reader matching vere's u3_sifter: pulls bits LSB-first across
// byte boundaries, with byte-aligned reads whenever the consumer asks for
// bytes after a multiple-of-8 number of bits.
struct MesaReader {
  const uint8_t* buf;
  size_t         len;
  size_t         pos = 0;     // index into buf
  uint64_t       bit_cache = 0;
  int            cache_bits = 0;
  bool           failed = false;

  uint64_t bits(int n) {
    while (cache_bits < n) {
      if (pos >= len) { failed = true; return 0; }
      bit_cache |= (uint64_t)buf[pos++] << cache_bits;
      cache_bits += 8;
    }
    uint64_t r = bit_cache & ((n == 64) ? ~0ULL : ((1ULL << n) - 1));
    bit_cache >>= n;
    cache_bits -= n;
    return r;
  }
  // After bit-aligned reads the cache should be empty before byte ops.
  uint8_t byte() {
    if (cache_bits != 0) { failed = true; return 0; }
    if (pos >= len)      { failed = true; return 0; }
    return buf[pos++];
  }
  uint16_t short_le() {
    uint8_t a = byte(); uint8_t b = byte();
    return (uint16_t)a | ((uint16_t)b << 8);
  }
  uint32_t var_word(int n) {
    uint32_t v = 0;
    for (int i = 0; i < n; i++) v |= (uint32_t)byte() << (8 * i);
    return v;
  }
  uint64_t var_chub(int n) {
    uint64_t v = 0;
    for (int i = 0; i < n; i++) v |= (uint64_t)byte() << (8 * i);
    return v;
  }
  const uint8_t* take(size_t n) {
    if (cache_bits != 0) { failed = true; return nullptr; }
    if (pos + n > len)   { failed = true; return nullptr; }
    const uint8_t* p = buf + pos;
    pos += n;
    return p;
  }
};

struct MesaName {
  uint8_t        ran;        // rank (0..3 → 2/4/8/16-byte ship)
  uint32_t       rif;        // rift
  bool           init;
  bool           aut;
  uint8_t        boq;        // fragment bloq exponent (typically 13)
  uint64_t       fra;        // fragment number (omitted when init)
  uint16_t       path_len;
  const uint8_t* path;
  int            ship_size;  // 2 << ran
  const uint8_t* ship_bytes; // pointer into the buffer
};

bool sift_mesa_name(MesaReader* r, MesaName* nm) {
  uint8_t meta_ran = (uint8_t)r->bits(2);
  uint8_t meta_rif = (uint8_t)r->bits(2);
  uint8_t meta_nit = (uint8_t)r->bits(1);
  uint8_t meta_tau = (uint8_t)r->bits(1);
  uint8_t meta_gaf = (uint8_t)r->bits(2);
  if (r->failed) return false;
  nm->ran   = meta_ran;
  nm->init  = (meta_nit == 1);
  nm->aut   = (meta_tau == 1);
  nm->ship_size  = 2 << meta_ran;
  nm->ship_bytes = r->take((size_t)nm->ship_size);
  if (!nm->ship_bytes) return false;
  nm->rif = r->var_word(meta_rif + 1);
  nm->boq = r->byte();
  if (nm->init) {
    nm->fra = 0;
  } else {
    nm->fra = r->var_chub(1 << meta_gaf);
  }
  nm->path_len = r->short_le();
  nm->path     = r->take(nm->path_len);
  return !r->failed;
}

void append_mesa_name(std::string* s, const MesaName& nm, const char* indent) {
  char buf[160];
  snprintf(buf, sizeof(buf), "%spublisher:  ", indent); *s += buf;
  *s += patp::from_bytes(nm.ship_bytes, nm.ship_size);
  snprintf(buf, sizeof(buf), "  (rift=%u)\n", nm.rif); *s += buf;
  snprintf(buf, sizeof(buf), "%sboq:        %u (fragment size = %llu bytes)\n",
           indent, nm.boq, 1ULL << nm.boq);
  *s += buf;
  if (nm.init) {
    snprintf(buf, sizeof(buf), "%sinit:       yes (no fragment number)\n", indent);
    *s += buf;
  } else {
    snprintf(buf, sizeof(buf), "%sfragment:   #%llu\n", indent,
             (unsigned long long)nm.fra);
    *s += buf;
    snprintf(buf, sizeof(buf), "%saut:        %s\n", indent, nm.aut ? "yes" : "no");
    *s += buf;
  }
  snprintf(buf, sizeof(buf), "%spath:       %u bytes  ", indent, nm.path_len);
  *s += buf;
  // Path is stored as plain ASCII bytes per mesa convention.
  if (nm.path && nm.path_len) {
    s->push_back('\'');
    s->append((const char*)nm.path, nm.path_len);
    s->push_back('\'');
  }
  *s += "\n";
}

struct MesaData {
  uint64_t total_bytes;     // tob_d: total payload size
  uint8_t  auth_kind;       // 0=sign(64), 1=hmac(16), 2=none, 3=pair(64)
  const uint8_t* auth;
  uint32_t frag_len;
  const uint8_t* frag;
};

bool sift_mesa_data(MesaReader* r, MesaData* d) {
  uint8_t meta_bot = (uint8_t)r->bits(2);
  uint8_t meta_aut = (uint8_t)r->bits(1);
  uint8_t meta_auv = (uint8_t)r->bits(1);
                     r->bits(2);  // unused
  uint8_t meta_men = (uint8_t)r->bits(2);
  if (r->failed) return false;
  d->total_bytes = r->var_chub(1 << meta_bot);
  // aut_o/auv_o are hoon loobeans: 0 = yes (c3y), 1 = no (c3n).
  //   aut=0,auv=0 → SIGN(64);  aut=0,auv=1 → HMAC(16)
  //   aut=1,auv=0 → NONE(0);   aut=1,auv=1 → PAIR(32+32)
  if (meta_aut == 0) {
    if (meta_auv == 0) { d->auth_kind = 0; d->auth = r->take(64); }
    else               { d->auth_kind = 1; d->auth = r->take(16); }
  } else {
    if (meta_auv == 0) { d->auth_kind = 2; d->auth = nullptr; }
    else               { d->auth_kind = 3; d->auth = r->take(64); }
  }
  uint8_t nel = meta_men;
  if (meta_men == 3) nel = r->byte();
  d->frag_len = r->var_word(nel);
  d->frag     = r->take(d->frag_len);
  return !r->failed;
}

void append_mesa_data(std::string* s, const MesaData& d, const char* indent) {
  char buf[160];
  snprintf(buf, sizeof(buf), "%stotal:      %llu bytes\n", indent,
           (unsigned long long)d.total_bytes); *s += buf;
  const char* ak = "?";
  size_t auth_len = 0;
  switch (d.auth_kind) {
    case 0: ak = "sign (ed25519, 64B)"; auth_len = 64; break;
    case 1: ak = "hmac (16B)";          auth_len = 16; break;
    case 2: ak = "none";                auth_len = 0;  break;
    case 3: ak = "pair (32+32B hash)";  auth_len = 64; break;
  }
  snprintf(buf, sizeof(buf), "%sauth:       %s\n", indent, ak); *s += buf;
  if (d.auth && auth_len) {
    snprintf(buf, sizeof(buf), "%s  ", indent); *s += buf;
    char hb[3];
    for (size_t i = 0; i < auth_len && i < 32; i++) {
      snprintf(hb, sizeof(hb), "%02x", d.auth[i]); *s += hb;
    }
    if (auth_len > 32) *s += "...";
    *s += "\n";
  }
  snprintf(buf, sizeof(buf), "%sfragment:   %u bytes (this packet's slice)\n",
           indent, d.frag_len);
  *s += buf;
}

// Split a path-bytes blob like "chum/1/~dinleb-rambep/2/0v..." on '/'.
std::vector<std::string> split_path(const uint8_t* p, size_t n) {
  std::vector<std::string> out;
  size_t start = 0;
  for (size_t i = 0; i <= n; i++) {
    if (i == n || p[i] == '/') {
      out.emplace_back((const char*)p + start, i - start);
      start = i + 1;
    }
  }
  return out;
}

bool format_heer(cue::Noun* e, std::string* out, const HearKeys& keys) {
  std::string& s = *out;
  s.clear();

  auto fail = [&]() {
    std::vector<uint8_t> tmp(kFormatCap);
    cue::print_noun(tmp.data(), tmp.size(), e);
    s = "(unrecognized %heer shape)\n\n";
    s += (const char*)tmp.data();
  };

  if (!cue::is_cell(e)) { fail(); return false; }
  cue::Noun* lane = cue::head(e);
  cue::Noun* blob = cue::tail(e);

  // ---- lane = [%if ip port] -----------------------------------------------
  s += "lane:    ";
  if (cue::is_cell(lane)) {
    cue::Noun* tag = cue::head(lane);
    cue::Noun* rest = cue::tail(lane);
    char tagbuf[8] = {0};
    if (!cue::is_cell(tag)) {
      size_t n = (tag->len < sizeof(tagbuf) - 1) ? (size_t)tag->len : sizeof(tagbuf) - 1;
      memcpy(tagbuf, (tag->len > 8) ? (const uint8_t*)(uintptr_t)tag->val
                                    : (const uint8_t*)&tag->val, n);
    }
    if (strcmp(tagbuf, "if") == 0 && cue::is_cell(rest)) {
      uint32_t ip   = (uint32_t)atom_u64(cue::head(rest));
      uint16_t port = (uint16_t)atom_u64(cue::tail(rest));
      char b[64];
      snprintf(b, sizeof(b), "%u.%u.%u.%u:%u",
               (ip >> 24) & 0xff, (ip >> 16) & 0xff,
               (ip >> 8)  & 0xff,  ip        & 0xff, port);
      s += b;
    } else {
      append_noun(&s, lane);
    }
  } else {
    append_noun(&s, lane);
  }
  s += "\n";

  // ---- blob = raw mesa packet bytes ---------------------------------------
  if (cue::is_cell(blob) || blob->len < 8) {
    s += "(blob too short for mesa header)\n";
    return true;
  }
  size_t blob_size = (size_t)blob->len;
  const uint8_t* bytes = atom_bytes(blob);

  uint32_t hed = (uint32_t)bytes[0]
              | ((uint32_t)bytes[1] << 8)
              | ((uint32_t)bytes[2] << 16)
              | ((uint32_t)bytes[3] << 24);
  uint32_t cookie = (uint32_t)bytes[4]
                 | ((uint32_t)bytes[5] << 8)
                 | ((uint32_t)bytes[6] << 16)
                 | ((uint32_t)bytes[7] << 24);

  uint8_t  nex = (uint8_t)((hed >> 2)  & 0x3);
  uint8_t  pro = (uint8_t)((hed >> 4)  & 0x7);
  uint8_t  typ = (uint8_t)((hed >> 7)  & 0x3);
  uint8_t  hop = (uint8_t)((hed >> 9)  & 0x7);
  uint32_t mug = (hed >> 12) & 0xfffff;

  static const char* PT[]   = {"reserved", "%page", "%peek", "%poke"};
  static const char* HOPS[] = {"none", "short", "long", "many"};

  char b[160];
  s += "blob:    ";
  snprintf(b, sizeof(b), "%zu bytes\n", blob_size); s += b;
  s += "header:\n";
  snprintf(b, sizeof(b), "  raw bytes 0..7: %02x %02x %02x %02x %02x %02x %02x %02x\n",
           bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]);
  s += b;
  snprintf(b, sizeof(b), "  protocol:   %u %s\n", pro, pro == 1 ? "" : "(unknown)"); s += b;
  snprintf(b, sizeof(b), "  type:       %u (%s)\n", typ, PT[typ]);                    s += b;
  snprintf(b, sizeof(b), "  next-hop:   %u (%s)\n", nex, HOPS[nex]);                  s += b;
  snprintf(b, sizeof(b), "  hopcount:   %u\n", hop);                                   s += b;
  snprintf(b, sizeof(b), "  checksum:   0x%05x\n", mug);                               s += b;
  if (cookie != kMesaCookie) {
    snprintf(b, sizeof(b), "  cookie:     0x%08x  (expected 0x%08x — bad)\n",
             cookie, kMesaCookie);
    s += b;
    return true;
  }

  // ---- body parse via streaming reader ------------------------------------
  MesaReader r{bytes + 8, blob_size - 8};

  auto dump_remaining = [&](const char* label) {
    snprintf(b, sizeof(b), "%s: %zu bytes left at offset %zu\n",
             label, r.len - r.pos, r.pos + 8);
    s += b;
  };

  // Helper: decrypt the trailing 0v.. component of a `chum/...` path. The
  // path was sealed with the X25519 shared secret between two ships:
  //   - the path's "her" (component [2])
  //   - the path constructor (the OTHER party, identified per +decrypt-path
  //     in vane/ames.hoon)
  // We don't know which side WE are, so try both: the path's `her` first,
  // then the packet's publisher (the constructor for ack-style paths
  // where her == us). Whichever produces a valid MAC wins.
  //
  // On success, captures the sym_key + sealed bytes — both are needed by
  // mesa_decrypt_data when the same chum scheme also encrypts the data
  // field of this packet (`+decrypt-spac` in vane/ames.hoon).
  struct ChumKey {
    bool                  ok = false;
    uint8_t               sym_key[32]{};
    std::vector<uint8_t>  sealed;
  };
  auto try_decrypt_chum = [&](const MesaName& nm, const char* indent) -> ChumKey {
    ChumKey ck;
    if (!keys.have_seed || !keys.resolve) return ck;
    auto parts = split_path(nm.path, nm.path_len);
    if (parts.size() < 5 || parts[0] != "chum") return ck;
    const std::string& her = parts[2];
    const std::string& uvs = parts[4];
    std::vector<uint8_t> sealed;
    if (!decode_uv(uvs.c_str(), uvs.size(), &sealed)) {
      s += indent; s += "decrypt: uv decode failed\n"; return ck;
    }

    std::vector<std::string> candidates = { her };
    std::string pub_patp = patp::from_bytes(nm.ship_bytes, nm.ship_size);
    if (pub_patp != her) candidates.push_back(pub_patp);

    std::string last_note;
    bool any_pending = false;
    for (const std::string& cand : candidates) {
      ResolvedPeer peer = keys.resolve(cand);
      if (!peer.ok) {
        if (peer.pending) any_pending = true;
        last_note = cand + ": " + peer.note;
        continue;
      }
      uint8_t scalar[32], sym_key[32];
      lv_crypto::derive_scalar(keys.our_seed, scalar);
      lv_crypto::derive_shared_secret(scalar, peer.pub, sym_key);
      std::string pt;
      if (lv_crypto::mesa_open_path(sym_key, sealed.data(), sealed.size(), &pt)) {
        s += indent;
        s += "decrypted (key with " + cand + "): ";
        s += pt;
        s += "\n";
        ck.ok = true;
        memcpy(ck.sym_key, sym_key, 32);
        ck.sealed = std::move(sealed);
        return ck;
      }
      last_note = cand + ": tag mismatch";
    }
    s += indent;
    if (any_pending) {
      s += "decrypt: ";
      s += last_note;
      s += "\n";
    } else {
      s += "decrypt: failed (";
      s += last_note;
      s += ")\n";
    }
    return ck;
  };

  ChumKey data_key;  // captured chum for the name that encrypts `data`
  if (typ == 1 /* PAGE */ || typ == 3 /* POKE */ || typ == 2 /* PEEK */) {
    MesaName nm;
    if (!sift_mesa_name(&r, &nm)) { s += "(name parse failed)\n"; return true; }
    s += "name:\n";
    append_mesa_name(&s, nm, "  ");
    ChumKey ck = try_decrypt_chum(nm, "  ");
    // For PAGE the only name is also the data-encryption key; POKE
    // overwrites this below with the pok (payload) name's key.
    if (typ == 1 /* PAGE */) data_key = std::move(ck);
  }
  if (typ == 3 /* POKE */) {
    MesaName pay;
    if (!sift_mesa_name(&r, &pay)) { s += "(payload-name parse failed)\n"; return true; }
    s += "payload-name:\n";
    append_mesa_name(&s, pay, "  ");
    data_key = try_decrypt_chum(pay, "  ");
  }
  if (typ == 1 /* PAGE */ || typ == 3 /* POKE */) {
    size_t data_start = r.pos + 8;  // absolute offset in the blob
    MesaData d;
    bool ok = sift_mesa_data(&r, &d);
    if (!ok) {
      s += "(data parse failed)\n";
      // Dump the next 32 bytes from where data parsing started.
      s += "  data section bytes (from offset ";
      char ob[32]; snprintf(ob, sizeof(ob), "%zu): ", data_start); s += ob;
      size_t end = data_start + 32 < blob_size ? data_start + 32 : blob_size;
      char hb[4];
      for (size_t i = data_start; i < end; i++) {
        snprintf(hb, sizeof(hb), "%02x ", bytes[i]);
        s += hb;
      }
      s += "\n";
      return true;
    }
    s += "data:\n";
    append_mesa_data(&s, d, "  ");

    // Decrypt + cue the payload. Per UIP 0113, fragment reassembly happens
    // in the runtime driver — the event log only ever sees the full
    // message, so dat IS the entire jammed payload (no partial fragments).
    if (d.frag_len > 0 && data_key.ok) {
      std::vector<uint8_t> pt;
      if (lv_crypto::mesa_decrypt_data(data_key.sym_key,
                                       data_key.sealed.data(),
                                       data_key.sealed.size(),
                                       d.frag, d.frag_len, &pt)) {
        cue::Arena perm    = cue::make_arena(kArenaCap);
        cue::Arena stack   = cue::make_arena(kArenaCap);
        cue::Arena scratch = cue::make_arena(kArenaCap);
        cue::Noun* msg = nullptr;
        cue::CueRes rc = cue::cue(pt.data(), pt.size(),
                                  &perm, &stack, &scratch, &msg);
        if (rc == cue::CUE_GOOD && msg) {
          s += "  payload (gage):\n";
          format_mesa_gage(&s, msg, "    ");
        } else {
          snprintf(b, sizeof(b),
                   "  payload (decrypted, %zu bytes; cue failed: %d):\n    ",
                   pt.size(), (int)rc);
          s += b;
          char hb[4];
          size_t shown = pt.size() > 256 ? 256 : pt.size();
          for (size_t i = 0; i < shown; i++) {
            snprintf(hb, sizeof(hb), "%02x", pt[i]); s += hb;
            if      ((i & 31) == 31) s += "\n    ";
            else if ((i &  3) ==  3) s += " ";
          }
          if (pt.size() > shown) s += "...";
          s += "\n";
        }
        cue::free_arena(&perm);
        cue::free_arena(&stack);
        cue::free_arena(&scratch);
      } else {
        s += "  payload: decrypt failed (sentinel byte missing?)\n";
      }
    }

    if (r.pos < r.len) dump_remaining("trailing");
  }
  if (typ == 1 && nex == 1 /* PAGE + HOP_SHORT */) {
    const uint8_t* nh = r.take(6);
    if (nh) {
      uint32_t ip   = (uint32_t)nh[0] | ((uint32_t)nh[1] << 8)
                    | ((uint32_t)nh[2] << 16) | ((uint32_t)nh[3] << 24);
      uint16_t port = (uint16_t)nh[4] | ((uint16_t)nh[5] << 8);
      snprintf(b, sizeof(b), "next-hop:   %u.%u.%u.%u:%u\n",
               (ip >> 24) & 0xff, (ip >> 16) & 0xff,
               (ip >> 8)  & 0xff,  ip        & 0xff, port);
      s += b;
    }
  }
  return true;
}

// Try to decrypt the encrypted body of a %hear ames packet.
// All "atom" buffers come in LSB-first byte order (wire / hoon-atom).
// Internally we reverse to RFC 5297 order before calling AES-SIV.
struct DecryptResult {
  bool ok = false;
  std::string status;
  std::vector<uint8_t> plaintext;  // in atom-byte order if ok
};
DecryptResult try_decrypt_hear(
    const uint8_t* content_atom, size_t content_size,
    const uint8_t* sndr_atom, int sndr_size, uint8_t sndr_tick,
    const uint8_t* rcvr_atom, int rcvr_size, uint8_t rcvr_tick,
    const uint8_t our_seed[32], int64_t our_life,
    const uint8_t peer_pub[32], int64_t peer_life)
{
  DecryptResult r;
  char buf[160];

  if (sndr_tick != (uint8_t)(peer_life % 16)) {
    snprintf(buf, sizeof(buf),
             "ticks mismatch (sndr_tick=%u, peer_life%%16=%lld)",
             sndr_tick, (long long)(peer_life % 16));
    r.status = buf; return r;
  }
  if (rcvr_tick != (uint8_t)(our_life % 16)) {
    snprintf(buf, sizeof(buf),
             "ticks mismatch (rcvr_tick=%u, our_life%%16=%lld)",
             rcvr_tick, (long long)(our_life % 16));
    r.status = buf; return r;
  }
  if (content_size < 18) { r.status = "content too short"; return r; }

  uint16_t len_pt = (uint16_t)content_atom[16]
                  | ((uint16_t)content_atom[17] << 8);
  size_t cyf_off = 18;
  size_t cyf_wire = content_size - cyf_off;

  if (g_debug_decrypt) {
    fprintf(stderr, "[decrypt] inputs:\n");
    fprintf(stderr, "  sndr-tick=%u  rcvr-tick=%u\n", sndr_tick, rcvr_tick);
    fprintf(stderr, "  peer_life=%lld (mod 16 = %lld)\n",
            (long long)peer_life, (long long)(peer_life % 16));
    fprintf(stderr, "  our_life=%lld  (mod 16 = %lld)\n",
            (long long)our_life, (long long)(our_life % 16));
    dump_hex("our_seed", our_seed, 32);
    dump_hex("peer_pub", peer_pub, 32);
    dump_hex("sndr (atom-LSB)", sndr_atom, sndr_size);
    dump_hex("rcvr (atom-LSB)", rcvr_atom, rcvr_size);
    dump_hex("content (atom-LSB)", content_atom,
             content_size > 96 ? 96 : content_size);
    fprintf(stderr, "  content_size=%zu  len_pt=%u  cyf_wire=%zu\n",
            content_size, len_pt, cyf_wire);
  }

  // The blob atom strips trailing zero bytes, so the wire ciphertext can
  // be shorter than the declared plaintext length. Zero-pad to len_pt.
  if (cyf_wire > len_pt) {
    snprintf(buf, sizeof(buf), "wire cyf longer than declared (declared %u, wire %zu)",
             len_pt, cyf_wire);
    r.status = buf; return r;
  }
  std::vector<uint8_t> cyf_atom(len_pt, 0);
  memcpy(cyf_atom.data(), content_atom + cyf_off, cyf_wire);

  // Build an atom-byte representation, then reverse to RFC byte order.
  auto rev_alloc = [](const uint8_t* src, size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; i++) v[i] = src[n - 1 - i];
    return v;
  };
  auto strip_trailing = [](const uint8_t* b, size_t n) {
    while (n > 0 && b[n - 1] == 0) n--; return n;
  };
  auto life_atom_bytes = [](int64_t life) {
    std::vector<uint8_t> v;
    uint64_t u = (uint64_t)life;
    while (u) { v.push_back((uint8_t)(u & 0xff)); u >>= 8; }
    return v;  // already in atom (LSB-first) order
  };

  uint8_t scalar_dbg[32], shared_dbg[32], hash_dbg[64];
  lv_crypto::derive_scalar(our_seed, scalar_dbg);
  lv_crypto::derive_shared_secret(scalar_dbg, peer_pub, shared_dbg);
  lv_crypto::sha512(shared_dbg, 32, hash_dbg);
  if (g_debug_decrypt) {
    fprintf(stderr, "[decrypt] derived:\n");
    dump_hex("clamped scalar", scalar_dbg, 32);
    dump_hex("X25519 shared", shared_dbg, 32);
    dump_hex("SHA-512(shared)", hash_dbg, 64);
  }

  uint8_t key64[64];
  memcpy(key64, hash_dbg, 64);
  // hoon convention: vere reverses the whole atom before AES-SIV. Match that.
  lv_crypto::reverse_bytes(key64, 64);

  std::vector<uint8_t> iv_rfc  = rev_alloc(content_atom, 16);
  std::vector<uint8_t> cyf_rfc = rev_alloc(cyf_atom.data(), len_pt);

  size_t sndr_alen = strip_trailing(sndr_atom, (size_t)sndr_size);
  size_t rcvr_alen = strip_trailing(rcvr_atom, (size_t)rcvr_size);
  std::vector<uint8_t> peer_life_atom = life_atom_bytes(peer_life);
  std::vector<uint8_t> our_life_atom  = life_atom_bytes(our_life);

  std::vector<uint8_t> sndr_rfc = rev_alloc(sndr_atom, sndr_alen);
  std::vector<uint8_t> rcvr_rfc = rev_alloc(rcvr_atom, rcvr_alen);
  std::vector<uint8_t> sndrlife_rfc = rev_alloc(peer_life_atom.data(), peer_life_atom.size());
  std::vector<uint8_t> rcvrlife_rfc = rev_alloc(our_life_atom.data(),  our_life_atom.size());

  if (g_debug_decrypt) {
    fprintf(stderr, "[decrypt] AES-SIV inputs (RFC byte order):\n");
    dump_hex("siv-key (after reverse-64)", key64, 64);
    dump_hex("iv", iv_rfc.data(), 16);
    dump_hex("ad[0] sndr", sndr_rfc.data(), sndr_rfc.size());
    dump_hex("ad[1] rcvr", rcvr_rfc.data(), rcvr_rfc.size());
    dump_hex("ad[2] sndr-life", sndrlife_rfc.data(), sndrlife_rfc.size());
    dump_hex("ad[3] rcvr-life", rcvrlife_rfc.data(), rcvrlife_rfc.size());
    dump_hex("ciphertext (rev)", cyf_rfc.data(), cyf_rfc.size());
  }

  const uint8_t* ad[4] = {
    sndr_rfc.data(), rcvr_rfc.data(),
    sndrlife_rfc.data(), rcvrlife_rfc.data()
  };
  size_t ad_lens[4] = {
    sndr_rfc.size(), rcvr_rfc.size(),
    sndrlife_rfc.size(), rcvrlife_rfc.size()
  };

  std::vector<uint8_t> pt_rfc(len_pt);
  bool ok = lv_crypto::aes_siv_decrypt(key64, ad, ad_lens, 4,
                                       iv_rfc.data(),
                                       cyf_rfc.data(), len_pt,
                                       pt_rfc.data());
  if (g_debug_decrypt) {
    fprintf(stderr, "[decrypt] result: %s\n", ok ? "ok" : "tag mismatch");
    if (ok) dump_hex("plaintext (rfc-order)", pt_rfc.data(), len_pt);
  }
  if (!ok) { r.status = "tag mismatch (wrong keys / lives?)"; return r; }

  // Reverse plaintext back into atom-byte order.
  r.plaintext = rev_alloc(pt_rfc.data(), len_pt);
  r.ok = true;
  return r;
}

// Render an arbitrary noun via cue::print_noun into the string.
void append_noun(std::string* s, cue::Noun* n) {
  std::vector<uint8_t> tmp(kFormatCap);
  cue::print_noun(tmp.data(), tmp.size(), n);
  *s += (const char*)tmp.data();
}

// Walk a noun's right-spine; fills `items` with each head and sets `term`
// to the final tail (which is the @-terminator of a list, or the last
// element of a tuple).
static void collect_spine(cue::Noun* n, std::vector<cue::Noun*>* items,
                          cue::Noun** term) {
  cue::Noun* cur = n;
  while (cue::is_cell(cur)) {
    items->push_back(cue::head(cur));
    cur = cue::tail(cur);
  }
  *term = cur;
}

static bool is_null_atom(cue::Noun* n) {
  return n && !cue::is_cell(n) && n->len == 0 && n->val == 0;
}

// Multi-line noun renderer, hoon-style:
//   - atoms, and cells whose flat printout fits in `kPrettyInline`
//     characters, render inline.
//   - longer cells are walked along their right-spine and printed one
//     element per line with hanging indent. A `~`-terminated spine prints
//     as `~[a b c]` (list); any other terminator prints as `[a b c d]`
//     with d as the final element (tuple).
constexpr size_t kPrettyInline = 96;
void append_noun_pretty(std::string* s, cue::Noun* n, const std::string& indent) {
  std::vector<uint8_t> tmp(kFormatCap);
  size_t inline_len = (size_t)cue::print_noun(tmp.data(), tmp.size(), n);
  if (!cue::is_cell(n) || inline_len + indent.size() <= kPrettyInline) {
    s->append((const char*)tmp.data(), inline_len);
    return;
  }
  std::vector<cue::Noun*> items;
  cue::Noun* term = nullptr;
  collect_spine(n, &items, &term);
  bool is_list = is_null_atom(term);
  std::string sub = indent + "  ";
  *s += is_list ? "~[" : "[";
  for (size_t i = 0; i < items.size(); i++) {
    if (i > 0) { *s += "\n"; *s += sub; }
    append_noun_pretty(s, items[i], sub);
  }
  if (!is_list) {
    *s += "\n"; *s += sub;
    append_noun_pretty(s, term, sub);
  }
  *s += "]";
}

// Render a `gage:mess` — `~` (empty) | `[mark=@tas data=*]`.
//   page = (cask) = (pair @tas *) per arvo.hoon
// Used by mesa pokes/pages: the cued payload of a chum-decrypted data
// field is always a gage (see vane/ames.hoon:8925).
// Render a tang (list of tank) as a python-style traceback under `header`.
// Frames are rendered in reverse order — the deepest frame (index 0) ends
// up at the bottom, matching crud rendering.
static void append_tang_traceback(std::string* s, cue::Noun* tang,
                                  const std::string& indent,
                                  const char* header) {
  *s += indent; *s += header; *s += "\n";
  if (!cue::is_cell(tang)) { *s += indent; *s += "  (empty)\n"; return; }
  std::vector<cue::Noun*> frames;
  for (cue::Noun* l = tang; cue::is_cell(l); l = cue::tail(l)) {
    frames.push_back(cue::head(l));
    if (frames.size() > 1024) break;
  }
  std::string frame_indent = indent + "  ";
  for (auto it = frames.rbegin(); it != frames.rend(); ++it) {
    std::string frame;
    append_tank(&frame, *it, 2, 0);
    // Palms with empty `open` tapes start with leading newlines — strip
    // them so the indentation lines up.
    size_t start = 0;
    while (start < frame.size() && frame[start] == '\n') start++;
    *s += frame_indent;
    for (size_t i = start; i < frame.size(); i++) {
      char c = frame[i];
      *s += c;
      if (c == '\n' && i + 1 < frame.size()) *s += frame_indent;
    }
    *s += "\n";
  }
}

void format_mesa_gage(std::string* s, cue::Noun* gage, const std::string& indent) {
  if (!cue::is_cell(gage)) {
    if (is_null_atom(gage)) { *s += indent; *s += "(empty gage)\n"; return; }
    *s += indent; *s += "(unexpected atom) ";
    append_noun(s, gage);
    *s += "\n";
    return;
  }
  cue::Noun* mark = cue::head(gage);
  cue::Noun* dat  = cue::tail(gage);
  *s += indent; *s += "mark:    ";
  if (cue::is_cell(mark)) append_noun(s, mark);
  else { *s += "%"; append_cord(s, mark); }
  *s += "\n";

  // Detect a naxplanation: gage is `[%message [%nax cause=@tas tang=(list tank)]]`.
  // Sent over the wire whenever a peek/poke ack is a nack with an attached
  // stack trace. Render the tang as a readable traceback rather than the
  // raw spine of leaves/roses/palms.
  std::string mark_s;
  if (!cue::is_cell(mark)) append_cord(&mark_s, mark);
  if (mark_s == "message" && cue::is_cell(dat)) {
    cue::Noun* tag  = cue::head(dat);
    cue::Noun* rest = cue::tail(dat);
    std::string tag_s;
    if (!cue::is_cell(tag)) append_cord(&tag_s, tag);
    if (tag_s == "nax" && cue::is_cell(rest)) {
      cue::Noun* cause = cue::head(rest);
      cue::Noun* tang  = cue::tail(rest);
      *s += indent; *s += "kind:    %nax (naxplanation)\n";
      *s += indent; *s += "cause:   %";
      append_cord(s, cause);
      *s += "\n";
      append_tang_traceback(s, tang, indent,
                            "Traceback (most recent call last):");
      return;
    }
  }

  *s += indent; *s += "data:    ";
  append_noun_pretty(s, dat, indent + "    ");
  *s += "\n";
}

// Render a path (=path) — a list of @tas cords — as `/foo/bar/baz`.
void append_path(std::string* s, cue::Noun* path_n) {
  std::vector<uint8_t> tmp(8 * 1024);
  cue::print_wire(tmp.data(), tmp.size(), path_n);
  *s += (const char*)tmp.data();
}

// Render a 1-byte vane atom as "%g (gall)" etc.
void append_vane(std::string* s, cue::Noun* vane_n) {
  if (cue::is_cell(vane_n) || vane_n->len == 0) { *s += "?"; return; }
  char vc = (char)(vane_n->val & 0xff);
  const char* full = "?";
  switch (vc) {
    case 'a': full = "ames"; break;
    case 'b': full = "behn"; break;
    case 'c': full = "clay"; break;
    case 'd': full = "dill"; break;
    case 'e': full = "eyre"; break;
    case 'g': full = "gall"; break;
    case 'i': full = "iris"; break;
    case 'j': full = "jael"; break;
    case 'k': full = "khan"; break;
    case 'l': full = "lick"; break;
  }
  char buf[32];
  snprintf(buf, sizeof(buf), "%%%c (%s)", vc, full);
  *s += buf;
}

// Render a gall plea payload — $ames-request-all in vane/gall.hoon:
//   [%0 ames-request]
//   ames-request = [%m mark noun] | [%l mark path] | [%s path] | [%u ~]
void append_gall_plea_payload(std::string* s, cue::Noun* payload) {
  if (!cue::is_cell(payload)) { *s += "(unexpected) "; append_noun(s, payload); return; }
  cue::Noun* ver = cue::head(payload);
  cue::Noun* req = cue::tail(payload);
  if (cue::is_cell(ver) || ver->val != 0) { append_noun(s, payload); return; }
  if (!cue::is_cell(req))                 { append_noun(s, payload); return; }
  cue::Noun* tag = cue::head(req);
  cue::Noun* body = cue::tail(req);
  if (cue::is_cell(tag) || tag->len > 1)  { append_noun(s, payload); return; }
  char t = (char)(tag->val & 0xff);
  switch (t) {
    case 'm': {  // poke
      if (!cue::is_cell(body)) { append_noun(s, payload); return; }
      *s += "%poke\n      mark:    ";
      append_cord(s, cue::head(body));
      *s += "\n      noun:    ";
      append_noun(s, cue::tail(body));
      break;
    }
    case 'l': {  // watch-as
      if (!cue::is_cell(body)) { append_noun(s, payload); return; }
      *s += "%watch-as\n      mark:    ";
      append_cord(s, cue::head(body));
      *s += "\n      path:    ";
      append_path(s, cue::tail(body));
      break;
    }
    case 's': {  // watch
      *s += "%watch\n      path:    ";
      append_path(s, body);
      break;
    }
    case 'u': {  // leave
      *s += "%leave";
      break;
    }
    default:
      append_noun(s, payload);
  }
}

// Render a clay plea payload — $riff-any in lull.hoon:
//   [%1 riff]   where  riff = [p=desk q=(unit rave)]
void append_clay_plea_payload(std::string* s, cue::Noun* payload) {
  if (!cue::is_cell(payload)) { append_noun(s, payload); return; }
  cue::Noun* ver = cue::head(payload);
  cue::Noun* riff = cue::tail(payload);
  if (cue::is_cell(ver) || ver->val != 1) { append_noun(s, payload); return; }
  if (!cue::is_cell(riff))                { append_noun(s, payload); return; }
  cue::Noun* desk = cue::head(riff);
  cue::Noun* unit_rave = cue::tail(riff);
  *s += "%clay-request\n      desk:    ";
  append_cord(s, desk);
  *s += "\n      rave:    ";
  if (!cue::is_cell(unit_rave)) {
    *s += "(desist — cancel previous request)";
  } else {
    append_noun(s, cue::tail(unit_rave));
  }
}

// Render a $plea — vane/ames.hoon imports it from lull:
//   [vane=@tas path=path payload=*]
void format_plea(std::string* s, cue::Noun* msg) {
  if (!cue::is_cell(msg)) { append_noun(s, msg); return; }
  cue::Noun* vane_n = cue::head(msg);
  cue::Noun* r1 = cue::tail(msg);
  if (!cue::is_cell(r1)) { append_noun(s, msg); return; }
  cue::Noun* path_n = cue::head(r1);
  cue::Noun* payload = cue::tail(r1);

  *s += "  plea:\n";
  *s += "    vane:       ";
  append_vane(s, vane_n);
  *s += "\n    path:       ";
  append_path(s, path_n);
  *s += "\n    payload:    ";

  char vc = (cue::is_cell(vane_n) || vane_n->len == 0)
              ? '?' : (char)(vane_n->val & 0xff);
  if      (vc == 'g') append_gall_plea_payload(s, payload);
  else if (vc == 'c') append_clay_plea_payload(s, payload);
  else                append_noun(s, payload);
}

// Render a $boon — the message body for a response. Boons don't have a
// fixed shape: a gall boon is a sign:agent (poke-ack/fact/watch-ack/kick),
// a clay boon is a riot, etc. Without flow context we don't know which
// vane originally set up the flow, so we just dump the noun.
void format_boon(std::string* s, cue::Noun* msg) {
  *s += "  boon (response):\n    payload:    ";
  append_noun(s, msg);
}

// Render a $naxplanation — [message-num error] for a nack-trace.
void format_naxplanation(std::string* s, cue::Noun* msg) {
  if (!cue::is_cell(msg)) { *s += "  naxplanation (malformed): "; append_noun(s, msg); return; }
  *s += "  naxplanation:\n    message-num: ";
  char buf[32];
  snprintf(buf, sizeof(buf), "%llu\n",
           (unsigned long long)atom_u64(cue::head(msg)));
  *s += buf;
  *s += "    error:       ";
  append_noun(s, cue::tail(msg));
}

// Pretty-print a $shut-packet (vane/ames.hoon line 588):
//   [=bone =message-num meat=(each fragment-meat ack-meat)]
// Falls back to a raw noun dump on any unexpected shape.
bool format_shut_packet(cue::Noun* e, std::string* out) {
  std::string& s = *out;
  s.clear();

  auto fail = [&]() {
    std::vector<uint8_t> tmp(kFormatCap);
    cue::print_noun(tmp.data(), tmp.size(), e);
    s = "(unrecognized shut-packet shape)\n\n";
    s += (const char*)tmp.data();
  };

  if (!cue::is_cell(e)) { fail(); return false; }
  cue::Noun* bone_n = cue::head(e);
  cue::Noun* r1 = cue::tail(e);
  if (!cue::is_cell(r1)) { fail(); return false; }
  cue::Noun* msg_n = cue::head(r1);
  cue::Noun* meat  = cue::tail(r1);
  if (!cue::is_cell(meat)) { fail(); return false; }
  cue::Noun* meat_tag  = cue::head(meat);
  cue::Noun* meat_body = cue::tail(meat);
  if (cue::is_cell(meat_tag)) { fail(); return false; }

  char buf[160];
  snprintf(buf, sizeof(buf), "  bone:         %llu\n",
           (unsigned long long)atom_u64(bone_n));      s += buf;
  snprintf(buf, sizeof(buf), "  message-num:  %llu\n",
           (unsigned long long)atom_u64(msg_n));       s += buf;

  // Hoon `each`: [%& a] | [%| b], loobean tags so 0 = fragment, 1 = ack.
  if (meat_tag->val == 0) {
    if (!cue::is_cell(meat_body)) { fail(); return false; }
    cue::Noun* nf_n  = cue::head(meat_body);
    cue::Noun* r2    = cue::tail(meat_body);
    if (!cue::is_cell(r2)) { fail(); return false; }
    cue::Noun* fn_n  = cue::head(r2);
    cue::Noun* frag_n = cue::tail(r2);

    uint64_t nf = atom_u64(nf_n);
    uint64_t fn = atom_u64(fn_n);
    snprintf(buf, sizeof(buf), "  kind:         fragment\n");      s += buf;
    snprintf(buf, sizeof(buf), "  fragment:     %llu / %llu\n",
             (unsigned long long)(fn + 1), (unsigned long long)nf); s += buf;

    if (cue::is_cell(frag_n)) {
      s += "  data:         (cell — unexpected)\n";
    } else {
      size_t flen = (size_t)frag_n->len;
      snprintf(buf, sizeof(buf), "  data:         %zu bytes\n", flen); s += buf;

      // Single-fragment messages: the fragment is the entire jammed
      // message. Cue + dispatch on bone direction (per +received in
      // vane/ames.hoon):
      //   odd bone           → %plea  (request)
      //   even, bit 1 = 0    → %boon  (response payload)
      //   even, bit 1 = 1    → %naxplanation
      bool decoded = false;
      if (nf == 1 && fn == 0 && flen > 0) {
        cue::Arena perm    = cue::make_arena(kArenaCap);
        cue::Arena stack   = cue::make_arena(kArenaCap);
        cue::Arena scratch = cue::make_arena(kArenaCap);
        cue::Noun* msg = nullptr;
        cue::CueRes rc = cue::cue(atom_bytes(frag_n), flen,
                                  &perm, &stack, &scratch, &msg);
        if (rc == cue::CUE_GOOD && msg) {
          uint64_t bone = atom_u64(bone_n);
          s += "\n";
          if      ((bone & 1) == 1)    format_plea(&s, msg);
          else if ((bone & 3) == 0)    format_boon(&s, msg);
          else                          format_naxplanation(&s, msg);
          s += "\n";
          decoded = true;
        }
        cue::free_arena(&perm);
        cue::free_arena(&stack);
        cue::free_arena(&scratch);
      }

      // Always show the raw hex too (cap at 256 bytes when we already
      // rendered the cue'd noun, otherwise 1 KiB).
      if (flen > 0) {
        const uint8_t* fb = atom_bytes(frag_n);
        size_t cap = decoded ? 256 : 1024;
        size_t shown = flen > cap ? cap : flen;
        s += "  hex:          ";
        char hb[4];
        for (size_t i = 0; i < shown; i++) {
          snprintf(hb, sizeof(hb), "%02x", fb[i]);
          s += hb;
          if      ((i & 31) == 31) s += "\n                ";
          else if ((i &  3) ==  3) s += " ";
        }
        if (flen > shown) s += "\n                ... (truncated)";
      }
    }
  } else if (meat_tag->val == 1) {
    if (!cue::is_cell(meat_body)) { fail(); return false; }
    cue::Noun* atag = cue::head(meat_body);
    cue::Noun* abody = cue::tail(meat_body);
    if (cue::is_cell(atag)) { fail(); return false; }
    if (atag->val == 0) {
      // fragment-ack
      snprintf(buf, sizeof(buf), "  kind:         ack (fragment)\n");   s += buf;
      snprintf(buf, sizeof(buf), "  fragment-num: %llu\n",
               (unsigned long long)atom_u64(abody));                    s += buf;
    } else if (atag->val == 1) {
      // message-ack: [ok=? lag=@dr]
      if (!cue::is_cell(abody)) { fail(); return false; }
      cue::Noun* ok_n  = cue::head(abody);
      cue::Noun* lag_n = cue::tail(abody);
      bool ok = !atom_bool(ok_n);  // hoon-loobean: 0 = yes
      snprintf(buf, sizeof(buf), "  kind:         ack (message %s)\n",
               ok ? "ok" : "nack");                                     s += buf;
      snprintf(buf, sizeof(buf), "  lag (@dr):    %llu\n",
               (unsigned long long)atom_u64(lag_n));                    s += buf;
    } else {
      fail(); return false;
    }
  } else {
    fail(); return false;
  }
  return true;
}

// (HearKeys / PeerResolver / ResolvedPeer forward-declared near the top)

// Format a %hear task body: [=lane =blob]
//   lane = [%& @pC] | [%| @uxaddress]   — galaxy or routable address
//   blob = @uxblob                       — raw ames packet bytes
// Decoded against +sift-shot in lull.hoon. We render the unencrypted parts:
// header bits, prelude (ticks + sender + receiver), origin, and the size
// of the (still-encrypted) content. With `keys` provided we additionally
// run SIV decrypt and dump the inner shut-packet noun.
bool format_hear(cue::Noun* e, std::string* out, const HearKeys& keys) {
  std::string& s = *out;
  s.clear();

  auto fail = [&]() {
    std::vector<uint8_t> tmp(kFormatCap);
    cue::print_noun(tmp.data(), tmp.size(), e);
    s = "(unrecognized %hear shape)\n\n";
    s += (const char*)tmp.data();
  };

  if (!cue::is_cell(e)) { fail(); return false; }
  cue::Noun* lane = cue::head(e);
  cue::Noun* blob = cue::tail(e);

  // ---- lane -----------------------------------------------------------------
  s += "lane:    ";
  if (cue::is_cell(lane)) {
    cue::Noun* tag = cue::head(lane);
    cue::Noun* val = cue::tail(lane);
    if (!cue::is_cell(tag) && tag->val == 0) {
      char b[32];
      snprintf(b, sizeof(b), "galaxy 0x%02llx", (unsigned long long)atom_u64(val));
      s += b;
    } else if (!cue::is_cell(tag) && tag->val == 1) {
      append_addr48(&s, atom_u64(val));
    } else {
      s += "?";
    }
  } else {
    s += "?";
  }
  s += "\n";

  // ---- blob -----------------------------------------------------------------
  if (cue::is_cell(blob)) { fail(); return false; }
  size_t blob_size = (size_t)blob->len;
  char b[96];
  snprintf(b, sizeof(b), "blob:    %zu bytes\n", blob_size);
  s += b;
  if (blob_size < 4) { s += "(blob too short for ames header)\n"; return true; }

  const uint8_t* bytes = atom_bytes(blob);

  // Header: 32 bits, little-endian read
  uint32_t hed = (uint32_t)bytes[0]
              | ((uint32_t)bytes[1] << 8)
              | ((uint32_t)bytes[2] << 16)
              | ((uint32_t)bytes[3] << 24);

  // Hoon-loobean convention: 0 = yes (`&` / c3y), 1 = no (`|` / c3n).
  // req, sam, and relayed are all loobean fields, so flip the bit to a C bool.
  bool     req     = ((hed >> 2)  & 1) == 0;
  bool     sam     = ((hed >> 3)  & 1) == 0;
  uint32_t ver     = (hed >> 4)  & 0x7;
  uint32_t sac     = (hed >> 7)  & 0x3;
  uint32_t rac     = (hed >> 9)  & 0x3;
  uint32_t cks     = (hed >> 11) & 0xfffff;  // 20-bit truncated mug
  bool     relayed = ((hed >> 31) & 1) == 0;

  static const int sizes[4] = {2, 4, 8, 16};
  int sndr_size = sizes[sac];
  int rcvr_size = sizes[rac];

  s += "header:\n";
  snprintf(b, sizeof(b), "  raw bytes 0..3: %02x %02x %02x %02x  (hed=0x%08x)\n",
           bytes[0], bytes[1], bytes[2], bytes[3], hed);
  s += b;
  snprintf(b, sizeof(b), "  protocol: %s%s\n",
           sam ? "ames" : "fine", req ? " (request)" : "");
  s += b;
  snprintf(b, sizeof(b), "  version:  %u\n", ver);                   s += b;
  snprintf(b, sizeof(b), "  sac/rac:  %u/%u  (sndr=%dB, rcvr=%dB)\n",
           sac, rac, sndr_size, rcvr_size);
  s += b;
  snprintf(b, sizeof(b), "  checksum: 0x%05x\n", cks);                s += b;
  snprintf(b, sizeof(b), "  relayed:  %s\n", relayed ? "yes" : "no"); s += b;

  // Per +sift-shot, when a packet is relayed the 6-byte origin sits at the
  // *low* end of the body — i.e. immediately after the 4-byte header. The
  // tick/sndr/rcvr/content prelude follows. (My earlier read had origin at
  // the END of the blob, which is wrong.)
  size_t origin_off = 4;
  size_t off        = relayed ? 10 : 4;
  size_t need       = 1 + (size_t)sndr_size + (size_t)rcvr_size;
  if (off + need > blob_size) {
    s += "(body too short)\n";
    return true;
  }

  uint8_t tick = bytes[off]; off++;
  uint8_t sndr_tick = tick & 0xf;
  uint8_t rcvr_tick = (tick >> 4) & 0xf;

  s += "prelude:\n";
  snprintf(b, sizeof(b), "  sndr-tick: %u  rcvr-tick: %u\n", sndr_tick, rcvr_tick);
  s += b;

  size_t sndr_off = off;
  s += "  sndr:      ";
  append_ship(&s, bytes + sndr_off, sndr_size);
  s += "\n";
  off += sndr_size;

  size_t rcvr_off = off;
  s += "  rcvr:      ";
  append_ship(&s, bytes + rcvr_off, rcvr_size);
  s += "\n";
  off += rcvr_size;

  if (relayed) {
    uint64_t origin = 0;
    for (int i = 0; i < 6; i++) origin |= (uint64_t)bytes[origin_off + i] << (i * 8);
    s += "  origin:    ";
    append_addr48(&s, origin);
    s += "\n";
  }

  size_t content_off  = off;
  size_t content_size = blob_size - content_off;

  // Raw hex dump of the first chunk of the blob, so the parser can be
  // verified by eye against the displayed sndr/rcvr.
  auto dump_blob_head = [&]() {
    s += "raw blob (first 64 bytes):\n  ";
    size_t dump = blob_size < 64 ? blob_size : 64;
    for (size_t i = 0; i < dump; i++) {
      snprintf(b, sizeof(b), "%02x", bytes[i]);
      s += b;
      if ((i & 15) == 15 && i + 1 < dump) s += "\n  ";
      else if ((i &  3) ==  3 && i + 1 < dump) s += " ";
    }
    s += "\n";
  };

  if (sam) {
    snprintf(b, sizeof(b), "content: %zu bytes (encrypted, starts at byte %zu)\n",
             content_size, content_off);
    s += b;
    dump_blob_head();

    if (keys.have_seed) {
      s += "\n";
      std::string sndr_patp = patp::from_bytes(bytes + sndr_off, sndr_size);
      std::string rcvr_patp = patp::from_bytes(bytes + rcvr_off, rcvr_size);
      ResolvedPeer sndr_info = keys.resolve ? keys.resolve(sndr_patp) : ResolvedPeer{};
      ResolvedPeer rcvr_info = keys.resolve ? keys.resolve(rcvr_patp) : ResolvedPeer{};
      auto status_line = [](const char* who, const ResolvedPeer& info) {
        // While the network fetcher is in flight, the resolver returns
        // pending=true with note="fetching ~ship". Surface that verbatim
        // so the user knows we're waiting, not failing.
        if (info.pending) return std::string("decrypt: ") + info.note + "\n";
        return std::string("decrypt: ") + who + " lookup failed: " +
               info.note + "\n";
      };
      if (!sndr_info.ok) { s += status_line("sndr", sndr_info); return true; }
      if (!rcvr_info.ok) { s += status_line("rcvr", rcvr_info); return true; }
      DecryptResult dr = try_decrypt_hear(
          bytes + content_off, content_size,
          bytes + sndr_off, sndr_size, sndr_tick,
          bytes + rcvr_off, rcvr_size, rcvr_tick,
          keys.our_seed,    rcvr_info.life,
          sndr_info.pub,    sndr_info.life);
      if (!dr.ok) {
        s += "decrypt: ";
        s += dr.status;
        s += "\n";
      } else {
        // Plaintext is a jam-encoded shut-packet noun.
        s += "decrypt: ok (";
        snprintf(b, sizeof(b), "%zu plaintext bytes)\n", dr.plaintext.size());
        s += b;

        cue::Arena perm    = cue::make_arena(kArenaCap);
        cue::Arena stack   = cue::make_arena(kArenaCap);
        cue::Arena scratch = cue::make_arena(kArenaCap);
        cue::Noun* shut = nullptr;
        cue::CueRes rc = cue::cue(dr.plaintext.data(), dr.plaintext.size(),
                                  &perm, &stack, &scratch, &shut);
        if (rc != cue::CUE_GOOD || shut == nullptr) {
          s += "(cue failed)\n";
        } else {
          s += "shut-packet:\n";
          std::string body;
          format_shut_packet(shut, &body);
          s += body;
        }
        cue::free_arena(&perm);
        cue::free_arena(&stack);
        cue::free_arena(&scratch);
      }
    }
    return true;
  }

  // ---- fine response packet (sam = no, req = no) -------------------------
  // Per +sift-purr in lull.hoon — the content has no AES-SIV envelope. It is:
  //   peep:  num=4B  pat-len=2B  pat=<pat-len>B           (LSB-first integers)
  //   meow:  sig=64B num=4B      dat=<rest>B
  // peep.pat is an ASCII path string starting with '/'.  meow.dat is this
  // packet's slice of the response; full-message reassembly happens upstream.
  snprintf(b, sizeof(b), "content: %zu bytes (fine, plaintext, starts at byte %zu)\n",
           content_size, content_off);
  s += b;
  dump_blob_head();

  if (content_size < 6) { s += "(content too short for fine peep)\n"; return true; }
  uint32_t peep_num = (uint32_t)bytes[content_off + 0]
                  | ((uint32_t)bytes[content_off + 1] <<  8)
                  | ((uint32_t)bytes[content_off + 2] << 16)
                  | ((uint32_t)bytes[content_off + 3] << 24);
  uint16_t pat_len  = (uint16_t)bytes[content_off + 4]
                  | ((uint16_t)bytes[content_off + 5] <<  8);
  if (6 + (size_t)pat_len > content_size) {
    s += "(peep path-length overruns blob)\n"; return true;
  }
  const uint8_t* pat = bytes + content_off + 6;
  s += "peep:\n";
  snprintf(b, sizeof(b), "  fragment-num: %u\n", peep_num); s += b;
  snprintf(b, sizeof(b), "  path:         '"); s += b;
  s.append((const char*)pat, pat_len); s += "'\n";

  // If the path is /chum/<ship>/<life>/<@uv>, decrypt the trailing component
  // using the ames-style AES-SIV scheme `en:crub:crypto`. The blob is the
  // jam of `[iv=@ux len=@ud cph=@ux]`; SIV key is sha512(sym_key).
  std::string fine_path((const char*)pat, pat_len);
  auto try_decrypt_fine_path = [&](const std::string& fp) -> std::string {
    if (!keys.have_seed || !keys.resolve) return "";
    // Split on '/' — leading '/' produces an empty first component.
    std::vector<std::string> ps;
    size_t st = 0;
    for (size_t i = 0; i <= fp.size(); i++) {
      if (i == fp.size() || fp[i] == '/') {
        ps.emplace_back(fp, st, i - st);
        st = i + 1;
      }
    }
    if (ps.size() < 5 || ps[1] != "chum") return "";
    const std::string& ship = ps[2];
    const std::string& enc  = ps[ps.size() - 1];
    ResolvedPeer peer = keys.resolve(ship);
    if (!peer.ok) {
      if (peer.pending) return peer.note;  // "fetching ~ship"
      return std::string("(peer ") + ship + ": " + peer.note + ")";
    }

    uint8_t scalar[32], sym_key[32], key64[64];
    lv_crypto::derive_scalar(keys.our_seed, scalar);
    lv_crypto::derive_shared_secret(scalar, peer.pub, sym_key);
    lv_crypto::sha512(sym_key, 32, key64);
    lv_crypto::reverse_bytes(key64, 64);

    std::vector<uint8_t> jammed;
    if (!decode_uv(enc.c_str(), enc.size(), &jammed)) return "(uv decode failed)";

    cue::Arena perm    = cue::make_arena(kArenaCap);
    cue::Arena stack   = cue::make_arena(kArenaCap);
    cue::Arena scratch = cue::make_arena(kArenaCap);
    cue::Noun* trip = nullptr;
    std::string out_str;
    cue::CueRes rc = cue::cue(jammed.data(), jammed.size(),
                              &perm, &stack, &scratch, &trip);
    do {
      if (rc != cue::CUE_GOOD || !trip || !cue::is_cell(trip)) {
        out_str = "(cue of jammed [iv len cph] failed)";
        break;
      }
      cue::Noun* iv_n  = cue::head(trip);
      cue::Noun* rest  = cue::tail(trip);
      if (!cue::is_cell(rest)) { out_str = "(jam shape)"; break; }
      cue::Noun* len_n = cue::head(rest);
      cue::Noun* cph_n = cue::tail(rest);
      if (cue::is_cell(iv_n) || cue::is_cell(len_n) || cue::is_cell(cph_n)) {
        out_str = "(jam atoms)"; break;
      }
      size_t pt_len = (size_t)atom_u64(len_n);
      if (pt_len == 0 || pt_len > 64 * 1024) { out_str = "(bad len)"; break; }

      // Reverse atom-LSB bytes into RFC byte order. Both atoms can have
      // fewer than the expected bytes (leading-zero stripping) — pad on the
      // RFC (high) side with zeros.
      std::vector<uint8_t> iv_rfc(16, 0), cph_rfc(pt_len, 0);
      const uint8_t* iv_a = atom_bytes(iv_n);
      size_t iv_a_n = (size_t)iv_n->len; if (iv_a_n > 16) iv_a_n = 16;
      for (size_t i = 0; i < iv_a_n; i++) iv_rfc[15 - i] = iv_a[i];
      const uint8_t* cph_a = atom_bytes(cph_n);
      size_t cph_a_n = (size_t)cph_n->len; if (cph_a_n > pt_len) cph_a_n = pt_len;
      for (size_t i = 0; i < cph_a_n; i++) cph_rfc[pt_len - 1 - i] = cph_a[i];

      std::vector<uint8_t> pt_rfc(pt_len);
      bool ok = lv_crypto::aes_siv_decrypt(key64, nullptr, nullptr, 0,
                                           iv_rfc.data(),
                                           cph_rfc.data(), pt_len,
                                           pt_rfc.data());
      if (!ok) { out_str = "(tag mismatch)"; break; }
      // Reverse to atom-LSB; the atom's bytes are the path string.
      std::vector<uint8_t> pt_atom(pt_len);
      for (size_t i = 0; i < pt_len; i++) pt_atom[i] = pt_rfc[pt_len - 1 - i];
      out_str.assign((const char*)pt_atom.data(), pt_len);
    } while (0);
    cue::free_arena(&perm);
    cue::free_arena(&stack);
    cue::free_arena(&scratch);
    return out_str;
  };

  std::string dec_path = try_decrypt_fine_path(fine_path);
  if (!dec_path.empty()) {
    s += "  decrypted:    "; s += dec_path; s += "\n";
  }

  size_t meow_off = content_off + 6 + (size_t)pat_len;
  if (meow_off + 68 > blob_size) { s += "(content ends before meow)\n"; return true; }
  uint32_t meow_num = (uint32_t)bytes[meow_off + 64]
                  | ((uint32_t)bytes[meow_off + 65] <<  8)
                  | ((uint32_t)bytes[meow_off + 66] << 16)
                  | ((uint32_t)bytes[meow_off + 67] << 24);
  size_t dat_off = meow_off + 68;
  size_t dat_len = blob_size - dat_off;
  s += "meow:\n";
  s += "  signature:    ";
  for (int i = 0; i < 16; i++) {
    snprintf(b, sizeof(b), "%02x", bytes[meow_off + i]); s += b;
  }
  s += "...  (64 bytes, ed25519)\n";
  snprintf(b, sizeof(b), "  total-frags:  %u\n", meow_num); s += b;
  snprintf(b, sizeof(b), "  data:         %zu bytes (this fragment)\n", dat_len);
  s += b;

  // Single-fragment response: dat layout is [response-sig=64B | jammed (cask)]
  // per +sift-roar (vane/ames.hoon:328). The leading 64 bytes are an extra
  // signature over the assembled response; the remainder (when nonzero)
  // cues to a (cask) = [mark=@tas data=*] = a `gage`.
  if (meow_num == 1 && dat_len > 64) {
    size_t cask_off = dat_off + 64;
    size_t cask_len = dat_len - 64;
    cue::Arena perm    = cue::make_arena(kArenaCap);
    cue::Arena stack   = cue::make_arena(kArenaCap);
    cue::Arena scratch = cue::make_arena(kArenaCap);
    cue::Noun* msg = nullptr;
    cue::CueRes rc = cue::cue(bytes + cask_off, cask_len,
                              &perm, &stack, &scratch, &msg);
    if (rc == cue::CUE_GOOD && msg) {
      s += "  payload (gage):\n";
      format_mesa_gage(&s, msg, "    ");
    } else {
      snprintf(b, sizeof(b), "  payload: cue failed (%d) over %zu bytes\n",
               (int)rc, cask_len);
      s += b;
    }
    cue::free_arena(&perm);
    cue::free_arena(&stack);
    cue::free_arena(&scratch);
  } else if (meow_num == 1 && dat_len == 64) {
    s += "  payload: empty (sig only)\n";
  }
  return true;
}

// Format a %crud task body: [=goof =ovum]
//   goof = [mote=@tas tang=(list tank)]
//   ovum = [wire card]
// The tang is bottom-first: the deepest frame is index 0. We render it
// top-first (innermost call last, like a python/c stack trace) so the
// most user-meaningful message ends up at the bottom.
bool format_crud(cue::Noun* e, std::string* out) {
  std::string& s = *out;
  s.clear();

  auto fail = [&]() {
    std::vector<uint8_t> tmp(kFormatCap);
    cue::print_noun(tmp.data(), tmp.size(), e);
    s = "(unrecognized %crud shape)\n\n";
    s += (const char*)tmp.data();
  };

  if (!cue::is_cell(e)) { fail(); return false; }
  cue::Noun* goof = cue::head(e);
  cue::Noun* ovum = cue::tail(e);
  if (!cue::is_cell(goof)) { fail(); return false; }
  cue::Noun* mote = cue::head(goof);
  cue::Noun* tang = cue::tail(goof);

  s += "mote:  %";
  append_cord(&s, mote);
  s += "\n";

  if (cue::is_cell(ovum)) {
    cue::Noun* wire = cue::head(ovum);
    cue::Noun* card = cue::tail(ovum);
    std::vector<uint8_t> wbuf(8 * 1024);
    cue::print_wire(wbuf.data(), wbuf.size(), wire);
    s += "wire:  ";
    s += (const char*)wbuf.data();
    s += "\n";
    if (cue::is_cell(card)) {
      cue::Noun* card_tag = cue::head(card);
      s += "card:  %";
      append_cord(&s, card_tag);
      s += "\n";
    }
  }

  s += "\nTraceback (most recent call last):\n";

  if (!cue::is_cell(tang)) { s += "  (empty)\n"; return true; }

  // Collect tang into a vector so we can print top-first (reverse order).
  std::vector<cue::Noun*> frames;
  for (cue::Noun* l = tang; cue::is_cell(l); l = cue::tail(l)) {
    frames.push_back(cue::head(l));
    if (frames.size() > 1024) break;
  }
  for (auto it = frames.rbegin(); it != frames.rend(); ++it) {
    std::string frame;
    append_tank(&frame, *it, 2, 0);
    // Palms with empty `open` tapes start with a leading newline (an empty
    // header line). Strip those — the frame's indent already places us on a
    // fresh line, so an extra blank line before the first child is just noise.
    size_t start = 0;
    while (start < frame.size() && frame[start] == '\n') start++;
    s += "  ";
    for (size_t i = start; i < frame.size(); i++) {
      char c = frame[i];
      s += c;
      if (c == '\n' && i + 1 < frame.size()) s += "  ";
    }
    s += "\n";
  }
  return true;
}

}  // namespace

Viewer* Viewer::clipboard_owner_ = nullptr;
void  (*Viewer::saved_set_clipboard_)(ImGuiContext*, const char*) = nullptr;

void Viewer::clipboard_set_hook(ImGuiContext* ctx, const char* text) {
  Viewer* self = clipboard_owner_;
  auto pass_through = [&](const char* s) {
    if (saved_set_clipboard_) saved_set_clipboard_(ctx, s);
  };
  if (!self || !text || !*text) { pass_through(text ? text : ""); return; }
  if (self->wrap_buf_.empty() ||
      self->wrap_to_data_.size() != self->wrap_buf_.size()) {
    pass_through(text); return;
  }
  // Locate the selection inside the wrapped buffer, then walk the parallel
  // mapping back into data_, dropping inserted breaks and recovering
  // replaced spaces. If we can't find an exact substring match (the user
  // probably copied something from a different ImGui widget), fall through.
  size_t len = strlen(text);
  size_t pos = self->wrap_buf_.find(text, 0, len);
  if (pos == std::string::npos || pos + len > self->wrap_to_data_.size()) {
    pass_through(text); return;
  }
  std::string out;
  out.reserve(len);
  for (size_t i = 0; i < len; i++) {
    uint32_t di = self->wrap_to_data_[pos + i];
    if (di == UINT32_MAX) continue;
    if (di < self->data_.size()) out += self->data_[di];
  }
  pass_through(out.c_str());
}

Viewer::Viewer() {
  perm_    = cue::make_arena(kArenaCap);
  stack_   = cue::make_arena(kArenaCap);
  scratch_ = cue::make_arena(kArenaCap);
  // Clipboard hook is installed lazily in draw(): ImGui_ImplOSX_Init runs
  // *after* our constructor and would overwrite anything we put here.
}

Viewer::~Viewer() {
  close();
  cue::free_arena(&perm_);
  cue::free_arena(&stack_);
  cue::free_arena(&scratch_);
  if (clipboard_owner_ == this) {
    ImGuiPlatformIO& pio = ImGui::GetPlatformIO();
    pio.Platform_SetClipboardTextFn = saved_set_clipboard_;
    saved_set_clipboard_ = nullptr;
    clipboard_owner_ = nullptr;
  }
}

void Viewer::close() {
  stop_indexing();
  stop_fetcher();
  if (env_) { mdb_env_close(env_); env_ = nullptr; }
  open_ = false;
  first_ = last_ = 0;
  cur_ = 0; prev_ = -1;
  time_.clear(); wire_.clear(); task_.clear(); data_.clear();
  shards_.clear();
  filter_idx_       = -1;
  filter_name_.clear();
  filter_eves_.clear();
  filter_built_at_  = (uint64_t)-1;
  filter_built_for_.clear();
  sender_filter_.clear();
  sender_filter_eves_.clear();
  sender_filter_built_at_ = (uint64_t)-1;
  sender_filter_built_for_.clear();
  combined_filter_eves_.clear();
  index_version_.store(0);
}

bool Viewer::open(const std::string& path, bool start_index) {
  close();
  path_ = path;
  error_.clear();

  int err;
  if ((err = mdb_env_create(&env_))) {
    error_ = fmt_path_lock_warning(err);
    return false;
  }
  mdb_env_set_maxdbs(env_, 1);
  mdb_env_set_mapsize(env_, (size_t)1048576 * (size_t)100000);

  // Open read-only and skip locking: the file may sit in a directory with
  // no write permissions, and we never modify it.
  unsigned int flags = MDB_RDONLY | MDB_NOLOCK | MDB_NOSUBDIR;

  // If the path doesn't end in data.mdb, append it.
  std::string p = path;
  if (p.size() < 8 || p.compare(p.size() - 8, 8, "data.mdb") != 0) {
    if (!p.empty() && p.back() != '/') p += '/';
    p += "data.mdb";
  }

  if ((err = mdb_env_open(env_, p.c_str(), flags, 0664))) {
    error_ = fmt_path_lock_warning(err);
    mdb_env_close(env_);
    env_ = nullptr;
    return false;
  }
  open_ = true;
  refresh_bounds();
  if (last_ > 0) {
    cur_ = (int64_t)last_;
    follow_tail_ = true;
  }
  if (start_index) start_indexing();
  start_fetcher();
  return true;
}

void Viewer::refresh_bounds() {
  if (!env_) return;

  MDB_txn* txn = nullptr;
  MDB_dbi  dbi;
  MDB_cursor* cur = nullptr;
  int err;

  if ((err = mdb_txn_begin(env_, nullptr, MDB_RDONLY, &txn))) {
    error_ = fmt_path_lock_warning(err); return;
  }
  if ((err = mdb_dbi_open(txn, "EVENTS", MDB_INTEGERKEY, &dbi))) {
    error_ = fmt_path_lock_warning(err); mdb_txn_abort(txn); return;
  }
  if ((err = mdb_cursor_open(txn, dbi, &cur))) {
    error_ = fmt_path_lock_warning(err); mdb_txn_abort(txn); return;
  }

  MDB_val key, val;
  if ((err = mdb_cursor_get(cur, &key, &val, MDB_FIRST)) == 0) {
    memcpy(&first_, key.mv_data, sizeof(first_));
  } else if (err == MDB_NOTFOUND) {
    first_ = 0; last_ = 0;
  } else {
    error_ = fmt_path_lock_warning(err);
  }
  if ((err = mdb_cursor_get(cur, &key, &val, MDB_LAST)) == 0) {
    memcpy(&last_, key.mv_data, sizeof(last_));
  }
  mdb_cursor_close(cur);
  mdb_txn_abort(txn);
}

void Viewer::load_event(uint64_t eve) {
  if (!env_) return;

  cue::reset_arena(&perm_);
  cue::reset_arena(&stack_);
  cue::reset_arena(&scratch_);

  MDB_txn* txn = nullptr;
  MDB_dbi  dbi;
  int err;

  if ((err = mdb_txn_begin(env_, nullptr, MDB_RDONLY, &txn))) {
    error_ = fmt_path_lock_warning(err); return;
  }
  if ((err = mdb_dbi_open(txn, "EVENTS", MDB_INTEGERKEY, &dbi))) {
    error_ = fmt_path_lock_warning(err); mdb_txn_abort(txn); return;
  }

  MDB_val key, val;
  key.mv_size = sizeof(eve);
  key.mv_data = &eve;
  err = mdb_get(txn, dbi, &key, &val);
  if (err) {
    error_ = fmt_path_lock_warning(err);
    mdb_txn_abort(txn);
    time_ = wire_ = task_ = data_ = "";
    return;
  }

  // First 4 bytes are a mug; the rest is the jammed noun.
  raw_size_ = val.mv_size;
  if (val.mv_size < 4) { mdb_txn_abort(txn); return; }
  memcpy(&mug_, val.mv_data, 4);

  cue::Noun* n = nullptr;
  cue::CueRes res = cue::cue((const uint8_t*)val.mv_data + 4,
                             val.mv_size - 4,
                             &perm_, &stack_, &scratch_, &n);
  if (res != cue::CUE_GOOD || n == nullptr) {
    error_ = "failed to deserialize event";
    mdb_txn_abort(txn);
    time_ = wire_ = task_ = data_ = "";
    return;
  }
  error_.clear();

  // Standard event noun shape is [date wire task event]. Boot/genesis
  // events have a different shape (mug == 0). Walk defensively: at every
  // step the current node must be a cell, otherwise we fall back to
  // dumping the raw deserialized noun.
  std::vector<uint8_t> buf(kFormatCap);
  time_.clear(); wire_.clear(); task_.clear(); data_.clear();

  auto dump_raw = [&]() {
    cue::print_noun(buf.data(), buf.size(), n);
    data_.assign((char*)buf.data());
    time_ = wire_ = task_ = "(non-standard event shape)";
  };

  if (!cue::is_cell(n))                             { dump_raw(); mdb_txn_abort(txn); return; }
  cue::Noun* date_n = cue::head(n);
  cue::Noun* rest1  = cue::tail(n);
  if (!cue::is_cell(rest1))                         { dump_raw(); mdb_txn_abort(txn); return; }
  cue::Noun* wire_n = cue::head(rest1);
  cue::Noun* rest2  = cue::tail(rest1);
  if (!cue::is_cell(rest2))                         { dump_raw(); mdb_txn_abort(txn); return; }
  cue::Noun* task_n = cue::head(rest2);
  cue::Noun* evt_n  = cue::tail(rest2);

  cue::print_da(buf.data(), buf.size(), date_n);
  time_.assign((char*)buf.data());

  cue::print_wire(buf.data(), buf.size(), wire_n);
  wire_.assign((char*)buf.data());

  if (cue::is_cell(task_n)) {
    // Some events nest the task; just dump the noun.
    cue::print_noun(buf.data(), buf.size(), task_n);
    task_.assign((char*)buf.data());
  } else {
    buf[0] = '%';
    cue::size cw = cue::print_cord(buf.data() + 1, buf.size() - 1, task_n);
    buf[1 + cw] = 0;
    task_.assign((char*)buf.data());
  }

  // Build the HearKeys (own seed + peer-pub resolver) once per event.
  // Real mode pulls peer pubkeys from the network-explorer API (cached).
  // Fake mode derives both our seed and every peer pubkey deterministically
  // from the patp via +pit:nu:crub:crypto.
  auto build_hear_keys = [&]() -> HearKeys {
    HearKeys hk;
    if (fake_mode_) {
      uint8_t our_bytes[16] = {0};
      int     our_size = 0;
      if (!patp::to_bytes(fake_ship_name_, our_bytes,
                          (int)sizeof(our_bytes), &our_size)) {
        return hk;                  // unparseable ship — leave have_seed=false
      }
      lv_crypto::derive_fake_seed(our_bytes, our_size, hk.our_seed);
      hk.have_seed = true;
      hk.resolve = [](const std::string& patp_name) -> ResolvedPeer {
        ResolvedPeer rp{};
        uint8_t bytes[16] = {0};
        int     n = 0;
        if (!patp::to_bytes(patp_name, bytes, (int)sizeof(bytes), &n)) {
          rp.note = "fake: cannot parse " + patp_name;
          return rp;
        }
        lv_crypto::derive_fake_eddsa_pub(bytes, n, rp.pub);
        rp.life = 1;                // fake ships always have life=1
        rp.ok   = true;
        return rp;
      };
      return hk;
    }

    uint8_t seed[32];
    if (parse_seed(our_seed_hex_, seed)) {
      hk.have_seed = true;
      memcpy(hk.our_seed, seed, 32);
      hk.resolve = [this](const std::string& patp_name) -> ResolvedPeer {
        ResolvedPeer rp{};
        std::lock_guard<std::mutex> g(node_mu_);
        auto it = node_cache_.find(patp_name);
        if (it == node_cache_.end()) {
          node_cache_.emplace(patp_name, CachedNode{});
          fetch_q_.push({patp_name, patp_name});
          fetch_cv_.notify_one();
          rp.pending = true;
          rp.note    = "fetching " + patp_name;
          return rp;
        }
        switch (it->second.state) {
          case CachedNode::PENDING:
            rp.pending = true;
            rp.note    = "fetching " + patp_name;
            return rp;
          case CachedNode::OK:
            memcpy(rp.pub, it->second.enc_key, 32);
            rp.life = it->second.life;
            rp.ok = true;
            return rp;
          case CachedNode::FAILED:
            rp.note = it->second.error.empty()
                ? ("lookup failed for " + patp_name)
                : it->second.error;
            return rp;
        }
        return rp;
      };
    }
    return hk;
  };

  if (task_ == "%request") {
    format_request(evt_n, &data_);
  } else if (task_ == "%receive") {
    format_receive(evt_n, &data_);
  } else if (task_ == "%crud") {
    format_crud(evt_n, &data_);
  } else if (task_ == "%heer") {
    HearKeys hk = build_hear_keys();
    format_heer(evt_n, &data_, hk);
  } else if (task_ == "%hear") {
    HearKeys hk = build_hear_keys();
    format_hear(evt_n, &data_, hk);
  } else if (task_ == "%cancel-request") {
    // %cancel-request itself carries no payload — the wire is the only
    // identifier. Find the most recent prior %request whose wire matches
    // and embed its rendered body so the operator can see what got
    // canceled without scrolling through prior events.
    data_  = "%cancel-request\nwire: ";
    data_ += wire_;
    data_ += "\n\n";

    uint64_t target = 0;
    for (auto& sp : shards_) {
      std::lock_guard<std::mutex> g(sp->mu);
      auto it = sp->request_wires.find(wire_);
      if (it == sp->request_wires.end()) continue;
      const auto& v = it->second;
      auto vit = std::lower_bound(v.begin(), v.end(), eve);
      if (vit == v.begin()) continue;
      --vit;
      if (*vit > target) target = *vit;
    }

    if (target == 0) {
      data_ += "(no matching %request indexed under this wire)\n";
    } else {
      char hb[64];
      snprintf(hb, sizeof(hb), "originating %%request — event %llu:\n\n",
               (unsigned long long)target);
      data_ += hb;

      uint64_t key_v = target;
      MDB_val key2{sizeof(key_v), &key_v}, val2;
      if (mdb_get(txn, dbi, &key2, &val2) == 0 && val2.mv_size >= 4) {
        cue::Arena perm    = cue::make_arena(kArenaCap);
        cue::Arena stack   = cue::make_arena(kArenaCap);
        cue::Arena scratch = cue::make_arena(kArenaCap);
        cue::Noun* tn = nullptr;
        cue::CueRes rc2 = cue::cue((const uint8_t*)val2.mv_data + 4,
                                   val2.mv_size - 4,
                                   &perm, &stack, &scratch, &tn);
        bool rendered = false;
        if (rc2 == cue::CUE_GOOD && tn && cue::is_cell(tn)) {
          cue::Noun* tr1 = cue::tail(tn);
          if (cue::is_cell(tr1)) {
            cue::Noun* tr2 = cue::tail(tr1);
            if (cue::is_cell(tr2)) {
              cue::Noun* ten = cue::tail(tr2);
              std::string body;
              if (format_request(ten, &body)) {
                data_ += body;
                rendered = true;
              }
            }
          }
        }
        if (!rendered) data_ += "(failed to deserialize matching %request)\n";
        cue::free_arena(&perm);
        cue::free_arena(&stack);
        cue::free_arena(&scratch);
      } else {
        data_ += "(matching %request event not found in the log)\n";
      }
    }
  } else {
    cue::print_noun(buf.data(), buf.size(), evt_n);
    data_.assign((char*)buf.data());
  }

  mdb_txn_abort(txn);
}

// Decode the task cord from a single jammed event using thread-local
// arenas. Returns the bucket name (e.g. "%hear") or a sentinel for
// non-standard shapes. Thread-safe: arenas are owned by the caller.
static bool decode_task_local(const uint8_t* buf, size_t len,
                              cue::Arena* perm, cue::Arena* stack, cue::Arena* scratch,
                              std::string* out, cue::Noun** evt_out,
                              cue::Noun** wire_out = nullptr) {
  cue::reset_arena(perm);
  cue::reset_arena(stack);
  cue::reset_arena(scratch);

  if (evt_out)  *evt_out  = nullptr;
  if (wire_out) *wire_out = nullptr;
  cue::Noun* n = nullptr;
  cue::CueRes res = cue::cue(buf, len, perm, stack, scratch, &n);
  if (res != cue::CUE_GOOD || n == nullptr || !cue::is_cell(n)) return false;
  cue::Noun* r1 = cue::tail(n);
  if (!cue::is_cell(r1)) return false;
  if (wire_out) *wire_out = cue::head(r1);
  cue::Noun* r2 = cue::tail(r1);
  if (!cue::is_cell(r2)) return false;
  cue::Noun* task_n = cue::head(r2);
  if (evt_out) *evt_out = cue::tail(r2);

  if (cue::is_cell(task_n)) { *out = "(cell)"; return true; }
  uint8_t cord[64];
  size_t cord_len = task_n->len < sizeof(cord) ? task_n->len : sizeof(cord) - 1;
  if (cord_len == 0) { *out = "%$"; return true; }
  const uint8_t* src = (task_n->len > 8)
      ? (const uint8_t*)(uintptr_t)task_n->val
      : (const uint8_t*)&task_n->val;
  memcpy(cord, src, cord_len);
  for (size_t i = 0; i < cord_len; i++) {
    if (cord[i] < 0x20 || cord[i] >= 0x7f) { *out = "(non-cord)"; return true; }
  }
  std::string name = "%";
  name.append((const char*)cord, cord_len);
  *out = std::move(name);
  return true;
}

// Extract a peer-ship @p from the body of a %hear or %heer event noun.
//   %hear: ames/fine prelude — bytes [0..3] header, then origin (6B if
//          relayed), tick (1B), sndr (sac-determined size).
//   %heer: mesa packet — header(4B) + cookie(4B) + body. The sender we want
//          is the publisher in name.her, but only if the packet *names* a
//          sender:
//            %peek (typ=2) is anonymous → no sender to record
//            %page (typ=1) → name.her  (publisher of the response)
//            %poke (typ=3) → second name (`pok`).her — the first name is
//                             the ack target, which is not the sender
// Returns "" on shape mismatch.
static std::string extract_sender_patp(const std::string& task, cue::Noun* evt_n) {
  if (!cue::is_cell(evt_n)) return "";
  cue::Noun* blob = cue::tail(evt_n);
  if (cue::is_cell(blob) || blob->len < 8) return "";
  size_t blob_size = (size_t)blob->len;
  const uint8_t* bytes = (blob->len > 8)
      ? (const uint8_t*)(uintptr_t)blob->val
      : (const uint8_t*)&blob->val;

  if (task == "%hear") {
    uint32_t hed = (uint32_t)bytes[0]
                | ((uint32_t)bytes[1] <<  8)
                | ((uint32_t)bytes[2] << 16)
                | ((uint32_t)bytes[3] << 24);
    bool     relayed = ((hed >> 31) & 1) == 0;  // hoon-loobean: 0=yes
    uint32_t sac     = (hed >>  7) & 0x3;
    static const int sizes[4] = {2, 4, 8, 16};
    int sndr_size = sizes[sac];
    size_t off = relayed ? 10 : 4;       // skip header (+ origin if relayed)
    if (off + 1 + (size_t)sndr_size > blob_size) return "";
    off += 1;                            // skip tick byte
    return patp::from_bytes(bytes + off, sndr_size);
  }
  if (task == "%heer") {
    uint32_t hed = (uint32_t)bytes[0]
                | ((uint32_t)bytes[1] <<  8)
                | ((uint32_t)bytes[2] << 16)
                | ((uint32_t)bytes[3] << 24);
    uint32_t cookie = (uint32_t)bytes[4]
                   | ((uint32_t)bytes[5] <<  8)
                   | ((uint32_t)bytes[6] << 16)
                   | ((uint32_t)bytes[7] << 24);
    if (cookie != kMesaCookie) return "";
    uint8_t typ = (uint8_t)((hed >> 7) & 0x3);
    if (typ != 1 /* page */ && typ != 3 /* poke */) return "";

    MesaReader r{bytes + 8, blob_size - 8};
    MesaName n1;
    if (!sift_mesa_name(&r, &n1)) return "";
    if (typ == 1 /* page */) {
      return patp::from_bytes(n1.ship_bytes, n1.ship_size);
    }
    // poke — first name is the ack target; second name (pok) carries the
    // sender of the poke.
    MesaName n2;
    if (!sift_mesa_name(&r, &n2)) return "";
    return patp::from_bytes(n2.ship_bytes, n2.ship_size);
  }
  return "";
}

// ---- background API fetcher ----------------------------------------------

void Viewer::start_fetcher() {
  stop_fetcher();
  fetch_stop_.store(false);
  fetch_thread_ = std::thread(&Viewer::fetch_loop, this);
}

void Viewer::stop_fetcher() {
  if (!fetch_thread_.joinable()) return;
  {
    std::lock_guard<std::mutex> g(node_mu_);
    fetch_stop_.store(true);
  }
  fetch_cv_.notify_all();
  fetch_thread_.join();
  // Drain any remaining queued requests so a subsequent open() starts clean.
  std::lock_guard<std::mutex> g(node_mu_);
  while (!fetch_q_.empty()) fetch_q_.pop();
}

void Viewer::fetch_loop() {
  while (true) {
    std::pair<std::string, std::string> item;
    {
      std::unique_lock<std::mutex> lock(node_mu_);
      fetch_cv_.wait(lock, [this]() {
        return fetch_stop_.load() || !fetch_q_.empty();
      });
      if (fetch_stop_.load()) return;
      item = fetch_q_.front();
      fetch_q_.pop();
    }
    api::NodeInfo ni;
    bool ok = api::fetch_node(item.second, &ni);
    {
      std::lock_guard<std::mutex> g(node_mu_);
      auto it = node_cache_.find(item.first);
      if (it != node_cache_.end()) {
        if (ok) {
          it->second.state = CachedNode::OK;
          memcpy(it->second.enc_key, ni.enc_key, 32);
          it->second.life = ni.revision;
        } else {
          it->second.state = CachedNode::FAILED;
          it->second.error = "API fetch failed for " + item.second;
        }
      }
    }
    node_version_.fetch_add(1);
    fetch_cv_.notify_all();  // wake up wait_for_pending_fetches
  }
}

void Viewer::wait_for_pending_fetches() {
  std::unique_lock<std::mutex> lock(node_mu_);
  fetch_cv_.wait(lock, [this]() {
    if (!fetch_q_.empty()) return false;
    for (auto& kv : node_cache_) {
      if (kv.second.state == CachedNode::PENDING) return false;
    }
    return true;
  });
}

void Viewer::stop_indexing() {
  if (workers_.empty()) return;
  stop_workers_.store(true);
  for (auto& t : workers_) if (t.joinable()) t.join();
  workers_.clear();
  stop_workers_.store(false);
}

void Viewer::start_indexing() {
  stop_indexing();
  if (!env_ || last_ < first_) return;

  unsigned int hw = std::thread::hardware_concurrency();
  // Each worker owns 3 large arenas, so we cap aggressively. The cue is
  // CPU-bound and 4 workers already get most of the speedup.
  size_t n = hw > 2 ? std::min<unsigned int>(hw - 1, (unsigned int)kMaxWorkers) : 1;

  shards_.clear();
  shards_.reserve(n);
  for (size_t i = 0; i < n; i++) shards_.push_back(std::make_unique<IndexShard>());

  uint64_t total = last_ - first_ + 1;
  uint64_t chunk = (total + n - 1) / n;

  workers_.reserve(n);
  for (size_t i = 0; i < n; i++) {
    uint64_t lo = first_ + chunk * i;
    uint64_t hi = std::min<uint64_t>(last_, lo + chunk - 1);
    workers_.emplace_back(&Viewer::index_worker, this, i, lo, hi);
  }
}

void Viewer::index_worker(size_t wi, uint64_t lo, uint64_t hi) {
  IndexShard& s = *shards_[wi];

  cue::Arena perm    = cue::make_arena(kArenaCap);
  cue::Arena stack   = cue::make_arena(kArenaCap);
  cue::Arena scratch = cue::make_arena(kArenaCap);

  MDB_txn* txn = nullptr;
  MDB_dbi  dbi;
  MDB_cursor* cur = nullptr;

  auto cleanup = [&]() {
    if (cur) mdb_cursor_close(cur);
    if (txn) mdb_txn_abort(txn);
    cue::free_arena(&perm);
    cue::free_arena(&stack);
    cue::free_arena(&scratch);
    s.done.store(true);
    index_version_.fetch_add(1);
  };

  if (mdb_txn_begin(env_, nullptr, MDB_RDONLY, &txn))                { cleanup(); return; }
  if (mdb_dbi_open(txn, "EVENTS", MDB_INTEGERKEY, &dbi))            { cleanup(); return; }
  if (mdb_cursor_open(txn, dbi, &cur))                              { cleanup(); return; }

  uint64_t key_v = lo;
  MDB_val key{sizeof(key_v), &key_v}, val;
  int rc = mdb_cursor_get(cur, &key, &val, MDB_SET_RANGE);

  // Local accumulators flushed periodically into the shard's maps to keep
  // mutex contention low.
  std::unordered_map<std::string, std::vector<uint64_t>> local;
  std::unordered_map<std::string, std::vector<uint64_t>> local_senders;
  std::unordered_map<std::string, std::vector<uint64_t>> local_request_wires;
  uint64_t scanned = 0;
  uint64_t since_flush = 0;
  constexpr uint64_t kFlushEvery = 1024;

  auto flush = [&]() {
    if (local.empty() && local_senders.empty() && local_request_wires.empty()) return;
    {
      std::lock_guard<std::mutex> g(s.mu);
      for (auto& kv : local) {
        auto& dst = s.tasks[kv.first];
        dst.insert(dst.end(), kv.second.begin(), kv.second.end());
      }
      for (auto& kv : local_senders) {
        auto& dst = s.senders[kv.first];
        dst.insert(dst.end(), kv.second.begin(), kv.second.end());
      }
      for (auto& kv : local_request_wires) {
        auto& dst = s.request_wires[kv.first];
        dst.insert(dst.end(), kv.second.begin(), kv.second.end());
      }
    }
    local.clear();
    local_senders.clear();
    local_request_wires.clear();
    s.indexed.store(scanned, std::memory_order_relaxed);
    index_version_.fetch_add(1, std::memory_order_relaxed);
  };

  std::vector<uint8_t> wbuf(8 * 1024);  // scratch for print_wire

  while (rc == 0 && !stop_workers_.load(std::memory_order_relaxed)) {
    uint64_t eve;
    memcpy(&eve, key.mv_data, sizeof(eve));
    if (eve > hi) break;

    if (val.mv_size >= 4) {
      std::string name;
      cue::Noun* evt_n  = nullptr;
      cue::Noun* wire_n = nullptr;
      if (decode_task_local((const uint8_t*)val.mv_data + 4, val.mv_size - 4,
                            &perm, &stack, &scratch, &name, &evt_n, &wire_n)) {
        local[name].push_back(eve);
        if (evt_n && (name == "%hear" || name == "%heer")) {
          std::string sndr = extract_sender_patp(name, evt_n);
          if (!sndr.empty()) local_senders[sndr].push_back(eve);
        }
        if (wire_n && name == "%request") {
          cue::print_wire(wbuf.data(), wbuf.size(), wire_n);
          local_request_wires[(const char*)wbuf.data()].push_back(eve);
        }
      }
    }
    scanned++;
    since_flush++;
    if (since_flush >= kFlushEvery) {
      flush();
      since_flush = 0;
    }
    rc = mdb_cursor_get(cur, &key, &val, MDB_NEXT);
  }
  flush();
  cleanup();
}

void Viewer::draw() {
  // Install the clipboard hook on the first frame, after the OSX backend
  // has had a chance to register its NSPasteboard handler. Re-check each
  // frame in case something else overwrites the function pointer.
  {
    ImGuiPlatformIO& pio = ImGui::GetPlatformIO();
    if (pio.Platform_SetClipboardTextFn != &Viewer::clipboard_set_hook) {
      saved_set_clipboard_ = pio.Platform_SetClipboardTextFn;
      pio.Platform_SetClipboardTextFn = &Viewer::clipboard_set_hook;
      clipboard_owner_ = this;
    }
  }

  ImGui::Begin("urbit event log", nullptr,
               ImGuiWindowFlags_NoMove |
               ImGuiWindowFlags_NoResize |
               ImGuiWindowFlags_NoCollapse |
               ImGuiWindowFlags_NoBringToFrontOnFocus);

  // Path entry
  static char path_buf[1024] = {0};
  if (path_buf[0] == 0 && !path_.empty()) {
    strncpy(path_buf, path_.c_str(), sizeof(path_buf) - 1);
  }
  ImGui::SetNextItemWidth(-120);
  ImGui::InputText("##path", path_buf, sizeof(path_buf));
  ImGui::SameLine();
  if (ImGui::Button("Open")) {
    open(path_buf);
  }

  if (!error_.empty()) {
    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "error: %s", error_.c_str());
  }

  if (!open_) {
    ImGui::TextDisabled("Open a directory containing data.mdb (or pass the data.mdb path).");
    ImGui::End();
    return;
  }

  // ---- ames decryption identity (paste once per session) -----------------
  if (ImGui::CollapsingHeader("identity (for %hear decryption)")) {
    static char our_seed_buf[256] = {0};
    static char fake_ship_buf[64] = {0};
    bool changed = false;

    if (ImGui::Checkbox("fake (derive all keys from ship name)", &fake_mode_)) {
      changed = true;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(no http requests)");

    if (fake_mode_) {
      ImGui::PushItemWidth(280);
      if (ImGui::InputText("our ship (e.g. ~zod)",
                           fake_ship_buf, sizeof(fake_ship_buf))) {
        fake_ship_name_ = fake_ship_buf;
        changed = true;
      }
      ImGui::PopItemWidth();

      uint8_t tb[16];
      int     tn = 0;
      bool    ship_ok = patp::to_bytes(fake_ship_name_, tb,
                                       (int)sizeof(tb), &tn);
      ImGui::TextDisabled(
          "fake mode: %s   keys derived via +pit:nu:crub:crypto",
          ship_ok ? "ok" : "(need a parsable @p)");
    } else {
      ImGui::PushItemWidth(540);
      if (ImGui::InputText("your seed or full $ring (32 or 65-byte hex)",
                           our_seed_buf, sizeof(our_seed_buf))) {
        our_seed_hex_ = our_seed_buf;
        changed = true;
      }
      ImGui::PopItemWidth();

      uint8_t tmp[32];
      bool seed_ok = parse_seed(our_seed_hex_, tmp);

      size_t n_total = 0, n_pending = 0, n_ok = 0, n_failed = 0, n_queued = 0;
      {
        std::lock_guard<std::mutex> g(node_mu_);
        n_total = node_cache_.size();
        n_queued = fetch_q_.size();
        for (auto& kv : node_cache_) {
          if      (kv.second.state == CachedNode::PENDING) n_pending++;
          else if (kv.second.state == CachedNode::OK)      n_ok++;
          else                                              n_failed++;
        }
      }
      ImGui::TextDisabled(
          "seed: %s   nodes cached: %zu (ok %zu, pending %zu, failed %zu, queued %zu)",
          seed_ok ? "ok" : "(need 32B seed or 65B ring)",
          n_total, n_ok, n_pending, n_failed, n_queued);
      if (ImGui::Button("clear node cache")) {
        std::lock_guard<std::mutex> g(node_mu_);
        node_cache_.clear();
        changed = true;
      }
    }
    if (changed) prev_ = -1;  // force reload of current event
  }

  refresh_bounds();

  if (follow_tail_) cur_ = (int64_t)last_;

  // ---- collect per-task and per-sender summaries across all shards --------
  struct Summary { std::string name; size_t count; };
  std::vector<Summary> summary;
  std::unordered_map<std::string, size_t> sum_idx;
  std::vector<Summary> sender_summary;
  std::unordered_map<std::string, size_t> sender_sum_idx;
  uint64_t total_indexed = 0;
  bool all_done = !shards_.empty();
  for (auto& sp : shards_) {
    total_indexed += sp->indexed.load(std::memory_order_relaxed);
    if (!sp->done.load(std::memory_order_relaxed)) all_done = false;
    std::lock_guard<std::mutex> g(sp->mu);
    for (auto& kv : sp->tasks) {
      auto it = sum_idx.find(kv.first);
      if (it == sum_idx.end()) {
        sum_idx[kv.first] = summary.size();
        summary.push_back({kv.first, kv.second.size()});
      } else {
        summary[it->second].count += kv.second.size();
      }
    }
    for (auto& kv : sp->senders) {
      auto it = sender_sum_idx.find(kv.first);
      if (it == sender_sum_idx.end()) {
        sender_sum_idx[kv.first] = sender_summary.size();
        sender_summary.push_back({kv.first, kv.second.size()});
      } else {
        sender_summary[it->second].count += kv.second.size();
      }
    }
  }
  std::vector<size_t> sorted_tasks(summary.size());
  for (size_t i = 0; i < summary.size(); i++) sorted_tasks[i] = i;
  std::sort(sorted_tasks.begin(), sorted_tasks.end(),
            [&](size_t a, size_t b) {
              return summary[a].count > summary[b].count;
            });
  std::vector<size_t> sorted_senders(sender_summary.size());
  for (size_t i = 0; i < sender_summary.size(); i++) sorted_senders[i] = i;
  std::sort(sorted_senders.begin(), sorted_senders.end(),
            [&](size_t a, size_t b) {
              return sender_summary[a].count > sender_summary[b].count;
            });

  // Map current filter_name_ back to a summary index (filter_idx_ is purely
  // a UI selector for radio-button state in the combo).
  auto find_summary = [&](const std::string& nm) -> int {
    auto it = sum_idx.find(nm);
    return it == sum_idx.end() ? -1 : (int)it->second;
  };
  if (!filter_name_.empty()) filter_idx_ = find_summary(filter_name_);
  else                        filter_idx_ = -1;

  // ---- filter dropdowns ---------------------------------------------------
  // Render the combos first so this frame can rebuild the filter event
  // list against the freshly-selected name and snap cur_ into it.
  bool filter_changed = false;
  ImGui::SetNextItemWidth(260);
  std::string preview = filter_name_.empty()
      ? std::string("(all)")
      : (filter_name_ + " (" + std::to_string(filter_eves_.size()) + ")");
  if (ImGui::BeginCombo("filter task", preview.c_str())) {
    if (ImGui::Selectable("(all)", filter_name_.empty())) {
      if (!filter_name_.empty()) { filter_name_.clear(); filter_changed = true; }
    }
    for (size_t i : sorted_tasks) {
      char label[160];
      snprintf(label, sizeof(label), "%s  (%zu)",
               summary[i].name.c_str(), summary[i].count);
      bool sel = (summary[i].name == filter_name_);
      if (ImGui::Selectable(label, sel)) {
        if (filter_name_ != summary[i].name) {
          filter_name_   = summary[i].name;
          follow_tail_   = false;
          filter_changed = true;
        }
      }
      if (sel) ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }

  ImGui::SameLine();
  ImGui::SetNextItemWidth(260);
  std::string sender_preview = sender_filter_.empty()
      ? std::string("(any)")
      : (sender_filter_ + " (" + std::to_string(sender_filter_eves_.size()) + ")");
  if (ImGui::BeginCombo("filter sender", sender_preview.c_str())) {
    if (ImGui::Selectable("(any)", sender_filter_.empty())) {
      if (!sender_filter_.empty()) { sender_filter_.clear(); filter_changed = true; }
    }
    for (size_t i : sorted_senders) {
      char label[160];
      snprintf(label, sizeof(label), "%s  (%zu)",
               sender_summary[i].name.c_str(), sender_summary[i].count);
      bool sel = (sender_summary[i].name == sender_filter_);
      if (ImGui::Selectable(label, sel)) {
        if (sender_filter_ != sender_summary[i].name) {
          sender_filter_  = sender_summary[i].name;
          follow_tail_    = false;
          filter_changed  = true;
        }
      }
      if (sel) ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }

  // ---- (re)build merged event list(s) for the active filter(s) -----------
  uint64_t cur_ver = index_version_.load(std::memory_order_relaxed);

  bool need_task_rebuild = !filter_name_.empty() &&
                           (filter_built_for_ != filter_name_ ||
                            filter_built_at_  != cur_ver);
  if (need_task_rebuild) {
    filter_eves_.clear();
    // Each shard owns a disjoint ascending event-num range and stores
    // events in scan order, so concatenating shards in worker-order yields
    // a globally-sorted vector.
    for (auto& sp : shards_) {
      std::lock_guard<std::mutex> g(sp->mu);
      auto it = sp->tasks.find(filter_name_);
      if (it != sp->tasks.end()) {
        filter_eves_.insert(filter_eves_.end(),
                            it->second.begin(), it->second.end());
      }
    }
    filter_built_for_ = filter_name_;
    filter_built_at_  = cur_ver;
  } else if (filter_name_.empty()) {
    filter_eves_.clear();
    filter_built_for_.clear();
  }

  bool need_sender_rebuild = !sender_filter_.empty() &&
                             (sender_filter_built_for_ != sender_filter_ ||
                              sender_filter_built_at_  != cur_ver);
  if (need_sender_rebuild) {
    sender_filter_eves_.clear();
    for (auto& sp : shards_) {
      std::lock_guard<std::mutex> g(sp->mu);
      auto it = sp->senders.find(sender_filter_);
      if (it != sp->senders.end()) {
        sender_filter_eves_.insert(sender_filter_eves_.end(),
                                   it->second.begin(), it->second.end());
      }
    }
    sender_filter_built_for_ = sender_filter_;
    sender_filter_built_at_  = cur_ver;
  } else if (sender_filter_.empty()) {
    sender_filter_eves_.clear();
    sender_filter_built_for_.clear();
  }

  // Compose the final filter view: task-only, sender-only, intersection,
  // or null (no filter).
  const std::vector<uint64_t>* filt_v = nullptr;
  if (!filter_name_.empty() && !sender_filter_.empty()) {
    combined_filter_eves_.clear();
    std::set_intersection(
        filter_eves_.begin(),        filter_eves_.end(),
        sender_filter_eves_.begin(), sender_filter_eves_.end(),
        std::back_inserter(combined_filter_eves_));
    filt_v = &combined_filter_eves_;
  } else if (!filter_name_.empty()) {
    filt_v = &filter_eves_;
  } else if (!sender_filter_.empty()) {
    filt_v = &sender_filter_eves_;
  }

  // If the user just picked a filter, snap cur_ into the filtered list so
  // the data pane immediately reflects an event matching the filter rather
  // than waiting for the next nav action.
  if (filter_changed && filt_v && !filt_v->empty()) {
    auto it = std::lower_bound(filt_v->begin(), filt_v->end(), (uint64_t)cur_);
    if (it == filt_v->end()) it = filt_v->end() - 1;
    cur_ = (int64_t)*it;
    prev_ = -1;  // force load_event() this frame
  }
  ImGui::SameLine();
  uint64_t total_eves = (last_ >= first_) ? (last_ - first_ + 1) : 0;
  if (all_done) {
    ImGui::TextDisabled("indexed %llu events on %zu threads",
                        (unsigned long long)total_indexed, shards_.size());
  } else {
    float pct = total_eves ? 100.f * (float)total_indexed / (float)total_eves : 0.f;
    ImGui::TextDisabled("indexing %llu / %llu (%.1f%%)  threads: %zu",
                        (unsigned long long)total_indexed,
                        (unsigned long long)total_eves, pct, shards_.size());
  }

  // ---- navigation row -----------------------------------------------------
  auto step_in_filter = [&](int dir) {
    if (!filt_v || filt_v->empty()) { cur_ += dir; return; }
    const auto& v = *filt_v;
    auto it = std::lower_bound(v.begin(), v.end(), (uint64_t)cur_);
    size_t idx;
    if (it == v.end()) idx = v.size() - 1;
    else               idx = (size_t)(it - v.begin());
    if (dir > 0) {
      if (idx < v.size() && (uint64_t)cur_ == v[idx])
        idx = (idx + 1 < v.size()) ? idx + 1 : idx;
    } else {
      idx = (idx > 0) ? idx - 1 : 0;
    }
    cur_ = (int64_t)v[idx];
  };

  if (ImGui::ArrowButton("##prev", ImGuiDir_Left))  { step_in_filter(-1); follow_tail_ = false; }
  ImGui::SameLine();
  if (ImGui::ArrowButton("##next", ImGuiDir_Right)) { step_in_filter(+1); follow_tail_ = false; }
  ImGui::SameLine();
  if (ImGui::Button("Tail")) {
    if (filt_v && !filt_v->empty()) cur_ = (int64_t)filt_v->back();
    else                             cur_ = (int64_t)last_;
    follow_tail_ = !filt_v;
  }
  ImGui::SameLine();
  ImGui::Checkbox("follow", &follow_tail_);
  ImGui::SameLine();
  ImGui::Text("range: %llu .. %llu", (unsigned long long)first_, (unsigned long long)last_);

  // ---- event number text input ---------------------------------------------
  static char eve_buf[32] = {0};
  static int64_t eve_buf_for = -1;
  if (eve_buf_for != cur_) {
    snprintf(eve_buf, sizeof(eve_buf), "%lld", (long long)cur_);
    eve_buf_for = cur_;
  }
  ImGui::SetNextItemWidth(-1);
  if (ImGui::InputText("##eve", eve_buf, sizeof(eve_buf),
                       ImGuiInputTextFlags_CharsDecimal |
                       ImGuiInputTextFlags_EnterReturnsTrue)) {
    long long parsed = atoll(eve_buf);
    if (parsed > 0) {
      cur_ = (int64_t)parsed;
      follow_tail_ = false;
    }
  }

  // ---- slider --------------------------------------------------------------
  if (filt_v) {
    const auto& v = *filt_v;
    if (!v.empty()) {
      auto it = std::lower_bound(v.begin(), v.end(), (uint64_t)cur_);
      int64_t idx = (it == v.end()) ? (int64_t)v.size() - 1
                                    : (int64_t)(it - v.begin());
      int64_t lo = 0, hi = (int64_t)v.size() - 1;
      // The filter labels (filter_name_, sender_filter_) embed user-facing
      // strings that may contain '%' (the task name, e.g. "%hear", or '~'
      // in patps); '%' is a printf specifier so escape to "%%" before
      // splicing into the format passed to ImGui::SliderScalar.
      std::string label;
      if (!filter_name_.empty())   label += filter_name_;
      if (!sender_filter_.empty()) {
        if (!label.empty()) label += " from ";
        label += sender_filter_;
      }
      std::string escaped;
      escaped.reserve(label.size() + 4);
      for (char c : label) {
        escaped += c;
        if (c == '%') escaped += '%';
      }
      char fmt[160];
      snprintf(fmt, sizeof(fmt), "%s %%lld / %zu", escaped.c_str(), v.size());
      ImGui::SetNextItemWidth(-1);
      if (ImGui::SliderScalar("##fslider", ImGuiDataType_S64,
                              &idx, &lo, &hi, fmt,
                              ImGuiSliderFlags_AlwaysClamp)) {
        cur_ = (int64_t)v[(size_t)idx];
        follow_tail_ = false;
      }
    } else {
      // Non-empty filters with no matches: keep the row visible so the
      // layout doesn't jump, and tell the user nothing matched.
      int64_t dummy = 0, lo = 0, hi = 0;
      ImGui::BeginDisabled();
      ImGui::SetNextItemWidth(-1);
      ImGui::SliderScalar("##empty_filter", ImGuiDataType_S64,
                          &dummy, &lo, &hi, "(no events match the active filters)",
                          ImGuiSliderFlags_AlwaysClamp);
      ImGui::EndDisabled();
    }
  } else {
    int64_t lo = (int64_t)first_;
    int64_t hi = (int64_t)last_;
    int64_t v  = cur_;
    ImGui::SetNextItemWidth(-1);
    if (ImGui::SliderScalar("##slider", ImGuiDataType_S64,
                            &v, &lo, &hi, "event %lld",
                            ImGuiSliderFlags_AlwaysClamp)) {
      cur_ = v;
      follow_tail_ = false;
    }
  }

  // ---- keyboard nav --------------------------------------------------------
  if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
      !ImGui::IsAnyItemActive()) {
    if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow,  true)) { step_in_filter(-1); follow_tail_ = false; }
    if (ImGui::IsKeyPressed(ImGuiKey_RightArrow, true)) { step_in_filter(+1); follow_tail_ = false; }
    if (ImGui::IsKeyPressed(ImGuiKey_PageUp,   true))   { for (int i = 0; i < 100; i++) step_in_filter(-1); follow_tail_ = false; }
    if (ImGui::IsKeyPressed(ImGuiKey_PageDown, true))   { for (int i = 0; i < 100; i++) step_in_filter(+1); follow_tail_ = false; }
    if (ImGui::IsKeyPressed(ImGuiKey_End)) {
      if (filt_v && !filt_v->empty()) cur_ = (int64_t)filt_v->back();
      else { cur_ = (int64_t)last_; follow_tail_ = true; }
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Home)) {
      if (filt_v && !filt_v->empty()) cur_ = (int64_t)filt_v->front();
      else                              cur_ = (int64_t)first_;
      follow_tail_ = false;
    }
  }

  if (cur_ < (int64_t)first_) cur_ = (int64_t)first_;
  if (cur_ > (int64_t)last_)  cur_ = (int64_t)last_;

  uint64_t node_ver = node_version_.load(std::memory_order_relaxed);
  if (cur_ != prev_ || follow_tail_ || node_ver != last_load_node_ver_) {
    load_event((uint64_t)cur_);
    prev_ = cur_;
    last_load_node_ver_ = node_ver;
  }

  ImGui::Separator();

  ImGui::Text("event   #%lld  (mug 0x%08x, %zu bytes)", (long long)cur_, mug_, raw_size_);
  ImGui::Text("time    %s", time_.c_str());
  ImGui::Text("wire    %s", wire_.c_str());
  ImGui::Text("task    %s", task_.c_str());
  ImGui::Separator();

  ImGui::TextUnformatted("data");
  ImVec2 avail = ImGui::GetContentRegionAvail();

  // InputTextMultiline doesn't word-wrap; pre-wrap the data ourselves.
  // Compute the column count from the available pixel width and the
  // monospace cell width. Re-wrap whenever the source string or the
  // available width changes (the wrap result is cached on the viewer so
  // we don't rebuild it every frame for free-scroll).
  float char_w = ImGui::CalcTextSize("M").x;
  if (char_w < 1.f) char_w = 7.f;  // sanity
  int  cols = (int)((avail.x - 24.f) / char_w);
  if (cols < 16) cols = 16;
  if (cols != wrap_cols_ ||
      data_.data() != wrap_src_ptr_ ||
      data_.size() != wrap_src_size_) {
    wrap_cols_     = cols;
    wrap_src_ptr_  = data_.data();
    wrap_src_size_ = data_.size();
    wrap_buf_.clear();
    wrap_to_data_.clear();
    wrap_buf_.reserve(data_.size() + data_.size() / (size_t)cols + 16);
    wrap_to_data_.reserve(wrap_buf_.capacity());
    int col = 0;
    int last_space = -1;
    for (size_t i = 0; i < data_.size(); i++) {
      char c = data_[i];
      if (c == '\n') {
        wrap_buf_ += c;
        wrap_to_data_.push_back((uint32_t)i);
        col = 0;
        last_space = -1;
        continue;
      }
      wrap_buf_ += c;
      wrap_to_data_.push_back((uint32_t)i);
      if (c == ' ') last_space = (int)wrap_buf_.size() - 1;
      col++;
      if (col >= cols) {
        if (last_space >= 0) {
          // Replace the space with a newline; the mapping entry for that
          // position keeps pointing at the original ' ' in data_, so a
          // copy that spans this break recovers the space.
          wrap_buf_[last_space] = '\n';
          col = (int)wrap_buf_.size() - last_space - 1;
          last_space = -1;
        } else {
          // Hard break: no corresponding character in data_.
          wrap_buf_ += '\n';
          wrap_to_data_.push_back(UINT32_MAX);
          col = 0;
        }
      }
    }
  }

  ImGui::InputTextMultiline("##data_box",
                            const_cast<char*>(wrap_buf_.c_str()),
                            wrap_buf_.size() + 1,
                            avail,
                            ImGuiInputTextFlags_ReadOnly);

  ImGui::End();
}
