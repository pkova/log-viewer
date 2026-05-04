// @p (patp) phonetic ship-name encoding.
//
// Ported from dire.c — straight translation of the Feistel obfuscator and
// suffix/prefix tables that hoon's @p uses. Faithful to the original;
// quirks (including the moon edge cases) are preserved.

#include "patp.h"

#include <stdint.h>
#include <string.h>
#include <vector>

namespace patp {

namespace {

constexpr uint32_t a_w =     0xffff;
constexpr uint32_t b_w =    0x10000;
constexpr uint32_t k_w = 0xffff0000;

constexpr uint32_t rak_w[4] = {
    0xb76d5eed, 0xee281300, 0x85bcae01, 0x4b387af7,
};

const char prefixes[256][4] = {
    "doz","mar","bin","wan","sam","lit","sig","hid","fid","lis","sog","dir","wac","sab","wis","sib",
    "rig","sol","dop","mod","fog","lid","hop","dar","dor","lor","hod","fol","rin","tog","sil","mir",
    "hol","pas","lac","rov","liv","dal","sat","lib","tab","han","tic","pid","tor","bol","fos","dot",
    "los","dil","for","pil","ram","tir","win","tad","bic","dif","roc","wid","bis","das","mid","lop",
    "ril","nar","dap","mol","san","loc","nov","sit","nid","tip","sic","rop","wit","nat","pan","min",
    "rit","pod","mot","tam","tol","sav","pos","nap","nop","som","fin","fon","ban","mor","wor","sip",
    "ron","nor","bot","wic","soc","wat","dol","mag","pic","dav","bid","bal","tim","tas","mal","lig",
    "siv","tag","pad","sal","div","dac","tan","sid","fab","tar","mon","ran","nis","wol","mis","pal",
    "las","dis","map","rab","tob","rol","lat","lon","nod","nav","fig","nom","nib","pag","sop","ral",
    "bil","had","doc","rid","moc","pac","rav","rip","fal","tod","til","tin","hap","mic","fan","pat",
    "tac","lab","mog","sim","son","pin","lom","ric","tap","fir","has","bos","bat","poc","hac","tid",
    "hav","sap","lin","dib","hos","dab","bit","bar","rac","par","lod","dos","bor","toc","hil","mac",
    "tom","dig","fil","fas","mit","hob","har","mig","hin","rad","mas","hal","rag","lag","fad","top",
    "mop","hab","nil","nos","mil","fop","fam","dat","nol","din","hat","nac","ris","fot","rib","hoc",
    "nim","lar","fit","wal","rap","sar","nal","mos","lan","don","dan","lad","dov","riv","bac","pol",
    "lap","tal","pit","nam","bon","ros","ton","fod","pon","sov","noc","sor","lav","mat","mip","fip",
};

const char suffixes[256][4] = {
    "zod","nec","bud","wes","sev","per","sut","let","ful","pen","syt","dur","wep","ser","wyl","sun",
    "ryp","syx","dyr","nup","heb","peg","lup","dep","dys","put","lug","hec","ryt","tyv","syd","nex",
    "lun","mep","lut","sep","pes","del","sul","ped","tem","led","tul","met","wen","byn","hex","feb",
    "pyl","dul","het","mev","rut","tyl","wyd","tep","bes","dex","sef","wyc","bur","der","nep","pur",
    "rys","reb","den","nut","sub","pet","rul","syn","reg","tyd","sup","sem","wyn","rec","meg","net",
    "sec","mul","nym","tev","web","sum","mut","nyx","rex","teb","fus","hep","ben","mus","wyx","sym",
    "sel","ruc","dec","wex","syr","wet","dyl","myn","mes","det","bet","bel","tux","tug","myr","pel",
    "syp","ter","meb","set","dut","deg","tex","sur","fel","tud","nux","rux","ren","wyt","nub","med",
    "lyt","dus","neb","rum","tyn","seg","lyx","pun","res","red","fun","rev","ref","mec","ted","rus",
    "bex","leb","dux","ryn","num","pyx","ryg","ryx","fep","tyr","tus","tyc","leg","nem","fer","mer",
    "ten","lus","nus","syl","tec","mex","pub","rym","tuc","fyl","lep","deb","ber","mug","hut","tun",
    "byl","sud","pem","dev","lur","def","bus","bep","run","mel","pex","dyt","byt","typ","lev","myl",
    "wed","duc","fur","fex","nul","luc","len","ner","lex","rup","ned","lec","ryd","lyd","fen","wel",
    "nyd","hus","rel","rud","nes","hes","fet","des","ret","dun","ler","nyr","seb","hul","ryl","lud",
    "rem","lys","fyn","wer","ryc","sug","nys","nyl","lyn","dyn","dem","lux","fed","sed","bec","mun",
    "lyr","tes","mud","nyt","byr","sen","weg","fyr","mur","tel","rep","teg","pec","nel","nev","fes",
};

inline uint32_t rotl32(uint32_t x, int8_t r) {
  return (x << r) | (x >> (32 - r));
}

inline uint32_t fmix32(uint32_t h) {
  h ^= h >> 16; h *= 0x85ebca6b;
  h ^= h >> 13; h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

void MurmurHash3_x86_32(const void* key, int32_t len,
                        uint32_t seed, void* out) {
  const uint8_t* data = (const uint8_t*)key;
  const int32_t  nblocks = len / 4;
  uint32_t h1 = seed;
  const uint32_t c1 = 0xcc9e2d51, c2 = 0x1b873593;

  const uint32_t* blocks = (const uint32_t*)(data + nblocks * 4);
  for (int32_t i = -nblocks; i; i++) {
    uint32_t k1 = blocks[i];
    k1 *= c1; k1 = rotl32(k1, 15); k1 *= c2;
    h1 ^= k1; h1 = rotl32(h1, 13); h1 = h1 * 5 + 0xe6546b64;
  }

  const uint8_t* tail = data + nblocks * 4;
  uint32_t k1 = 0;
  switch (len & 3) {
    case 3: k1 ^= tail[2] << 16;  // fallthrough
    case 2: k1 ^= tail[1] << 8;   // fallthrough
    case 1: k1 ^= tail[0];
            k1 *= c1; k1 = rotl32(k1, 15); k1 *= c2; h1 ^= k1;
  }
  h1 ^= len;
  h1 = fmix32(h1);
  *(uint32_t*)out = h1;
}

uint32_t feob(uint32_t m_w) {
  uint32_t l_w = m_w % a_w;
  uint32_t r_w = m_w / a_w;
  uint32_t f_w, t_w;
  uint8_t  k_y[2];

  for (uint8_t j_y = 0; j_y < 4; j_y++) {
    k_y[0] = (uint8_t)(r_w & 0xff);
    k_y[1] = (uint8_t)((r_w >> 8) & 0xff);
    MurmurHash3_x86_32(k_y, 2, rak_w[j_y], &f_w);
    // NB: addition can overflow a u32 before mod, so widen.
    t_w = (uint32_t)(((uint64_t)f_w + l_w) % ((j_y & 1) == 0 ? a_w : b_w));
    l_w = r_w;
    r_w = t_w;
  }
  return (a_w == r_w) ? (r_w * a_w) + l_w : (l_w * a_w) + r_w;
}

uint32_t feisob(uint32_t m_w) {
  uint32_t c_w = feob(m_w - b_w);
  return b_w + ((c_w < k_w) ? c_w : feob(c_w));
}

struct Ship { uint64_t hed; uint64_t tel; };

int ship_lz(const Ship& s) {
  int lz = 0;
  for (int i = 15; i >= 0; i--) {
    if (((const uint8_t*)&s)[i] != 0) break;
    lz++;
  }
  return lz;
}

std::string ship_to_patq(const Ship& s) {
  if (s.hed == 0 && s.tel == 0) return "~zod";
  const char (*tables[2])[4] = { suffixes, prefixes };
  int lz = ship_lz(s);
  int top = 15 - lz;
  std::string r = "~";
  for (int i = top; i >= 0; i--) {
    uint8_t byt = ((const uint8_t*)&s)[i];
    r += tables[i % 2][byt];
    if ((i % 2) == 0 && i != 0) {
      // Step boundary (between byte-pairs). Per urbit-ob's `patp`, every
      // 4th step gets a "--" instead of a single "-" — that's the boundary
      // between the moon-half and the planet-half within a comet.
      int step_done = (top - i) / 2 + 1;
      r += (step_done % 4 == 0) ? "--" : "-";
    }
  }
  return r;
}

// Apply urbit-ob's `fein` Feistel obfuscation to the ship value:
//   v < 0x10000           : galaxy/star, no obfuscation
//   0x10000 ≤ v < 2^32    : planet — feisob the entire 32-bit value
//   2^32 ≤ v < 2^64       : moon — keep the high 32 bits raw, recursively
//                           feisob the low 32 bits (only if they are
//                           themselves in planet range)
//   v ≥ 2^64              : comet — no obfuscation
std::string ship_to_patp(const Ship& s) {
  if (s.hed == 0 && s.tel == 0) return "~zod";
  Ship p = s;
  if (s.tel == 0) {
    if (s.hed >= 0x100000000ULL) {
      uint32_t lo = (uint32_t)s.hed;
      uint32_t obf = (lo < b_w) ? lo : feisob(lo);
      p.hed = (s.hed & 0xFFFFFFFF00000000ULL) | (uint64_t)obf;
    } else if (s.hed >= b_w) {
      p.hed = feisob((uint32_t)s.hed);
    }
  }
  return ship_to_patq(p);
}

}  // namespace

std::string from_bytes(const uint8_t* bytes, int n) {
  if (n < 0) n = 0;
  if (n > 16) n = 16;
  Ship s{0, 0};
  memcpy(&s, bytes, (size_t)n);
  return ship_to_patp(s);
}

namespace {

bool prefix_lookup(const std::string& syll, uint8_t* out) {
  for (int i = 0; i < 256; i++) {
    if (syll == prefixes[i]) { *out = (uint8_t)i; return true; }
  }
  return false;
}

bool suffix_lookup(const std::string& syll, uint8_t* out) {
  for (int i = 0; i < 256; i++) {
    if (syll == suffixes[i]) { *out = (uint8_t)i; return true; }
  }
  return false;
}

uint32_t defeob(uint32_t y_w) {
  uint32_t l, r;
  if (y_w >= a_w * a_w) {           // case 2: r ended up == a_w
    l = y_w - a_w * a_w;
    r = a_w;
  } else {                          // case 1
    l = y_w / a_w;
    r = y_w % a_w;
  }
  // Run feob's 4 rounds in reverse (j = 3, 2, 1, 0).
  for (int j = 3; j >= 0; j--) {
    uint32_t r_old = l;             // pre-round r became post-round l
    uint8_t k_y[2] = { (uint8_t)(r_old & 0xff),
                       (uint8_t)((r_old >> 8) & 0xff) };
    uint32_t f_w;
    MurmurHash3_x86_32(k_y, 2, rak_w[j], &f_w);
    uint32_t mod = ((j & 1) == 0) ? a_w : b_w;
    int64_t  l_old = (int64_t)r - (int64_t)f_w;
    l_old = ((l_old % (int64_t)mod) + (int64_t)mod) % (int64_t)mod;
    l = (uint32_t)l_old;
    r = r_old;
  }
  return l + r * a_w;
}

uint32_t defeisob(uint32_t y_w) {
  uint32_t outer = y_w - b_w;
  uint32_t c     = (outer < k_w) ? outer : defeob(outer);
  return defeob(c) + b_w;
}

}  // namespace

bool to_bytes(const std::string& patp_str, uint8_t* out, int max_size,
              int* actual_size) {
  if (patp_str.empty() || patp_str[0] != '~') return false;

  std::vector<std::string> sylls;
  size_t i = 1;
  while (i < patp_str.size()) {
    if (patp_str[i] == '-') { i++; continue; }
    if (i + 3 > patp_str.size()) return false;
    sylls.push_back(patp_str.substr(i, 3));
    i += 3;
  }
  // Accept 1 (galaxy), 2 (star pre-feistel), 4 (planet), 8 (moon), 16
  // (comet) syllables. Anything else is malformed.
  size_t ns = sylls.size();
  if (ns != 1 && ns != 2 && ns != 4 && ns != 8 && ns != 16) return false;

  // Decode every syllable into its byte value. Even-index syllables are
  // prefixes, odd-index are suffixes. Galaxy (single syllable) is a
  // special case: only a suffix.
  uint8_t bytes[16] = {0};
  if (ns == 1) {
    uint8_t b;
    if (!suffix_lookup(sylls[0], &b)) return false;
    bytes[0] = b;
  } else {
    // ship_to_patq emits byte (top - i) at syllable position i, with
    // top = ns - 1. So syllable i decodes into byte (ns - 1 - i).
    for (size_t i = 0; i < ns; i++) {
      uint8_t v;
      bool ok = (i % 2 == 0) ? prefix_lookup(sylls[i], &v)
                             : suffix_lookup(sylls[i], &v);
      if (!ok) return false;
      bytes[ns - 1 - i] = v;
    }
  }

  // Reverse the Feistel obfuscation. Mirrors `fein` in ship_to_patp:
  //   - galaxy/star (1-2 bytes effective): no obfuscation
  //   - planet (4 bytes): defeisob the whole 32-bit value when it sits in
  //                       the planet range
  //   - moon (8 bytes): defeisob the LOW 32 bits only; high 32 bits raw
  //   - comet (16 bytes): no obfuscation
  if (ns == 4 || ns == 8) {
    uint32_t lo = (uint32_t)bytes[0]
                | ((uint32_t)bytes[1] <<  8)
                | ((uint32_t)bytes[2] << 16)
                | ((uint32_t)bytes[3] << 24);
    if (lo >= b_w) lo = defeisob(lo);
    bytes[0] = (uint8_t)(lo);
    bytes[1] = (uint8_t)(lo >> 8);
    bytes[2] = (uint8_t)(lo >> 16);
    bytes[3] = (uint8_t)(lo >> 24);
  }

  // Determine the wire ship size: galaxies and stars share rank 0 (2 B),
  // planets are rank 1 (4 B), moons rank 2 (8 B), comets rank 3 (16 B).
  int ship_size;
  if (ns == 16)        ship_size = 16;
  else if (ns == 8)    ship_size = 8;
  else if (ns == 4) {
    // After defeisob, value < b_w means it shrunk into star range.
    uint64_t v = (uint64_t)bytes[0]
               | ((uint64_t)bytes[1] <<  8)
               | ((uint64_t)bytes[2] << 16)
               | ((uint64_t)bytes[3] << 24);
    ship_size = (v < b_w) ? 2 : 4;
  } else {
    ship_size = 2;
  }

  if (ship_size > max_size) return false;
  *actual_size = ship_size;
  for (int b = 0; b < ship_size; b++) out[b] = bytes[b];
  return true;
}

}  // namespace patp
