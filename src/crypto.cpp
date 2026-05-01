// AES-256, AES-CMAC (RFC 4493), and AES-256-SIV-CMAC (RFC 5297).
// Decrypt-only — that's all the viewer needs.
//
// Buffers are MSB-first (RFC convention). The caller is responsible for
// reversing hoon-atom byte arrays before invoking aes_siv_decrypt.

#include "crypto.h"

#include <stdlib.h>
#include <string.h>
#include <vector>

extern "C" {
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "blake3.h"
}

namespace lv_crypto {

// ---------- AES-256 ---------------------------------------------------------

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t RCON[15] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,
};

static inline uint32_t word_be(const uint8_t* b) {
  return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
         ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}

static inline uint32_t SubWord(uint32_t w) {
  return ((uint32_t)SBOX[(w >> 24) & 0xff] << 24)
       | ((uint32_t)SBOX[(w >> 16) & 0xff] << 16)
       | ((uint32_t)SBOX[(w >>  8) & 0xff] <<  8)
       |  (uint32_t)SBOX[ w        & 0xff];
}

static inline uint32_t RotWord(uint32_t w) {
  return (w << 8) | (w >> 24);
}

void aes256_init(Aes256* ctx, const uint8_t key[32]) {
  uint32_t* rk = ctx->rk;
  for (int i = 0; i < 8; i++) rk[i] = word_be(key + 4 * i);
  for (int i = 8; i < 60; i++) {
    uint32_t t = rk[i - 1];
    if      ((i & 7) == 0) t = SubWord(RotWord(t)) ^ ((uint32_t)RCON[i / 8] << 24);
    else if ((i & 7) == 4) t = SubWord(t);
    rk[i] = rk[i - 8] ^ t;
  }
}

static inline uint8_t xt(uint8_t b) {
  return (uint8_t)((b << 1) ^ ((b & 0x80) ? 0x1b : 0));
}

void aes256_encrypt(const Aes256* ctx, const uint8_t in[16], uint8_t out[16]) {
  uint8_t s[16];
  memcpy(s, in, 16);

  // AddRoundKey 0
  for (int c = 0; c < 4; c++) {
    uint32_t k = ctx->rk[c];
    s[4*c+0] ^= (uint8_t)(k >> 24);
    s[4*c+1] ^= (uint8_t)(k >> 16);
    s[4*c+2] ^= (uint8_t)(k >>  8);
    s[4*c+3] ^= (uint8_t) k;
  }

  for (int round = 1; round <= 14; round++) {
    // SubBytes
    for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];

    // ShiftRows: state stored column-major s[r + 4c]; row r shifts left by r.
    uint8_t t;
    t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
    t = s[2];  s[2]  = s[10]; s[10] = t;
    t = s[6];  s[6]  = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = s[3];  s[3]  = t;

    // MixColumns (skip on last round)
    if (round < 14) {
      for (int c = 0; c < 4; c++) {
        uint8_t a0 = s[4*c+0], a1 = s[4*c+1], a2 = s[4*c+2], a3 = s[4*c+3];
        uint8_t a0_2 = xt(a0), a1_2 = xt(a1), a2_2 = xt(a2), a3_2 = xt(a3);
        s[4*c+0] = a0_2 ^ a1_2 ^ a1 ^ a2 ^ a3;
        s[4*c+1] = a0 ^ a1_2 ^ a2_2 ^ a2 ^ a3;
        s[4*c+2] = a0 ^ a1 ^ a2_2 ^ a3_2 ^ a3;
        s[4*c+3] = a0_2 ^ a0 ^ a1 ^ a2 ^ a3_2;
      }
    }

    // AddRoundKey
    for (int c = 0; c < 4; c++) {
      uint32_t k = ctx->rk[4*round + c];
      s[4*c+0] ^= (uint8_t)(k >> 24);
      s[4*c+1] ^= (uint8_t)(k >> 16);
      s[4*c+2] ^= (uint8_t)(k >>  8);
      s[4*c+3] ^= (uint8_t) k;
    }
  }
  memcpy(out, s, 16);
}

// ---------- AES-CTR (decrypt = encrypt) -------------------------------------

static void aes_ctr(const Aes256* ctx, uint8_t counter[16],
                    const uint8_t* in, size_t len, uint8_t* out) {
  uint8_t ks[16];
  size_t off = 0;
  while (off < len) {
    aes256_encrypt(ctx, counter, ks);
    size_t n = len - off; if (n > 16) n = 16;
    for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
    off += n;
    // Increment 128-bit big-endian counter.
    for (int i = 15; i >= 0; i--) if (++counter[i]) break;
  }
}

// ---------- CMAC subkeys + helpers ------------------------------------------

static void cmac_dbl(uint8_t b[16]) {
  uint8_t carry = (b[0] & 0x80) ? 0x87 : 0x00;
  for (int i = 0; i < 15; i++) b[i] = (uint8_t)((b[i] << 1) | (b[i+1] >> 7));
  b[15] = (uint8_t)((b[15] << 1) ^ carry);
}

static void cmac_subkeys(const Aes256* ctx, uint8_t K1[16], uint8_t K2[16]) {
  uint8_t L[16] = {0};
  aes256_encrypt(ctx, L, L);  // L = AES(K, 0)
  memcpy(K1, L, 16); cmac_dbl(K1);
  memcpy(K2, K1, 16); cmac_dbl(K2);
}

void aes_cmac(const Aes256* ctx, const uint8_t* data, size_t len, uint8_t mac[16]) {
  uint8_t K1[16], K2[16];
  cmac_subkeys(ctx, K1, K2);

  uint8_t X[16] = {0};
  uint8_t M_last[16];

  if (len == 0) {
    M_last[0] = 0x80;
    for (int i = 1; i < 16; i++) M_last[i] = 0;
    for (int i = 0; i < 16; i++) M_last[i] ^= K2[i];
  } else {
    size_t n = (len + 15) / 16;
    bool last_complete = (len % 16) == 0;

    for (size_t i = 0; i < n - 1; i++) {
      for (int j = 0; j < 16; j++) X[j] ^= data[i*16 + j];
      aes256_encrypt(ctx, X, X);
    }

    size_t last_off = (n - 1) * 16;
    if (last_complete) {
      for (int j = 0; j < 16; j++) M_last[j] = data[last_off + j] ^ K1[j];
    } else {
      size_t last_len = len - last_off;
      for (size_t j = 0; j < last_len; j++) M_last[j] = data[last_off + j];
      M_last[last_len] = 0x80;
      for (size_t j = last_len + 1; j < 16; j++) M_last[j] = 0;
      for (int j = 0; j < 16; j++) M_last[j] ^= K2[j];
    }
  }

  for (int j = 0; j < 16; j++) X[j] ^= M_last[j];
  aes256_encrypt(ctx, X, mac);
}

// ---------- S2V (RFC 5297) --------------------------------------------------

// Compute CMAC over `msg` with its last 128 bits XORed by D — the S2V
// "xorend" operation. xorend XORs D into the *last 128 bits of msg*, which
// can straddle a block boundary when msg_len % 16 != 0; the simplest
// correct approach is to build the full T buffer and run CMAC on it.
static void cmac_xorend(const Aes256* ctx, const uint8_t* msg, size_t msg_len,
                        const uint8_t D[16], uint8_t out[16]) {
  // Pre: msg_len >= 16 (caller checked).
  if (msg_len <= 256) {
    uint8_t T[256];
    memcpy(T, msg, msg_len);
    for (int j = 0; j < 16; j++) T[msg_len - 16 + j] ^= D[j];
    aes_cmac(ctx, T, msg_len, out);
  } else {
    uint8_t* T = (uint8_t*)malloc(msg_len);
    memcpy(T, msg, msg_len);
    for (int j = 0; j < 16; j++) T[msg_len - 16 + j] ^= D[j];
    aes_cmac(ctx, T, msg_len, out);
    free(T);
  }
}

static void s2v(const Aes256* k1_ctx,
                const uint8_t* const* ad, const size_t* ad_lens, size_t ad_count,
                const uint8_t* msg, size_t msg_len,
                uint8_t v[16]) {
  uint8_t D[16], tmp[16];
  uint8_t zero[16] = {0};
  aes_cmac(k1_ctx, zero, 16, D);

  for (size_t i = 0; i < ad_count; i++) {
    cmac_dbl(D);
    aes_cmac(k1_ctx, ad[i], ad_lens[i], tmp);
    for (int j = 0; j < 16; j++) D[j] ^= tmp[j];
  }

  if (msg_len >= 16) {
    cmac_xorend(k1_ctx, msg, msg_len, D, v);
  } else {
    cmac_dbl(D);
    uint8_t T[16] = {0};
    for (size_t j = 0; j < msg_len; j++) T[j] = msg[j];
    if (msg_len < 16) T[msg_len] = 0x80;
    for (int j = 0; j < 16; j++) T[j] ^= D[j];
    aes_cmac(k1_ctx, T, 16, v);
  }
}

// ---------- AES-SIV decrypt (RFC 5297) --------------------------------------

bool aes_siv_decrypt(const uint8_t key[64],
                     const uint8_t* const* ad, const size_t* ad_lens, size_t ad_count,
                     const uint8_t iv[16],
                     const uint8_t* ct, size_t ct_len,
                     uint8_t* pt) {
  Aes256 k1, k2;
  aes256_init(&k1, key);          // S2V key
  aes256_init(&k2, key + 32);     // CTR key

  // Q = IV with bits 31 and 63 (counting from MSB end) of bytes 8 and 12 cleared.
  uint8_t Q[16];
  memcpy(Q, iv, 16);
  Q[8]  &= 0x7f;
  Q[12] &= 0x7f;

  aes_ctr(&k2, Q, ct, ct_len, pt);

  uint8_t v[16];
  s2v(&k1, ad, ad_lens, ad_count, pt, ct_len, v);

  uint8_t diff = 0;
  for (int i = 0; i < 16; i++) diff |= (uint8_t)(v[i] ^ iv[i]);
  return diff == 0;
}

// ---------- ames key-agreement ---------------------------------------------

void sha512(const uint8_t* msg, size_t len, uint8_t hash[64]) {
  crypto_sha512(hash, msg, len);
}

void reverse_bytes(uint8_t* buf, size_t len) {
  for (size_t i = 0, j = len - 1; i < j; i++, j--) {
    uint8_t t = buf[i]; buf[i] = buf[j]; buf[j] = t;
  }
}

// Ed25519 clamped scalar from a 32-byte seed (matches +luck:ed:crypto):
//   h = SHA-512(seed)
//   a = h[0..31] with bottom 3 bits cleared, top bit cleared, bit 254 set
void derive_scalar(const uint8_t seed[32], uint8_t scalar[32]) {
  uint8_t h[64];
  crypto_sha512(h, seed, 32);
  memcpy(scalar, h, 32);
  scalar[0]  &= 0xf8;
  scalar[31] &= 0x7f;
  scalar[31] |= 0x40;
}

// Mirror +slar:ed:crypto:
//   1) decompress Ed25519 pubkey -> Montgomery u = (1+y)/(1-y) mod p
//   2) X25519(scalar, u)
void derive_shared_secret(const uint8_t our_scalar[32],
                          const uint8_t peer_eddsa_pub[32],
                          uint8_t out_secret[32]) {
  uint8_t mont_pub[32];
  crypto_eddsa_to_x25519(mont_pub, peer_eddsa_pub);
  crypto_x25519(out_secret, our_scalar, mont_pub);
}

void derive_symmetric_key(const uint8_t our_seed[32],
                          const uint8_t peer_eddsa_pub[32],
                          uint8_t out_key64[64]) {
  uint8_t scalar[32], secret[32];
  derive_scalar(our_seed, scalar);
  derive_shared_secret(scalar, peer_eddsa_pub, secret);
  // hoon's symmetric_key is the X25519 result; the SIV key is shaz(...)
  crypto_sha512(out_key64, secret, 32);
}

// ---- fake-ship key derivation (jael %fake) --------------------------------

void derive_fake_seed(const uint8_t* ship_bytes, int ship_size,
                      uint8_t out_seed[32]) {
  uint8_t input[64] = {0};
  int n = ship_size > 64 ? 64 : ship_size;
  if (n > 0) memcpy(input, ship_bytes, (size_t)n);
  uint8_t hash[64];
  crypto_sha512(hash, input, 64);
  // hoon's `(rsh 8 bits)` — top 32 atom-bytes of the 64-byte digest, which
  // in atom-LSB layout corresponds to bytes [32..63] of the SHA-512 output.
  memcpy(out_seed, hash + 32, 32);
}

void derive_fake_eddsa_pub(const uint8_t* ship_bytes, int ship_size,
                           uint8_t out_pub[32]) {
  uint8_t crypto_seed[32];
  derive_fake_seed(ship_bytes, ship_size, crypto_seed);
  // Ed25519 keypair-from-seed (puck:ed). monocypher's variant zeros the
  // seed argument on return, so pass a private copy.
  uint8_t seed_copy[32];
  memcpy(seed_copy, crypto_seed, 32);
  uint8_t sk[64];
  crypto_ed25519_key_pair(sk, out_pub, seed_copy);
}

// ---- BLAKE3 wrappers + mesa path decryption -------------------------------

void blake3_keyed(const uint8_t key[32],
                  const uint8_t* msg, size_t msg_len,
                  uint8_t* out, size_t out_len) {
  blake3_hasher h;
  blake3_hasher_init_keyed(&h, key);
  blake3_hasher_update(&h, msg, msg_len);
  blake3_hasher_finalize(&h, out, out_len);
}

void blake3_kdf(const char* context_str, size_t context_len,
                const uint8_t* ikm, size_t ikm_len,
                uint8_t* out, size_t out_len) {
  blake3_hasher h;
  blake3_hasher_init_derive_key_raw(&h, context_str, context_len);
  blake3_hasher_update(&h, ikm, ikm_len);
  blake3_hasher_finalize(&h, out, out_len);
}

// ---- ChaCha8 / HChaCha8 (mesa uses 8-round ChaCha, not 20) ----------------

static inline uint32_t load32_le(const uint8_t* p) {
  return  (uint32_t)p[0]
       | ((uint32_t)p[1] <<  8)
       | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
}
static inline void store32_le(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t) v;
  p[1] = (uint8_t)(v >>  8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}
static inline uint32_t rotl32(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

#define CHACHA_QR(a,b,c,d) \
  a += b; d ^= a; d = rotl32(d,16); \
  c += d; b ^= c; b = rotl32(b,12); \
  a += b; d ^= a; d = rotl32(d, 8); \
  c += d; b ^= c; b = rotl32(b, 7);

// 4 double rounds = 8 rounds total.
static void chacha8_rounds(uint32_t s[16]) {
  for (int i = 0; i < 4; i++) {
    CHACHA_QR(s[ 0], s[ 4], s[ 8], s[12]);
    CHACHA_QR(s[ 1], s[ 5], s[ 9], s[13]);
    CHACHA_QR(s[ 2], s[ 6], s[10], s[14]);
    CHACHA_QR(s[ 3], s[ 7], s[11], s[15]);
    CHACHA_QR(s[ 0], s[ 5], s[10], s[15]);
    CHACHA_QR(s[ 1], s[ 6], s[11], s[12]);
    CHACHA_QR(s[ 2], s[ 7], s[ 8], s[13]);
    CHACHA_QR(s[ 3], s[ 4], s[ 9], s[14]);
  }
}

static const uint32_t CHACHA_SIGMA[4] = {
  0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
};

// HChaCha8: 32-byte key + 16-byte nonce → 32-byte subkey.
//   state words: [sigma | key | nonce(4 words)]  (no add-state step)
static void hchacha8(const uint8_t key[32], const uint8_t nonce16[16],
                     uint8_t out[32]) {
  uint32_t s[16];
  for (int i = 0; i < 4; i++) s[i]      = CHACHA_SIGMA[i];
  for (int i = 0; i < 8; i++) s[4 + i]  = load32_le(key + 4*i);
  for (int i = 0; i < 4; i++) s[12 + i] = load32_le(nonce16 + 4*i);
  chacha8_rounds(s);
  for (int i = 0; i < 4; i++) store32_le(out + 4*i,        s[i]);
  for (int i = 0; i < 4; i++) store32_le(out + 16 + 4*i,   s[12 + i]);
}

// ChaCha8 stream-XOR with 64-bit nonce + 64-bit counter (DJB layout).
static void chacha8_djb_xor(const uint8_t key[32], const uint8_t nonce8[8],
                            uint64_t counter,
                            const uint8_t* in, size_t len, uint8_t* out) {
  uint32_t s0[16];
  for (int i = 0; i < 4; i++) s0[i]      = CHACHA_SIGMA[i];
  for (int i = 0; i < 8; i++) s0[4 + i]  = load32_le(key + 4*i);
  s0[14] = load32_le(nonce8);
  s0[15] = load32_le(nonce8 + 4);

  size_t off = 0;
  while (off < len) {
    s0[12] = (uint32_t) counter;
    s0[13] = (uint32_t)(counter >> 32);
    uint32_t s[16];
    memcpy(s, s0, sizeof(s));
    chacha8_rounds(s);
    uint8_t block[64];
    for (int i = 0; i < 16; i++) store32_le(block + 4*i, s[i] + s0[i]);
    size_t n = len - off; if (n > 64) n = 64;
    for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ block[i];
    off += n;
    counter++;
  }
}

bool mesa_open_path(const uint8_t sym_key[32],
                    const uint8_t* sealed, size_t sealed_len,
                    std::string* out) {
  // Layout per +seal-path:crypt — `(can 3 [16 tag] cyf [1 0x1] ~)`:
  //   atom-bytes [0..15]              = tag (BLAKE3 keyed-MAC over plaintext)
  //   atom-bytes [16..N-2]            = ciphertext (ChaCha8)
  //   atom-byte  [N-1]                = 0x01 sentinel
  if (sealed_len < 18) return false;
  if (sealed[sealed_len - 1] != 0x01) return false;

  // keys = blake3_kdf("mesa-aead", sym_key)[0..64]
  // enc_key = keys[0..31], mac_key = keys[32..63]
  uint8_t keys[64];
  blake3_kdf("mesa-aead", 9, sym_key, 32, keys, 64);
  const uint8_t* enc_key = keys;
  const uint8_t* mac_key = keys + 32;

  const uint8_t* tag     = sealed;
  const uint8_t* cyf     = sealed + 16;
  size_t         cyf_len = sealed_len - 17;

  // 24-byte XChaCha8 nonce = blake3_kdf("mesa-crypt-iv", tag).
  // Then xchacha8 returns (subkey32, sub_nonce8) = (HChaCha8(key, xnonce[0..16]),
  //                                                  xnonce[16..24]).
  uint8_t xnonce[24];
  blake3_kdf("mesa-crypt-iv", 13, tag, 16, xnonce, 24);
  uint8_t subkey[32];
  hchacha8(enc_key, xnonce, subkey);

  std::vector<uint8_t> pt(cyf_len);
  chacha8_djb_xor(subkey, xnonce + 16, /*counter=*/0, cyf, cyf_len, pt.data());

  // Tag = blake3_keyed(mac_key, plaintext)[0..16]
  uint8_t recomputed[16];
  blake3_keyed(mac_key, pt.data(), cyf_len, recomputed, 16);
  uint8_t diff = 0;
  for (int i = 0; i < 16; i++) diff |= (uint8_t)(tag[i] ^ recomputed[i]);
  if (diff != 0) return false;

  out->assign((const char*)pt.data(), cyf_len);
  return true;
}

bool mesa_decrypt_data(const uint8_t sym_key[32],
                       const uint8_t* iv, size_t iv_len,
                       const uint8_t* ct, size_t ct_len,
                       std::vector<uint8_t>* pt_out) {
  // hoon `+decrypt`: cyf must be at least 2 bytes (1 ct + 0x01 sentinel),
  // last byte 0x01, output is crypt(key, iv_octs, (ct_len-1)^cyf_bytes).
  if (ct_len < 2) return false;
  if (ct[ct_len - 1] != 0x01) return false;

  // Same xchacha8 dance as mesa_open_path, but key = sym_key directly
  // (no blake3-kdf step) and the IV is the entire sealed-path blob.
  uint8_t xnonce[24];
  blake3_kdf("mesa-crypt-iv", 13, iv, iv_len, xnonce, 24);
  uint8_t subkey[32];
  hchacha8(sym_key, xnonce, subkey);

  size_t pt_len = ct_len - 1;
  pt_out->resize(pt_len);
  chacha8_djb_xor(subkey, xnonce + 16, /*counter=*/0, ct, pt_len, pt_out->data());
  return true;
}

}  // namespace lv_crypto
