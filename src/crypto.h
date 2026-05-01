#pragma once

// Minimal crypto for ames decryption.
//
// All inputs/outputs are byte buffers in normal (network/MSB-first) order.
// The caller is responsible for converting hoon atoms (which are stored
// LSB-first in memory) to the byte order each routine expects.

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

namespace lv_crypto {

// AES-256 raw block cipher.
struct Aes256 {
  uint32_t rk[60];  // expanded round keys (14 rounds + 1)
};
void aes256_init(Aes256* ctx, const uint8_t key[32]);
void aes256_encrypt(const Aes256* ctx, const uint8_t in[16], uint8_t out[16]);

// AES-256-CMAC (RFC 4493) — single-shot.
void aes_cmac(const Aes256* ctx, const uint8_t* data, size_t len, uint8_t mac[16]);

// AES-256 SIV-CMAC (RFC 5297). Decrypt only.
//
//   key       : 64 bytes; high 32 = S2V key, low 32 = CTR key
//   ad[]      : associated data, ad_lens[]: their lengths, ad_count: how many
//   iv        : 16-byte SIV from the ciphertext blob
//   ct        : ciphertext bytes (length only)
//   ct_len    : length in bytes
//   pt        : output plaintext (must be ct_len bytes)
// Returns true on tag match, false otherwise.
bool aes_siv_decrypt(const uint8_t key[64],
                     const uint8_t* const* ad, const size_t* ad_lens, size_t ad_count,
                     const uint8_t iv[16],
                     const uint8_t* ct, size_t ct_len,
                     uint8_t* pt);

// ---- ames key-agreement (mirrors hoon's `luck` and `slar`) ----------------
//
// derive_scalar: Ed25519 clamped scalar from a 32-byte seed.
//                Output bytes are little-endian as required by X25519.
//
// derive_shared_secret: X25519(our_scalar, ed25519_to_x25519(peer_pubkey)).
//                Inputs in their natural ed25519 byte order (the bytes from
//                the API "encryption-key" field). Output is 32 bytes.
//
// derive_symmetric_key: convenience — runs the full path end-to-end and
//                       returns the 64-byte SHA-512(shared_secret) used as
//                       the SIV-CMAC key.
void derive_scalar(const uint8_t seed[32], uint8_t scalar[32]);
void derive_shared_secret(const uint8_t our_scalar[32],
                          const uint8_t peer_eddsa_pub[32],
                          uint8_t out_secret[32]);
void derive_symmetric_key(const uint8_t our_seed[32],
                          const uint8_t peer_eddsa_pub[32],
                          uint8_t out_key64[64]);

void sha512(const uint8_t* msg, size_t len, uint8_t hash[64]);

// Reverse `len` bytes in place — atom-byte-order ↔ RFC-byte-order conversion.
void reverse_bytes(uint8_t* buf, size_t len);

// ---- fake-ship key derivation (jael %fake boot) ---------------------------
//
// `++pit:nu:crub:crypto 512 our` (vane/jael.hoon line 338): take the ship
// atom, zero-pad to 64 bytes, SHA-512, and split the digest in half — the
// HIGH 32 bytes are the crypto seed `c`, the low 32 bytes are the signing
// seed (unused here). Both functions take ship-atom bytes in atom-LSB
// order — i.e., the same byte layout the ames wire uses.
void derive_fake_seed(const uint8_t* ship_bytes, int ship_size,
                      uint8_t out_seed[32]);

// Ed25519 public key for the fake ship's crypto seed: `puck(c)`.
void derive_fake_eddsa_pub(const uint8_t* ship_bytes, int ship_size,
                           uint8_t out_pub[32]);

// ---- mesa (UIP 0113) directed-messaging path encryption -------------------

// BLAKE3 keyed hash. Key is 32 bytes; msg/out are arbitrary length.
void blake3_keyed(const uint8_t key[32],
                  const uint8_t* msg, size_t msg_len,
                  uint8_t* out, size_t out_len);

// BLAKE3 KDF mode (RFC 9580 §3.4): derives `out_len` bytes from `ikm`
// keyed by `context_str`.
void blake3_kdf(const char* context_str, size_t context_len,
                const uint8_t* ikm, size_t ikm_len,
                uint8_t* out, size_t out_len);

// Mesa's `+open-path:crypt`: AEAD-decrypt a sealed path using the X25519
// shared secret as the AEAD key. AEAD = HChaCha8-derived ChaCha8 stream
// cipher + BLAKE3 keyed-hash MAC; nonce derived from the tag via blake3-kdf.
// Returns true on tag verification + writes plaintext path bytes (no leading
// slash) to *out.
//
//   sym_key:  32-byte X25519 shared secret (atom-LSB byte order)
//   sealed:   atom-LSB bytes of the seal-path output
//             layout: [tag(16) | ciphertext(N) | 0x01]
bool mesa_open_path(const uint8_t sym_key[32],
                    const uint8_t* sealed, size_t sealed_len,
                    std::string* out);

// Mesa's `+decrypt:crypt`: ChaCha8-decrypt a `[%chum ...]`-space-encrypted
// `data` payload. Unlike +open-path, there is no MAC — only a 0x01 sentinel
// byte at the end. The IV is the sealed-path blob (same atom-LSB bytes
// passed to mesa_open_path) — its full length is hashed under the
// "mesa-crypt-iv" KDF context to derive the XChaCha8 nonce.
//
//   sym_key:  X25519 shared secret (the peer's symmetric_key, atom-LSB)
//   iv:       sealed-path atom-LSB bytes
//   ct:       ciphertext atom-LSB bytes (last byte must be 0x01)
//   pt_out:   plaintext bytes (resized to ct_len-1)
// Returns true if the sentinel byte is present.
bool mesa_decrypt_data(const uint8_t sym_key[32],
                       const uint8_t* iv, size_t iv_len,
                       const uint8_t* ct, size_t ct_len,
                       std::vector<uint8_t>* pt_out);

}  // namespace lv_crypto
