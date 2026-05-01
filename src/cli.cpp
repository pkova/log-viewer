// CLI subcommand implementations — pure C++, no GUI deps. Built on every
// platform; the GUI driver (Cocoa/Metal on macOS, Win32/DX11 on Windows)
// is its own translation unit.

#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "viewer.h"
#include "crypto.h"

extern "C" void crypto_eddsa_scalarbase(uint8_t point[32],
                                        const uint8_t scalar[32]);

// Defined at global scope in viewer.cpp.
extern bool g_debug_decrypt;

namespace cli {

// CLI probe: skip the GUI entirely, dump one event's parse to stdout.
//   log-viewer --probe <eve> <path-to-data.mdb> [--seed HEX]
int run_probe(int argc, const char* argv[]) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s --probe <eve> <path> [--seed HEX]\n", argv[0]);
    return 2;
  }
  uint64_t eve = (uint64_t)atoll(argv[2]);
  std::string path = argv[3];
  std::string seed;
  for (int i = 4; i + 1 < argc; i += 2) {
    std::string k = argv[i], v = argv[i + 1];
    if (k == "--seed") seed = v;
  }

  g_debug_decrypt = true;

  Viewer v;
  if (!v.open(path, /*start_index=*/false)) {
    fprintf(stderr, "open failed\n");
    return 1;
  }
  if (!seed.empty()) v.set_identity(seed);

  printf("range:  %llu .. %llu\n",
         (unsigned long long)v.first_eve(), (unsigned long long)v.last_eve());
  printf("event:  %llu\n", (unsigned long long)eve);
  v.load_event(eve);
  v.wait_for_pending_fetches();
  v.load_event(eve);
  printf("time:   %s\n", v.time().c_str());
  printf("wire:   %s\n", v.wire().c_str());
  printf("task:   %s\n", v.task().c_str());
  printf("\n%s\n", v.data().c_str());
  return 0;
}

// FIPS-197 + NIST CMAC self-tests. Returns 0 on success.
int run_crypto_test() {
  uint8_t key[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
  };
  uint8_t pt[16] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
  };
  uint8_t expected[16] = {
    0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89,
  };
  lv_crypto::Aes256 ctx;
  lv_crypto::aes256_init(&ctx, key);
  uint8_t ct[16];
  lv_crypto::aes256_encrypt(&ctx, pt, ct);
  if (memcmp(ct, expected, 16) != 0) {
    fprintf(stderr, "AES-256 FAIL\n  got:     ");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", ct[i]);
    fprintf(stderr, "\n  expected: ");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", expected[i]);
    fprintf(stderr, "\n");
    return 1;
  }
  fprintf(stderr, "AES-256 ok\n");

  uint8_t cmac_key[32] = {
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4,
  };
  uint8_t cmac_msg[16] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
  };
  uint8_t cmac_expected[16] = {
    0x28,0xa7,0x02,0x3f,0x45,0x2e,0x8f,0x82,0xbd,0x4b,0xf2,0x8d,0x8c,0x37,0xc3,0x5c,
  };
  lv_crypto::Aes256 cctx;
  lv_crypto::aes256_init(&cctx, cmac_key);
  uint8_t mac[16];
  lv_crypto::aes_cmac(&cctx, cmac_msg, 16, mac);
  if (memcmp(mac, cmac_expected, 16) != 0) {
    fprintf(stderr, "AES-256 CMAC (16B msg) FAIL\n  got:     ");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", mac[i]);
    fprintf(stderr, "\n  expected: ");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", cmac_expected[i]);
    fprintf(stderr, "\n");
    return 1;
  }
  fprintf(stderr, "AES-256 CMAC (16B) ok\n");

  uint8_t cmac_empty_expected[16] = {
    0x02,0x89,0x62,0xf6,0x1b,0x7b,0xf8,0x9e,0xfc,0x6b,0x55,0x1f,0x46,0x67,0xd9,0x83,
  };
  lv_crypto::aes_cmac(&cctx, nullptr, 0, mac);
  if (memcmp(mac, cmac_empty_expected, 16) != 0) {
    fprintf(stderr, "AES-256 CMAC (empty) FAIL\n");
    return 1;
  }
  fprintf(stderr, "AES-256 CMAC (empty) ok\n");
  return 0;
}

int run_pubkey(int argc, const char* argv[]) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s --pubkey <seed-hex-32-or-ring-65>\n", argv[0]);
    return 2;
  }
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  std::string in = argv[2];
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i + 1 < in.size(); ) {
    char c = in[i];
    if (c == '.' || c == ' ') { i++; continue; }
    if (c == '0' && (in[i+1] == 'x' || in[i+1] == 'X')) { i += 2; continue; }
    int hi = nib(in[i]), lo = nib(in[i + 1]);
    if (hi < 0 || lo < 0) { i++; continue; }
    bytes.push_back((uint8_t)((hi << 4) | lo));
    i += 2;
  }
  uint8_t seed[32];
  if (bytes.size() == 32) {
    memcpy(seed, bytes.data(), 32);
  } else if (bytes.size() == 65 && bytes[0]  == 0x42) {
    memcpy(seed, bytes.data() + 33, 32);
  } else if (bytes.size() == 65 && bytes[64] == 0x42) {
    for (int i = 0; i < 32; i++) seed[i] = bytes[31 - i];
  } else {
    fprintf(stderr, "got %zu bytes, expected 32 or 65 (with 'B' magic)\n",
            bytes.size());
    return 1;
  }
  fprintf(stderr, "seed (atom-LSB):\n  ");
  for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", seed[i]);
  fprintf(stderr, "\n");

  uint8_t scalar[32];
  lv_crypto::derive_scalar(seed, scalar);
  fprintf(stderr, "clamped scalar:\n  ");
  for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", scalar[i]);
  fprintf(stderr, "\n");

  uint8_t pub[32];
  crypto_eddsa_scalarbase(pub, scalar);
  fprintf(stderr, "ed25519 pubkey (atom-LSB, monocypher output):\n  ");
  for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", pub[i]);
  fprintf(stderr, "\n");

  fprintf(stderr, "api-format (MSB-first):\n  0x");
  for (int i = 31; i >= 0; i--) fprintf(stderr, "%02x", pub[i]);
  fprintf(stderr, "\n");
  return 0;
}

}  // namespace cli
