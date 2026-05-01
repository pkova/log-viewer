#include "api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"

namespace api {

namespace {

bool find_str_field(const std::string& body, const char* prefix,
                    std::string* out) {
  size_t p = body.find(prefix);
  if (p == std::string::npos) return false;
  p += strlen(prefix);
  size_t q = body.find('"', p);
  if (q == std::string::npos) return false;
  *out = body.substr(p, q - p);
  return true;
}

bool find_int_field(const std::string& body, const char* prefix, int* out) {
  size_t p = body.find(prefix);
  if (p == std::string::npos) return false;
  p += strlen(prefix);
  *out = atoi(body.c_str() + p);
  return true;
}

bool parse_hex_msb(const std::string& hex, uint8_t out_lsb[32]) {
  size_t off = 0;
  if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) off = 2;
  if (hex.size() - off != 64) return false;
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  uint8_t msb[32];
  for (int i = 0; i < 32; i++) {
    int hi = nib(hex[off + 2*i]), lo = nib(hex[off + 2*i + 1]);
    if (hi < 0 || lo < 0) return false;
    msb[i] = (uint8_t)((hi << 4) | lo);
  }
  for (int i = 0; i < 32; i++) out_lsb[i] = msb[31 - i];
  return true;
}

}  // namespace

bool fetch_node(const std::string& patp, NodeInfo* out) {
  std::string path = "/get-node?urbit-id=" + patp;
  http::Response resp =
      http::https_get("network-explorer-api.arvo.network", path);
  if (!resp.ok) return false;

  std::string enc_hex;
  if (!find_str_field(resp.body, "\"encryption-key\":\"", &enc_hex)) return false;
  if (!parse_hex_msb(enc_hex, out->enc_key)) return false;
  if (!find_int_field(resp.body, "\"revision\":", &out->revision)) return false;
  return true;
}

}  // namespace api
