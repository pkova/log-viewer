#pragma once

// Tiny synchronous client for network-explorer-api.arvo.network.
// Hits the /get-node endpoint, extracts the `encryption-key` (32 bytes,
// MSB-first display, stored here in atom-LSB byte order) and `revision`
// (the ship's current life) from the JSON.

#include <stdint.h>
#include <string>

namespace api {

struct NodeInfo {
  uint8_t enc_key[32];   // atom-LSB byte order (ready for monocypher)
  int     revision = 0;  // = life
};

// Synchronous HTTPS GET via /usr/bin/curl. Returns true on success.
// `patp` must be a plain @p like "~halbex-palheb" (no spaces/quotes).
bool fetch_node(const std::string& patp, NodeInfo* out);

}  // namespace api
