#pragma once

#include <stdint.h>
#include <string>

namespace patp {

// Convert `n` raw ship bytes (LSB-first, as on the ames wire) into a
// phonetic @p string like "~sampel-palnet". Galaxies and comets are
// rendered without obfuscation; planets and moons run through the
// Feistel-cipher (feisob/feob).
std::string from_bytes(const uint8_t* bytes, int n);

// Inverse: parse a @p string into atom-LSB bytes. Supports galaxies
// (1 syllable), stars (2 syllables), planets (4 syllables), moons
// (8 syllables) and comets (16 syllables). Output is sized to the wire
// ship-rank: 2 bytes for galaxy/star, 4 bytes for planet, 8 bytes for
// moon, 16 bytes for comet. Returns false on shape mismatch or
// unrecognized syllables.
bool to_bytes(const std::string& patp_str, uint8_t* out, int max_size,
              int* actual_size);

}  // namespace patp
