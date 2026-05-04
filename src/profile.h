#pragma once

// Tiny scope-timer for the viewer's hot paths. Off by default; setting
// `lv::g_profile = true` (e.g. by CLI mode) makes each `LV_PROFILE_SCOPE`
// emit its label + elapsed microseconds to stderr at scope exit, and lets
// `LV_PROFILE_BLOCK` accumulate the elapsed time into a named bucket
// printed by `lv::profile_dump()`.
//
// Designed to live alongside the existing g_debug_decrypt flag — small,
// stderr-driven, no allocation, no extra deps.

#include <stdio.h>

#include <atomic>
#include <chrono>
#include <string>
#include <unordered_map>
#include <utility>

namespace lv {

extern bool g_profile;

struct ScopeTimer {
  const char* label;
  std::chrono::steady_clock::time_point t0;
  ScopeTimer(const char* l) : label(l), t0(std::chrono::steady_clock::now()) {}
  ~ScopeTimer() {
    if (!g_profile) return;
    auto dt = std::chrono::steady_clock::now() - t0;
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(dt).count();
    fprintf(stderr, "  prof %-32s %lld us\n", label, (long long)us);
  }
};

// Aggregating bucket. RAII, but rather than print on destruct it adds the
// elapsed microseconds to a process-global counter under `label`. Use
// `profile_dump()` to print all buckets and clear them. Cheap when
// g_profile is off (we still capture the timestamps but skip the map
// update — keep the code path identical to avoid measurement skew).
struct AggTimer {
  const char* label;
  std::chrono::steady_clock::time_point t0;
  AggTimer(const char* l) : label(l), t0(std::chrono::steady_clock::now()) {}
  ~AggTimer();
};

void profile_dump();

}  // namespace lv

// __LINE__ is itself a macro, so the obvious `_lv_ag_##__LINE__` would
// produce `_lv_ag___LINE__` literally — collisions on every call.
// Two-stage indirection forces expansion before pasting.
#define LV_CONCAT_INNER(a, b) a##b
#define LV_CONCAT(a, b)       LV_CONCAT_INNER(a, b)

#define LV_PROFILE_SCOPE(name) lv::ScopeTimer LV_CONCAT(_lv_ts_, __LINE__)(name)
#define LV_PROFILE_BLOCK(name) lv::AggTimer  LV_CONCAT(_lv_ag_, __LINE__)(name)
