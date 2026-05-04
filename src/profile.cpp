#include "profile.h"

#include <stdio.h>

#include <algorithm>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace lv {

bool g_profile = false;

namespace {

struct Bucket {
  uint64_t total_us = 0;
  uint64_t calls    = 0;
};

std::mutex                        g_mu;
std::unordered_map<std::string, Bucket> g_buckets;

}  // namespace

AggTimer::~AggTimer() {
  if (!g_profile) return;
  auto dt = std::chrono::steady_clock::now() - t0;
  auto us = std::chrono::duration_cast<std::chrono::microseconds>(dt).count();
  std::lock_guard<std::mutex> g(g_mu);
  auto& b = g_buckets[label];
  b.total_us += (uint64_t)us;
  b.calls    += 1;
}

void profile_dump() {
  std::lock_guard<std::mutex> g(g_mu);
  if (g_buckets.empty()) {
    fprintf(stderr, "profile: no buckets recorded\n");
    return;
  }
  // Sort by total time descending.
  std::vector<std::pair<std::string, Bucket>> rows(g_buckets.begin(),
                                                   g_buckets.end());
  std::sort(rows.begin(), rows.end(),
            [](const auto& a, const auto& b) {
              return a.second.total_us > b.second.total_us;
            });
  fprintf(stderr, "profile buckets (sorted by total):\n");
  fprintf(stderr, "  %-32s %12s %12s %10s\n",
          "label", "total us", "calls", "avg us");
  for (const auto& kv : rows) {
    double avg = kv.second.calls
        ? (double)kv.second.total_us / (double)kv.second.calls
        : 0.0;
    fprintf(stderr, "  %-32s %12llu %12llu %10.1f\n",
            kv.first.c_str(),
            (unsigned long long)kv.second.total_us,
            (unsigned long long)kv.second.calls,
            avg);
  }
  g_buckets.clear();
}

}  // namespace lv
