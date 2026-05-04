#pragma once

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "cue.h"

extern "C" {
#include "lmdb.h"
}

struct ImGuiContext;  // forward decl so we can hold a Platform_SetClipboardTextFn pointer

// One per worker thread. Holds a per-shard sorted index of [task -> events].
// Workers scan disjoint ascending event-number ranges, so concatenating
// shards in worker-order yields a globally sorted list.
struct IndexShard {
  std::mutex mu;
  std::unordered_map<std::string, std::vector<uint64_t>> tasks;
  // `senders` is populated for %hear and %heer events — the peer ship
  // (sndr for ames/fine, name.her for mesa) extracted from the packet
  // header. Key is the @p text (e.g. "~bitpyx-dildus").
  std::unordered_map<std::string, std::vector<uint64_t>> senders;
  // `request_wires` maps the wire path of a %request event to the
  // event-num list. Used to back-reference the originating request when a
  // %cancel-request shows up later. Vectors are sorted ascending.
  std::unordered_map<std::string, std::vector<uint64_t>> request_wires;
  std::atomic<uint64_t> indexed{0};
  std::atomic<bool>     done{false};
};

class Viewer {
 public:
  Viewer();
  ~Viewer();

  bool open(const std::string& path, bool start_index = true);
  void close();
  void draw();

  // Probe / accessors used by the --probe CLI mode.
  void load_event(uint64_t eve);
  const std::string& time() const { return time_; }
  const std::string& wire() const { return wire_; }
  const std::string& task() const { return task_; }
  const std::string& data() const { return data_; }
  uint64_t            first_eve() const { return first_; }
  uint64_t            last_eve()  const { return last_;  }

  // Identity setter for probe mode (no UI).
  void set_identity(const std::string& seed_hex) {
    our_seed_hex_ = seed_hex;
  }

  // Block until every indexing shard reports done. Used by --bench to
  // make sure the per-task event lists are stable before stepping
  // through them.
  void wait_for_indexing();

  // Snapshot the indexed event-numbers for a task (e.g. "%heer"), in
  // ascending order. Empty if no shard has seen the task yet.
  std::vector<uint64_t> events_for_task(const std::string& name);

  // Test setter for --bench: enable fake-mode decryption with the given
  // ship name. Mirrors the UI checkbox + textbox path.
  void set_fake_ship(const std::string& patp_name) {
    fake_mode_      = true;
    fake_ship_name_ = patp_name;
  }

 private:
  void refresh_bounds();
  void start_indexing();
  void stop_indexing();
  void index_worker(size_t wi, uint64_t lo, uint64_t hi);

  std::string path_;
  std::string error_;

  MDB_env* env_ = nullptr;
  bool     open_ = false;

  uint64_t first_ = 0;
  uint64_t last_  = 0;
  int64_t  cur_   = 0;
  int64_t  prev_  = -1;
  bool     follow_tail_ = true;

  // Arenas for the foreground load_event / decode path.
  cue::Arena perm_;
  cue::Arena stack_;
  cue::Arena scratch_;

  // Reusable scratch buffer for cue::print_* into. Sized once at open()
  // and reused per event so we don't pay a 4 MiB malloc + free on every
  // arrow-key step. (Profiling showed those two operations dominated
  // load_event when stepping through %heer events.)
  std::vector<uint8_t> fmt_buf_;

  // formatted strings for the current event
  std::string time_;
  std::string wire_;
  std::string task_;
  std::string data_;

  uint32_t mug_ = 0;
  size_t   raw_size_ = 0;

  // Cache for word-wrapped `data_` rendering. Invalidated when the
  // source pointer/size or the wrap column count changes.
  std::string           wrap_buf_;
  std::vector<uint32_t> wrap_to_data_;  // wrap_buf index -> data_ index; UINT32_MAX = inserted
  int                   wrap_cols_     = 0;
  const char*           wrap_src_ptr_  = nullptr;
  size_t                wrap_src_size_ = 0;

  // Clipboard hook so Cmd-C produces the original (unwrapped) text.
  static Viewer*  clipboard_owner_;
  static void   (*saved_set_clipboard_)(ImGuiContext*, const char*);
  static void     clipboard_set_hook(ImGuiContext* ctx, const char* text);

  // ---- background indexing ------------------------------------------------
  std::vector<std::unique_ptr<IndexShard>> shards_;
  std::vector<std::thread>                 workers_;
  std::atomic<bool>                        stop_workers_{false};
  std::atomic<uint64_t>                    index_version_{0};

  // Decryption: only the user's own networking ring/seed is needed. Peer
  // pubkeys + lives come from the network-explorer API, looked up
  // asynchronously and cached by ship value. We *don't* fetch ourselves
  // — moons aren't in the API and the receiver's pubkey isn't part of
  // the X25519 derivation.
  std::string our_seed_hex_;
  int         our_life_ = 1;
  // Observed receiver patp from the first %hear we successfully parsed.
  // Every packet in our log has us as the rcvr, so we read it off the
  // wire instead of asking the user to type their ship name. Used by
  // chum-candidate logic in format_heer / fine to skip self lookups.
  // Written by index workers (under mutex) and by load_event in the
  // foreground; read in build_hear_keys.
  std::mutex  observed_mu_;
  std::string observed_our_ship_;

  // "Fake" mode — keys are deterministically derived from the ship atom
  // per +pit:nu:crub:crypto in vane/jael.hoon (the %fake boot path).
  // No network requests are made. Both our own seed and peer pubkeys come
  // from the patp directly.
  bool        fake_mode_      = false;
  std::string fake_ship_name_;       // e.g. "~zod"

  struct CachedNode {
    enum State { PENDING, OK, FAILED } state = PENDING;
    uint8_t     enc_key[32]{};
    int         life = 0;
    std::string error;
  };

  std::mutex                                         node_mu_;
  std::unordered_map<std::string, CachedNode>        node_cache_;  // key = atom-LSB ship bytes (stripped)
  std::queue<std::pair<std::string, std::string>>    fetch_q_;     // (cache-key, patp)
  std::condition_variable                            fetch_cv_;
  std::thread                                        fetch_thread_;
  std::atomic<bool>                                  fetch_stop_{false};
  std::atomic<uint64_t>                              node_version_{0};
  uint64_t                                           last_load_node_ver_ = 0;

  void start_fetcher();
  void stop_fetcher();
  void fetch_loop();

 public:
  // Block until all currently-queued node lookups have finished. Used by
  // the --probe CLI path so output reflects post-fetch state.
  void wait_for_pending_fetches();

  // Filter UI / cache
  int         filter_idx_           = -1;     // -1 = "(all)"
  std::string filter_name_;                   // selected task name
  // Cached merged event list for the active filter, rebuilt when index
  // advances. Lookups (slider, prev/next) use this.
  std::vector<uint64_t> filter_eves_;
  uint64_t              filter_built_at_     = (uint64_t)-1;
  std::string           filter_built_for_;

  // Sender-filter UI / cache (parallel to the task filter above).
  std::string           sender_filter_;        // empty = "(any)"
  std::vector<uint64_t> sender_filter_eves_;
  uint64_t              sender_filter_built_at_ = (uint64_t)-1;
  std::string           sender_filter_built_for_;

  // Intersection of task and sender filters when both are active. Sorted.
  std::vector<uint64_t> combined_filter_eves_;
};
