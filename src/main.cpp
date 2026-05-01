// Shared entry point. Routes --test / --pubkey / --probe to the CLI
// handlers in cli.cpp; everything else hands off to run_gui(), which has
// a per-platform implementation (Cocoa+Metal on macOS, Win32+DX11 on
// Windows).

#include <stdio.h>
#include <string.h>

#include "cli.h"

int main(int argc, const char* argv[]) {
  if (argc > 1 && strcmp(argv[1], "--test")   == 0) return cli::run_crypto_test();
  if (argc > 1 && strcmp(argv[1], "--pubkey") == 0) return cli::run_pubkey(argc, argv);
  if (argc > 1 && strcmp(argv[1], "--probe")  == 0) return cli::run_probe(argc, argv);

  const char* initial_path = (argc > 1) ? argv[1] : nullptr;
  return run_gui(initial_path);
}
