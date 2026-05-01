#pragma once

// CLI subcommand entry points shared between the macOS and Windows
// frontends. Each is a self-contained "main"-style function returning
// a process exit code.

namespace cli {

int run_probe(int argc, const char* argv[]);
int run_crypto_test();
int run_pubkey(int argc, const char* argv[]);

}  // namespace cli

// Implemented per-platform (gui_macos.mm, gui_win32.cpp). Spins up the
// native window, runs the message loop until the user closes it, and
// returns a process exit code.
int run_gui(const char* initial_path);
