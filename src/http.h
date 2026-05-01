#pragma once

// Minimal portable HTTPS client.
//
// Today there is one implementation: src/http_posix.cpp, which speaks TLS
// via mbedTLS over BSD sockets and the system CA bundle. macOS, Linux and
// FreeBSD all build against this file. A future Windows implementation
// (WinHTTP) lives behind the same `namespace http` so callers are
// platform-blind.
//
// The interface is intentionally small: synchronous GET, no follow-redirect,
// no streaming. Callers (worker threads in the viewer) get a status code and
// a buffered body, and parse the body themselves — JSON parsing is not in
// scope.

#include <stdint.h>
#include <string>

namespace http {

struct Response {
  int         status = 0;   // HTTP status code (0 if the request failed)
  std::string body;
  std::string error;        // populated when ok=false
  bool        ok = false;
};

// Synchronous HTTPS GET. `host` is "example.com" (no scheme/port). `path`
// includes leading "/" and any query string. Returns Response with
// `ok=true` on a successful round-trip; on connect/handshake/HTTP-shape
// failure, `ok=false` and `error` carries a one-line description.
Response https_get(const std::string& host, const std::string& path);

// Disable certificate verification for all subsequent calls. Intended for
// development against self-signed endpoints. Not thread-safe; call once
// at startup.
void tls_disable_verification();

}  // namespace http
