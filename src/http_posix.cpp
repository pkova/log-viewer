// POSIX HTTPS client (macOS / Linux / *BSD).
//
// Adapted from the aas-sign project's platform layer. mbedTLS handles the
// TLS handshake and record layer over a plain BSD socket via mbedtls_net_*.
// CA verification reads a PEM bundle off disk — we probe the well-known
// distro paths and fall back to $SSL_CERT_FILE.
//
// One TlsConnection per request: the higher layer runs on a dedicated
// fetcher thread and never reuses the channel, so the simpler RAII
// open-write-read-close shape is plenty. No keep-alive, no parallel
// requests, no chunked-write streaming.

#include "http.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <sstream>
#include <stdexcept>

extern "C" {
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
}

namespace http {

namespace {

bool        g_tls_insecure = false;
std::string g_ca_bundle_override;

std::string mbed_error(int ret) {
  char buf[256];
  mbedtls_strerror(ret, buf, sizeof(buf));
  return buf;
}

// Probe the well-known absolute paths every major distro family uses.
// All are PEM bundles (concatenated certs) — the format
// mbedtls_x509_crt_parse_file accepts directly.
std::string find_ca_bundle() {
  if (!g_ca_bundle_override.empty()) return g_ca_bundle_override;
  if (const char* p = std::getenv("SSL_CERT_FILE"); p && *p) {
    struct stat st;
    if (::stat(p, &st) == 0) return p;
  }
  static const char* paths[] = {
      "/etc/ssl/certs/ca-certificates.crt",      // Debian/Ubuntu/Arch
      "/etc/pki/tls/certs/ca-bundle.crt",        // RHEL/CentOS/Fedora
      "/etc/ssl/ca-bundle.pem",                  // OpenSUSE
      "/etc/ssl/cert.pem",                       // Alpine/FreeBSD/macOS
      "/etc/pki/tls/cacert.pem",
      "/usr/local/share/certs/ca-root-nss.crt",  // FreeBSD ports
      "/usr/local/etc/openssl@3/cert.pem",       // Homebrew Intel
      "/opt/homebrew/etc/openssl@3/cert.pem",    // Homebrew Apple Silicon
  };
  for (const char* p : paths) {
    struct stat st;
    if (::stat(p, &st) == 0) return p;
  }
  return "";
}

struct TlsConnection {
  mbedtls_net_context      server_fd;
  mbedtls_entropy_context  entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context      ssl;
  mbedtls_ssl_config       conf;
  mbedtls_x509_crt         cacert;

  TlsConnection(const std::string& host, const std::string& port) {
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&cacert);

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                    &entropy, nullptr, 0);
    if (ret != 0)
      throw std::runtime_error("ctr_drbg_seed: " + mbed_error(ret));

    ret = mbedtls_net_connect(&server_fd, host.c_str(), port.c_str(),
                              MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
      throw std::runtime_error("connect " + host + ":" + port + ": " +
                               mbed_error(ret));

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
      throw std::runtime_error("ssl_config_defaults: " + mbed_error(ret));

    if (g_tls_insecure) {
      mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    } else {
      std::string bundle = find_ca_bundle();
      if (bundle.empty())
        throw std::runtime_error(
            "no CA bundle found at any standard path; set SSL_CERT_FILE "
            "or call http::tls_disable_verification()");
      // mbedtls returns the count of certs that failed to parse on
      // success — negative is a hard error.
      ret = mbedtls_x509_crt_parse_file(&cacert, bundle.c_str());
      if (ret < 0)
        throw std::runtime_error("parse CA bundle " + bundle + ": " +
                                 mbed_error(ret));
      mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
      mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) throw std::runtime_error("ssl_setup: " + mbed_error(ret));

    ret = mbedtls_ssl_set_hostname(&ssl, host.c_str());
    if (ret != 0)
      throw std::runtime_error("ssl_set_hostname: " + mbed_error(ret));

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send,
                        mbedtls_net_recv, nullptr);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
          ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        throw std::runtime_error("TLS handshake " + host + ": " +
                                 mbed_error(ret));
    }
  }

  ~TlsConnection() {
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&cacert);
  }

  void write_all(const std::string& data) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data.data());
    size_t remaining = data.size();
    while (remaining > 0) {
      int ret = mbedtls_ssl_write(&ssl, p, remaining);
      if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        throw std::runtime_error("ssl_write: " + mbed_error(ret));
      }
      p += ret;
      remaining -= (size_t)ret;
    }
  }

  std::string read_all() {
    std::string out;
    uint8_t buf[4096];
    for (;;) {
      int ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
      if (ret == MBEDTLS_ERR_SSL_WANT_READ) continue;
      if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) break;
      if (ret < 0) throw std::runtime_error("ssl_read: " + mbed_error(ret));
      out.append(reinterpret_cast<char*>(buf), (size_t)ret);
    }
    return out;
  }
};

// Decode a raw HTTP/1.1 response: status line + headers + body, with
// chunked transfer-encoding handled inline. Connection: close on the
// request side keeps this simple — no Content-Length / pipelining games.
bool parse_http_response(const std::string& raw, Response* out) {
  size_t line_end = raw.find("\r\n");
  if (line_end == std::string::npos) {
    out->error = "malformed HTTP response (no status line)";
    return false;
  }
  size_t sp1 = raw.find(' ');
  if (sp1 == std::string::npos || sp1 + 4 > raw.size()) {
    out->error = "malformed HTTP status line";
    return false;
  }
  out->status = atoi(raw.c_str() + sp1 + 1);

  size_t body_start = raw.find("\r\n\r\n");
  if (body_start == std::string::npos) {
    out->error = "no header/body separator";
    return false;
  }
  std::string headers = raw.substr(0, body_start);
  out->body = raw.substr(body_start + 4);

  // Case-insensitive search for chunked TE.
  bool chunked = false;
  for (size_t i = 0; i + 17 <= headers.size(); i++) {
    if (strncasecmp(headers.c_str() + i, "transfer-encoding", 17) == 0) {
      // Look for "chunked" on the rest of the line.
      size_t eol = headers.find("\r\n", i);
      if (eol == std::string::npos) eol = headers.size();
      std::string line = headers.substr(i, eol - i);
      for (size_t j = 0; j + 7 <= line.size(); j++) {
        if (strncasecmp(line.c_str() + j, "chunked", 7) == 0) {
          chunked = true; break;
        }
      }
      break;
    }
  }
  if (chunked) {
    std::string decoded;
    const std::string& src = out->body;
    size_t pos = 0;
    while (pos < src.size()) {
      size_t nl = src.find("\r\n", pos);
      if (nl == std::string::npos) break;
      size_t chunk_len = (size_t)strtoul(src.c_str() + pos, nullptr, 16);
      if (chunk_len == 0) break;
      pos = nl + 2;
      if (pos + chunk_len > src.size()) break;
      decoded.append(src, pos, chunk_len);
      pos += chunk_len + 2;          // skip trailing \r\n
    }
    out->body = std::move(decoded);
  }
  return true;
}

}  // namespace

void tls_disable_verification() { g_tls_insecure = true; }

Response https_get(const std::string& host, const std::string& path) {
  Response r;
  try {
    TlsConnection conn(host, "443");
    std::ostringstream req;
    req << "GET " << path << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "User-Agent: log-viewer/0.1\r\n"
        << "Accept: */*\r\n"
        << "Connection: close\r\n\r\n";
    conn.write_all(req.str());
    std::string raw = conn.read_all();
    if (!parse_http_response(raw, &r)) return r;
    r.ok = (r.status >= 200 && r.status < 300);
    if (!r.ok && r.error.empty()) r.error = "HTTP " + std::to_string(r.status);
    return r;
  } catch (const std::exception& e) {
    r.error = e.what();
    return r;
  }
}

}  // namespace http
