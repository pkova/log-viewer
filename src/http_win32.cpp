// Windows HTTPS client via WinHTTP.
//
// Mirrors the public surface declared in http.h. We deliberately use the
// system stack here rather than the FetchContent'd mbedTLS — Windows ships
// WinHTTP, it speaks HTTPS over the system cert store, and it's the
// idiomatic call path. UTF-8 strings on the wire get widened to UTF-16 for
// the W-suffixed entry points; response headers come back as numbers, body
// as raw bytes.

#include "http.h"

#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>

#include <sstream>
#include <string>
#include <vector>

namespace http {

namespace {

bool g_tls_insecure = false;

std::wstring widen(const std::string& s) {
  if (s.empty()) return L"";
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                              nullptr, 0);
  std::wstring out((size_t)n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
  return out;
}

std::string narrow(const wchar_t* p, size_t n) {
  if (n == 0) return "";
  int wn = WideCharToMultiByte(CP_UTF8, 0, p, (int)n, nullptr, 0,
                               nullptr, nullptr);
  std::string out((size_t)wn, '\0');
  WideCharToMultiByte(CP_UTF8, 0, p, (int)n, out.data(), wn, nullptr, nullptr);
  return out;
}

std::string win_error(DWORD err) {
  // First try the normal Win32 message table.
  wchar_t* buf = nullptr;
  DWORD flags  = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                 FORMAT_MESSAGE_FROM_SYSTEM     |
                 FORMAT_MESSAGE_IGNORE_INSERTS;
  DWORD n = FormatMessageW(flags, nullptr, err,
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                           (LPWSTR)&buf, 0, nullptr);
  // WinHTTP errors (12000–12175) live in winhttp.dll's message table.
  if (n == 0 && err >= 12000 && err <= 12175) {
    HMODULE m = LoadLibraryW(L"winhttp.dll");
    if (m) {
      n = FormatMessageW(flags | FORMAT_MESSAGE_FROM_HMODULE, m, err,
                         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                         (LPWSTR)&buf, 0, nullptr);
      FreeLibrary(m);
    }
  }
  std::string out;
  if (n > 0 && buf) {
    while (n > 0 && (buf[n - 1] == L'\r' || buf[n - 1] == L'\n' ||
                     buf[n - 1] == L' ')) n--;
    out = narrow(buf, n);
  } else {
    std::ostringstream os;
    os << "win32 error " << err;
    out = os.str();
  }
  if (buf) LocalFree(buf);
  return out;
}

struct Handle {
  HINTERNET h = nullptr;
  Handle()                              = default;
  Handle(const Handle&)                 = delete;
  Handle& operator=(const Handle&)      = delete;
  Handle(HINTERNET p) : h(p)            {}
  ~Handle() { if (h) WinHttpCloseHandle(h); }
  operator HINTERNET() const            { return h; }
};

}  // namespace

void tls_disable_verification() { g_tls_insecure = true; }

Response https_get(const std::string& host, const std::string& path) {
  Response r;
  std::wstring whost = widen(host);
  std::wstring wpath = widen(path);

  Handle session = WinHttpOpen(L"log-viewer/0.1",
                               WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME,
                               WINHTTP_NO_PROXY_BYPASS, 0);
  if (!session) { r.error = "WinHttpOpen: " + win_error(GetLastError()); return r; }

  Handle conn = WinHttpConnect(session, whost.c_str(),
                               INTERNET_DEFAULT_HTTPS_PORT, 0);
  if (!conn) { r.error = "WinHttpConnect: " + win_error(GetLastError()); return r; }

  Handle req = WinHttpOpenRequest(conn, L"GET", wpath.c_str(), nullptr,
                                  WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
  if (!req) { r.error = "WinHttpOpenRequest: " + win_error(GetLastError()); return r; }

  if (g_tls_insecure) {
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA       |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID  |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID|
                  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
  }

  if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
    r.error = "WinHttpSendRequest: " + win_error(GetLastError());
    return r;
  }
  if (!WinHttpReceiveResponse(req, nullptr)) {
    r.error = "WinHttpReceiveResponse: " + win_error(GetLastError());
    return r;
  }

  DWORD status = 0;
  DWORD status_size = sizeof(status);
  if (!WinHttpQueryHeaders(req,
                           WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX,
                           &status, &status_size, WINHTTP_NO_HEADER_INDEX)) {
    r.error = "WinHttpQueryHeaders: " + win_error(GetLastError());
    return r;
  }
  r.status = (int)status;

  // WinHttpQueryDataAvailable returns the bytes available in the next
  // response chunk; loop until it reports zero. WinHTTP transparently
  // decodes Transfer-Encoding: chunked for us.
  DWORD available = 0;
  while (WinHttpQueryDataAvailable(req, &available) && available != 0) {
    std::vector<char> buf(available);
    DWORD got = 0;
    if (!WinHttpReadData(req, buf.data(), available, &got)) {
      r.error = "WinHttpReadData: " + win_error(GetLastError());
      return r;
    }
    r.body.append(buf.data(), got);
    if (got == 0) break;
  }

  r.ok = (r.status >= 200 && r.status < 300);
  if (!r.ok) r.error = "HTTP " + std::to_string(r.status);
  return r;
}

}  // namespace http
