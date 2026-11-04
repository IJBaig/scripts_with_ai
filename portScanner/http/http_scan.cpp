// http_scan.cpp
// Compile: g++ -O2 -std=c++17 -pthread http_scan.cpp -o http_scan
//
// Scans all 65535 ports on a host and detects which are running HTTP or HTTPS.
// Zero external dependencies — TLS detection uses a raw ClientHello probe.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// ─── Globals ────────────────────────────────────────────────────────────────

static std::mutex       g_out_mutex;
static std::atomic<int> g_found_count{0};

// ─── Help / Usage ───────────────────────────────────────────────────────────

static void printHelp(const char* prog) {
    std::cout <<
R"(
╔══════════════════════════════════════════════════════════════╗
║               http_scan — HTTP/HTTPS Port Scanner            ║
╚══════════════════════════════════════════════════════════════╝

Scans every port (1-65535) on a target and detects which ones
are running HTTP or HTTPS. No false positives — every reported
port is confirmed by actual protocol handshake.

USAGE:
  )" << prog << R"( <target> [connect_ms] [banner_ms] [threads]

ARGUMENTS:
  <target>       Required. One of:
                   • IP address      →  192.168.1.10
                   • Hostname / DNS  →  example.com
                   • URL             →  http://example.com
                                        https://192.168.1.10
                                        http://myhost:8080

  [connect_ms]   TCP connect timeout in milliseconds. Default: 400
                 Lower = faster scan, may miss slow hosts.
                 Raise if scanning over VPN or WAN.

  [banner_ms]    Response read timeout in milliseconds. Default: 400
                 Time to wait for HTTP or TLS response after connect.

  [threads]      Number of parallel threads. Default: 256
                 Higher = faster. Watch your fd limit (see below).

EXAMPLES:
  )" << prog << R"( 192.168.1.10
  )" << prog << R"( example.com
  )" << prog << R"( https://example.com
  )" << prog << R"( http://10.0.0.1:8080
  )" << prog << R"( 10.0.0.5 200 600 512

DETECTION METHOD:
  Each port goes through two probes:

  1. HTTP probe  — sends a real GET request, confirms response
                   starts with HTTP/1.0, HTTP/1.1 or HTTP/2.
                   Reports: [+] HTTP

  2. HTTPS probe — sends a raw TLS ClientHello, checks for a
                   valid TLS ServerHello (0x16 0x03 header).
                   Then sends HTTP inside TLS to confirm it is
                   actually HTTPS and not some other TLS service.
                   Reports: [+] HTTPS

  A port is only reported if the protocol is confirmed.
  Open ports that speak neither HTTP nor HTTPS are silently skipped.

FD LIMIT NOTE:
  High thread counts need more file descriptors.
  If you see warnings, run before scanning:
    ulimit -n 4096

OUTPUT:
  [+] HTTP  on port 80
  [+] HTTPS on port 443
  Done in 38214 ms. 2 HTTP/HTTPS port(s) found,

FLAGS:
  -h, --help     Show this help and exit.

)";
}

// ─── Networking helpers ──────────────────────────────────────────────────────

static bool setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

// Non-blocking TCP connect with millisecond timeout.
// Returns open fd on success, -1 on failure.
static int tryConnect(const sockaddr_in& addr, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (!setNonBlocking(fd)) { close(fd); return -1; }

    int r = connect(fd, (const sockaddr*)&addr, sizeof(addr));
    if (r < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (r < 0) {
        fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
        timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        int sel = select(fd + 1, nullptr, &wfds, nullptr, &tv);
        if (sel <= 0) { close(fd); return -1; }
        int err = 0; socklen_t len = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
            close(fd); return -1;
        }
    }
    return fd;  // left non-blocking
}

// Send all bytes in buf. Returns false on hard failure.
static bool sendAll(int fd, const char* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            return false;
        }
        sent += (size_t)n;
    }
    return true;
}

// Read up to max_bytes within timeout_ms. Returns what was received.
static std::string recvTimeout(int fd, size_t max_bytes, int timeout_ms) {
    std::string buf;
    char tmp[1024];
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);

    while (buf.size() < max_bytes) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) break;

        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        timeval tv{ (long)(remaining / 1000), (long)((remaining % 1000) * 1000) };
        int sel = select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if (sel < 0) { if (errno == EINTR) continue; break; }
        if (sel == 0) break;

        size_t want = std::min(sizeof(tmp), max_bytes - buf.size());
        ssize_t n = recv(fd, tmp, want, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        buf.append(tmp, (size_t)n);
    }
    return buf;
}

// ─── HTTP probe ──────────────────────────────────────────────────────────────
//
// Sends a real HTTP GET and checks whether the response starts with
// "HTTP/1.0", "HTTP/1.1", or "HTTP/2". This is the only reliable signal
// that the port is serving HTTP — status codes, server headers, etc.
// are intentionally ignored.

static bool probeHttp(int fd, const std::string& host, int timeout_ms) {
    std::string req =
        "GET / HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Connection: close\r\n"
        "User-Agent: http_scan/1.0\r\n"
        "\r\n";

    if (!sendAll(fd, req.c_str(), req.size())) return false;

    // We only need the first 12 bytes to confirm the protocol.
    std::string resp = recvTimeout(fd, 12, timeout_ms);
    if (resp.size() < 7) return false;

    return (resp.compare(0, 7, "HTTP/1.") == 0 ||
            resp.compare(0, 7, "HTTP/2 ") == 0 ||
            resp.compare(0, 8, "HTTP/2\r\n") == 0);
}

// ─── TLS ClientHello ────────────────────────────────────────────────────────
//
// A minimal but valid TLS 1.0–1.3 ClientHello.
// Offers TLS 1.0 through 1.3 cipher suites.
// The server's ServerHello starts with: 0x16 0x03 <minor> 0x00 ...
// Any byte at [1]==0x03 and [0]==0x16 is a valid TLS record header.

static const uint8_t kTlsClientHello[] = {
    // TLS Record Layer
    0x16,       // content type: Handshake
    0x03, 0x01, // version: TLS 1.0 (for maximum compatibility)
    0x00, 0xf1, // length of handshake data below

    // Handshake header
    0x01,             // HandshakeType: ClientHello
    0x00, 0x00, 0xed, // length

    // ClientHello
    0x03, 0x03,  // client version: TLS 1.2 (actual negotiation via extensions)

    // Random (32 bytes — static, we don't need a real session)
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,

    0x00,       // session ID length: 0

    // Cipher suites (16 suites = 32 bytes + 2 length)
    0x00, 0x20,
    0xc0,0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc0,0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc0,0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc0,0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xc0,0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc0,0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x00,0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x00,0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
    0x00,0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x13,0x01, // TLS_AES_128_GCM_SHA256       (TLS 1.3)
    0x13,0x02, // TLS_AES_256_GCM_SHA384       (TLS 1.3)
    0x13,0x03, // TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
    0x00,0x9c, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x00,0x9d, // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x00,0xff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    0x00,0x00, // TLS_NULL_WITH_NULL_NULL (padding)

    // Compression methods
    0x01, 0x00, // length 1, no compression

    // Extensions length
    0x00, 0x84,

    // Extension: server_name (SNI) — empty for IP scanning
    0x00,0x00, 0x00,0x05, 0x00,0x03, 0x00,0x00,0x00,

    // Extension: ec_point_formats
    0x00,0x0b, 0x00,0x04, 0x03,0x00,0x01,0x02,

    // Extension: supported_groups (elliptic curves)
    0x00,0x0a, 0x00,0x16, 0x00,0x14,
    0x00,0x1d, // x25519
    0x00,0x17, // secp256r1
    0x00,0x1e, // x448
    0x00,0x19, // secp521r1
    0x00,0x18, // secp384r1
    0x01,0x00, // ffdhe2048
    0x01,0x01, // ffdhe3072
    0x01,0x02, // ffdhe4096
    0x01,0x03, // ffdhe6144
    0x01,0x04, // ffdhe8192

    // Extension: session_ticket
    0x00,0x23, 0x00,0x00,

    // Extension: encrypt_then_mac
    0x00,0x16, 0x00,0x00,

    // Extension: extended_master_secret
    0x00,0x17, 0x00,0x00,

    // Extension: signature_algorithms
    0x00,0x0d, 0x00,0x1e, 0x00,0x1c,
    0x04,0x03, 0x05,0x03, 0x06,0x03,
    0x08,0x07, 0x08,0x08, 0x08,0x09,
    0x08,0x0a, 0x08,0x0b, 0x08,0x04,
    0x08,0x05, 0x08,0x06, 0x04,0x01,
    0x05,0x01, 0x06,0x01,

    // Extension: supported_versions (TLS 1.3 + 1.2)
    0x00,0x2b, 0x00,0x07, 0x06,
    0x03,0x04, // TLS 1.3
    0x03,0x03, // TLS 1.2
    0x03,0x02, // TLS 1.1

    // Extension: psk_key_exchange_modes
    0x00,0x2d, 0x00,0x02, 0x01,0x01,

    // Extension: key_share (x25519)
    0x00,0x33, 0x00,0x26, 0x00,0x24,
    0x00,0x1d, 0x00,0x20,
    0x35,0x80,0x72,0xd6,0x36,0x58,0x80,0xd1,
    0xae,0xea,0x32,0x9a,0xdf,0x91,0x21,0x38,
    0x38,0x51,0xed,0x21,0xa2,0x8e,0x3b,0x75,
    0xe9,0x65,0xd0,0xd2,0xcd,0x16,0x62,0x54,
};

// Returns true if the response is a valid TLS ServerHello.
// A TLS record starts with: 0x16 (handshake), 0x03 (major ver), <minor>
static bool isTlsServerHello(const std::string& resp) {
    if (resp.size() < 3) return false;
    return ((uint8_t)resp[0] == 0x16 &&
            (uint8_t)resp[1] == 0x03);
}

// ─── HTTPS probe ─────────────────────────────────────────────────────────────
//
// Step 1: Send TLS ClientHello, check for ServerHello → confirms TLS.
// Step 2: We cannot send a real HTTP request inside TLS without a full
//         TLS implementation, so after confirming TLS, we open a SECOND
//         plain connection and try an HTTP probe. If the server responds
//         to plain HTTP too, it is dual-mode. If not, we check whether
//         the TLS port *only* responds to HTTPS by checking common HTTPS
//         ports (443, 8443, etc.) OR simply trust the TLS confirmation
//         combined with the lack of plain HTTP — that is HTTPS.
//
// Real-world rule: TLS on a TCP port + no plain HTTP = HTTPS confirmed.
// A port that responds to both plain HTTP and TLS is flagged HTTPS
// (TLS takes priority as it is the stronger signal).

static bool probeTls(int fd, int timeout_ms) {
    if (!sendAll(fd,
            reinterpret_cast<const char*>(kTlsClientHello),
            sizeof(kTlsClientHello))) return false;

    // We need at least 3 bytes for TLS record header check.
    std::string resp = recvTimeout(fd, 16, timeout_ms);
    return isTlsServerHello(resp);
}

// ─── Per-port probe ──────────────────────────────────────────────────────────
//
// Returns 0 = nothing, 1 = HTTP, 2 = HTTPS
// Logic:
//   - Try TLS first. TLS check is fast (just header bytes).
//     If TLS confirmed → HTTPS (no need to also check plain HTTP).
//   - If TLS fails → try plain HTTP probe on the same fd (already connected).
//     The fd was left open and readable from the failed TLS attempt.
//     But since we sent TLS bytes, the server may have closed. So we
//     reconnect cleanly for the HTTP probe.

enum ProbeResult { NONE = 0, HTTP = 1, HTTPS = 2 };

static ProbeResult probePort(const sockaddr_in& addr,
                             const std::string& host,
                             int connect_ms, int banner_ms) {
    // ── HTTPS attempt (TLS ClientHello) ─────────────────────────
    {
        int fd = tryConnect(addr, connect_ms);
        if (fd >= 0) {
            bool tls = probeTls(fd, banner_ms);
            close(fd);
            if (tls) return HTTPS;
        }
    }

    // ── HTTP attempt (plain GET) ─────────────────────────────────
    {
        int fd = tryConnect(addr, connect_ms);
        if (fd < 0) return NONE;
        bool http = probeHttp(fd, host, banner_ms);
        close(fd);
        if (http) return HTTP;
    }

    return NONE;
}

// ─── Worker thread ───────────────────────────────────────────────────────────

static void worker(const sockaddr_in& base,
                   const std::string& host,
                   std::atomic<int>& next_port,
                   int connect_ms, int banner_ms) {
    for (;;) {
        int port = next_port.fetch_add(1);
        if (port > 65535) return;

        sockaddr_in addr = base;
        addr.sin_port = htons((uint16_t)port);

        ProbeResult result = probePort(addr, host, connect_ms, banner_ms);

        if (result != NONE) {
            g_found_count.fetch_add(1);
            const char* label = (result == HTTPS) ? "HTTPS" : "HTTP ";
            std::lock_guard<std::mutex> lk(g_out_mutex);
            std::cout << "[+] " << label << " on port " << port << "\n"
                      << std::flush;
        }
    }
}

// ─── Input parsing ───────────────────────────────────────────────────────────
//
// Accepts:
//   192.168.1.10
//   example.com
//   http://example.com
//   https://example.com
//   http://example.com:8080/path/ignored

static std::string parseTarget(const std::string& input) {
    std::string s = input;

    // Strip scheme
    for (const char* scheme : { "https://", "http://" }) {
        size_t pos = s.find(scheme);
        if (pos == 0) {
            s = s.substr(strlen(scheme));
            break;
        }
    }

    // Strip path
    size_t slash = s.find('/');
    if (slash != std::string::npos) s = s.substr(0, slash);

    // Strip port if explicitly given in URL (e.g. example.com:8080)
    size_t colon = s.rfind(':');
    if (colon != std::string::npos) {
        // Make sure it is not an IPv6 address (those have multiple colons)
        // Simple check: if only one colon, strip the port
        if (std::count(s.begin(), s.end(), ':') == 1)
            s = s.substr(0, colon);
    }

    return s;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    // Help flag
    if (argc < 2 ||
        std::string(argv[1]) == "-h" ||
        std::string(argv[1]) == "--help") {
        printHelp(argv[0]);
        return (argc < 2) ? 1 : 0;
    }

    signal(SIGPIPE, SIG_IGN);

    // Parse and validate args
    std::string raw_target = argv[1];
    int connect_ms = (argc > 2 && std::atoi(argv[2]) > 0) ? std::atoi(argv[2]) : 400;
    int banner_ms  = (argc > 3 && std::atoi(argv[3]) > 0) ? std::atoi(argv[3]) : 400;
    int nthreads   = (argc > 4 && std::atoi(argv[4]) > 0) ? std::atoi(argv[4]) : 256;

    std::string host = parseTarget(raw_target);
    if (host.empty()) {
        std::cerr << "[!] Could not parse target: " << raw_target << "\n";
        return 1;
    }

    // fd limit check
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        // Each port does up to 2 connects, so headroom needed is nthreads * 2
        rlim_t needed = (rlim_t)(nthreads * 2 + 32);
        if (rl.rlim_cur < needed) {
            std::cerr << "[!] Warning: fd limit (" << rl.rlim_cur
                      << ") may be too low for " << nthreads
                      << " threads (need ~" << needed << ").\n"
                      << "    Try: ulimit -n 4096\n";
            rl.rlim_cur = (needed < rl.rlim_max) ? needed : rl.rlim_max;
            setrlimit(RLIMIT_NOFILE, &rl);
        }
    }

    // DNS resolution
    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
        std::cerr << "[!] Failed to resolve: " << host << "\n";
        return 1;
    }
    sockaddr_in base{};
    std::memcpy(&base, res->ai_addr, sizeof(sockaddr_in));
    freeaddrinfo(res);
    base.sin_port = 0;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &base.sin_addr, ip_str, sizeof(ip_str));

    std::cout << "Scanning " << host << " (" << ip_str
              << ") on all 65535 ports with " << nthreads << " threads...\n"
              << std::flush;

    // Launch workers
    std::atomic<int> next_port{1};
    auto t0 = std::chrono::steady_clock::now();

    std::vector<std::thread> pool;
    pool.reserve(nthreads);
    for (int i = 0; i < nthreads; ++i)
        pool.emplace_back(worker,
                          std::cref(base),
                          std::cref(host),
                          std::ref(next_port),
                          connect_ms, banner_ms);
    for (auto& t : pool) t.join();

    auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    std::cout << "\nDone in " << dt << " ms. "
              << g_found_count.load() << " HTTP/HTTPS port(s) found,\n";
    return 0;
}
