// ssh_scan.cpp  —  g++ -O2 -std=c++17 -pthread ssh_scan.cpp -o ssh_scan
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

#include <atomic>
#include <chrono>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static std::mutex       g_out_mutex;
static std::atomic<int> g_found_count{0};

static bool setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

// Non-blocking connect with timeout. Returns fd on success, -1 otherwise.
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
    return fd;   // left non-blocking
}

// Read a few bytes first; only send our hello if the server looks like SSH.
// Then read the rest of the banner line.
static std::string probeSsh(int fd, int timeout_ms) {
    std::string buf;
    char tmp[256];
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);

    bool hello_sent = false;

    while (std::chrono::steady_clock::now() < deadline) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) break;

        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        timeval tv{ (long)(remaining / 1000), (long)((remaining % 1000) * 1000) };
        int sel = select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if (sel < 0) { if (errno == EINTR) continue; break; }
        if (sel == 0) break;

        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        buf.append(tmp, (size_t)n);

        // Early reject: if first 4 bytes aren't "SSH-" it's not SSH.
        if (buf.size() >= 4 && buf.compare(0, 4, "SSH-") != 0) break;

        // Once we see "SSH-" prefix, send our identification (once only).
        if (!hello_sent && buf.size() >= 4) {
            const char* hello = "SSH-2.0-probe_1.0\r\n";
            (void)send(fd, hello, strlen(hello), MSG_NOSIGNAL);
            hello_sent = true;
        }

        auto nl = buf.find('\n');
        if (nl != std::string::npos) { buf.resize(nl); break; }
        if (buf.size() > 1024) break;   // safety
    }

    while (!buf.empty() && (buf.back() == '\r' || buf.back() == '\n'))
        buf.pop_back();
    return buf;
}

static void worker(const sockaddr_in& base,
                   std::atomic<int>& next_port,
                   int connect_ms, int banner_ms) {
    for (;;) {
        int port = next_port.fetch_add(1);
        if (port > 65535) return;

        sockaddr_in addr = base;
        addr.sin_port = htons((uint16_t)port);

        int fd = tryConnect(addr, connect_ms);
        if (fd < 0) continue;

        std::string banner = probeSsh(fd, banner_ms);
        close(fd);

        if (banner.rfind("SSH-", 0) == 0) {
            g_found_count.fetch_add(1);
            std::lock_guard<std::mutex> lk(g_out_mutex);
            std::cout << "[+] SSH on port " << port << "   -> " << banner << "\n"
                      << std::flush;
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0]
                  << " <host> [connect_ms=400] [banner_ms=400] [threads=256]\n";
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);

    std::string host = argv[1];

    // Validate and apply defaults for numeric args
    int connect_ms = (argc > 2 && std::atoi(argv[2]) > 0) ? std::atoi(argv[2]) : 400;
    int banner_ms  = (argc > 3 && std::atoi(argv[3]) > 0) ? std::atoi(argv[3]) : 400;
    int nthreads   = (argc > 4 && std::atoi(argv[4]) > 0) ? std::atoi(argv[4]) : 256;

    // Check fd limit and warn if too low
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rlim_t needed = (rlim_t)(nthreads + 32);
        if (rl.rlim_cur < needed) {
            std::cerr << "[!] Warning: fd limit (" << rl.rlim_cur
                      << ") may be too low for " << nthreads
                      << " threads. Consider: ulimit -n 4096\n";
            // Attempt to raise it
            rl.rlim_cur = needed < rl.rlim_max ? needed : rl.rlim_max;
            setrlimit(RLIMIT_NOFILE, &rl);
        }
    }

    // Resolve host
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
        std::cerr << "Failed to resolve " << host << "\n";
        return 1;
    }
    sockaddr_in base;
    std::memcpy(&base, res->ai_addr, sizeof(sockaddr_in));
    freeaddrinfo(res);
    base.sin_port = 0;

    // Use inet_ntop instead of deprecated inet_ntoa
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &base.sin_addr, ip_str, sizeof(ip_str));

    std::cout << "Scanning " << host << " (" << ip_str
              << ") on all 65535 ports with " << nthreads << " threads...\n"
              << std::flush;

    std::atomic<int> next_port{1};
    auto t0 = std::chrono::steady_clock::now();

    std::vector<std::thread> pool;
    pool.reserve(nthreads);
    for (int i = 0; i < nthreads; ++i)
        pool.emplace_back(worker, std::cref(base),
                          std::ref(next_port), connect_ms, banner_ms);
    for (auto& t : pool) t.join();

    auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    // Print count only — ports already printed above as found
    std::cout << "\nDone in " << dt << " ms. "
              << g_found_count.load() << " SSH port(s) found,\n";
    return 0;
}
