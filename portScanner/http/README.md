# HTTP/HTTPS Scanner
## in testing
A multithreaded TCP scanner written in C++ that scans all 65,535 ports on a target host and identifies services responding to HTTP or TLS probes.

## Features

- Scans all TCP ports from 1 to 65535.
- Uses multithreading for faster scanning.
- Supports non-blocking TCP connections.
- Supports configurable connection timeout.
- Supports configurable response timeout.
- Detects HTTP services using HTTP GET requests.
- Detects TLS services using a raw TLS ClientHello.
- Supports HTTP and HTTPS URL input.
- Accepts IP addresses, hostnames, and URLs.
- Removes URL schemes, paths, and explicitly supplied ports when parsing targets.
- Resolves domain names to IPv4 addresses.
- Checks the file descriptor limit.
- Attempts to increase the file descriptor limit when needed.
- Uses thread-safe output.
- Displays the number of detected services and scan duration.
- Does not require external libraries.

## Requirements

- Linux
- GCC/G++ compiler
- C++17 support
- POSIX threads

## Compilation

Compile the source code:

```bash
g++ -O2 -std=c++17 -pthread http_scan.cpp -o http_scan
```

## Usage

```bash
./http_scan <target> [connect_ms] [banner_ms] [threads]
```

### Arguments

| Argument | Description | Default |
|---|---|---|
| target | IP address, hostname, or URL | Required |
| connect_ms | TCP connection timeout in milliseconds | 400 |
| banner_ms | HTTP/TLS response timeout in milliseconds | 400 |
| threads | Number of scanning threads | 256 |

All optional arguments must be positive integers. Invalid or missing values use their defaults.

## Examples

**1. Scan an IP address**

```bash
./http_scan 192.168.1.100
```

**2. Scan a domain name**

```bash
./http_scan example.com
```

**3. Scan using an HTTP URL**

```bash
./http_scan http://example.com
```

**4. Scan using an HTTPS URL**

```bash
./http_scan https://example.com
```

**5. Scan a URL with a port**

```bash
./http_scan http://192.168.1.100:8080
```

Note: The supplied port is removed during target parsing. The scanner still scans all 65,535 ports.

**6. Change connection timeout**

```bash
./http_scan 192.168.1.100 1000
```

**7. Change connection and response timeouts**

```bash
./http_scan 192.168.1.100 1000 1500
```

**8. Change all settings**

```bash
./http_scan 192.168.1.100 1000 1500 512
```

Uses:
- Connection timeout: 1000 ms
- Response timeout: 1500 ms
- Threads: 512

**9. Display help**

```bash
./http_scan --help
```

Or:

```bash
./http_scan -h
```

## Sample Output

```text
Scanning example.com (93.184.216.34) on all 65535 ports with 256 threads...

[+] HTTP  on port 80
[+] HTTPS on port 443
[+] HTTPS on port 8443

Done in 38214 ms. 3 HTTP/HTTPS port(s) found,
```

The IP address, detected ports, and scan duration depend on the target and network conditions.

## How It Works

1. Parses the supplied target and removes the URL scheme, path, and optional port.
2. Resolves the hostname to an IPv4 address.
3. Creates multiple worker threads.
4. Each thread takes the next available port from 1 to 65535.
5. Attempts a non-blocking TCP connection.
6. Sends a TLS ClientHello to check for a TLS response.
7. Checks the response for a TLS handshake record header.
8. If TLS detection fails, establishes a new TCP connection.
9. Sends an HTTP GET request.
10. Checks whether the response starts with an HTTP response prefix.
11. Reports detected HTTP or TLS services.
12. Displays the total number of detected services and scan duration.

## Detection Methods

### HTTP Detection

The scanner sends an HTTP GET request:

```http
GET / HTTP/1.1
Host: example.com
Connection: close
User-Agent: http_scan/1.0
```

It checks the response for:

- HTTP/1.0
- HTTP/1.1
- HTTP/2

### HTTPS Detection

The scanner sends a raw TLS ClientHello containing TLS cipher suites and extensions.

It checks the server response for:

- TLS handshake record type: `0x16`
- TLS major version byte: `0x03`

If the response matches these bytes, the scanner reports the port as HTTPS.

## Notes and Limitations

- Scans TCP ports only.
- Scans all 65,535 ports on every run.
- Supports IPv4 resolution.
- Does not perform HTTP authentication.
- Does not crawl websites or inspect web pages.
- Does not check for web vulnerabilities.
- Does not retrieve SSL certificates.
- Does not establish a complete TLS session.
- TLS detection uses a response-header check, so other TLS services might be classified as HTTPS.
- Does not perform a full HTTP/2 negotiation.
- Does not scan UDP ports.
- High thread counts require sufficient file descriptors.
- Network latency, firewall rules, and connection limits affect scan results.
