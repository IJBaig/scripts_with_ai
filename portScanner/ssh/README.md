# SSH Scanner
## in testing
A multithreaded TCP scanner written in C++ that scans all 65,535 TCP ports on a target host and identifies SSH services by reading their SSH banners.

## Features

- Scans all TCP ports from 1 to 65535.
- Uses multithreading for faster scanning.
- Uses non-blocking TCP connections.
- Supports configurable connection timeout.
- Supports configurable SSH banner timeout.
- Identifies SSH services by checking for the `SSH-` banner prefix.
- Sends an SSH client identification string after detecting an SSH server.
- Reads and displays the server's SSH banner.
- Resolves domain names to IPv4 addresses.
- Automatically checks the file descriptor limit.
- Attempts to increase the file descriptor limit when needed.
- Uses thread-safe output.
- Displays the total number of SSH services found and scan duration.

## Requirements

- Linux
- GCC/G++ compiler
- C++17 support
- POSIX threads

## Compilation

Clone the repository:

Compile the source code:

```bash
g++ -O2 -std=c++17 -pthread ssh_scan.cpp -o ssh_scan
```

## Usage

```bash
./ssh_scan <host> [connect_ms] [banner_ms] [threads]
```

### Arguments

| Argument   | Description                            | Default  |
| ---------- | -------------------------------------- | -------- |
| host       | Target IP address or domain name       | Required |
| connect_ms | TCP connection timeout in milliseconds | 400      |
| banner_ms  | SSH banner timeout in milliseconds     | 400      |
| threads    | Number of scanning threads             | 256      |

All optional arguments must be positive integers. Invalid or missing values use their defaults.

## Examples

**1. Scan a target using default settings**

```bash
./ssh_scan 192.168.1.100
```

**2. Scan a domain name**

```bash
./ssh_scan example.com
```

**3. Set connection timeout**

```bash
./ssh_scan 192.168.1.100 1000
```

Uses a 1000 ms connection timeout.

**4. Set connection and banner timeouts**

```bash
./ssh_scan 192.168.1.100 1000 1500
```

Uses a 1000 ms connection timeout and a 1500 ms banner timeout.

**5. Set all options**

```bash
./ssh_scan 192.168.1.100 1000 1500 512
```

Uses:

- Connection timeout: 1000 ms
- Banner timeout: 1500 ms
- Threads: 512

## Sample Output

```text
Scanning 192.168.1.100 (192.168.1.100) on all 65535 ports with 256 threads...

[+] SSH on port 22   -> SSH-2.0-OpenSSH_9.2p1
[+] SSH on port 2222 -> SSH-2.0-OpenSSH_8.9p1

Done in 12500 ms. 2 SSH port(s) found,
```

Output depends on the target and network conditions.

## How It Works

1. Resolves the target hostname to an IPv4 address.
2. Creates multiple worker threads.
3. Each thread takes the next available port from 1 to 65535.
4. Attempts a non-blocking TCP connection.
5. Waits for the connection result using `select()`.
6. If the connection succeeds, waits for the server response.
7. Checks whether the response starts with `SSH-`.
8. Sends `SSH-2.0-probe_1.0` as the client identification string.
9. Reads the server's SSH identification banner.
10. Displays the port and banner if SSH is detected.
11. Reports the total number of SSH services found and scan duration.

## Notes and Limitations

- The scanner checks TCP ports only.
- It scans all 65,535 ports on every run.
- It detects SSH through the server identification banner.
- It does not perform SSH authentication.
- It does not check SSH vulnerabilities or weak credentials.
- It does not perform a full SSH version or vulnerability assessment.
- Connections that fail or time out are skipped.
- The scanner supports IPv4 resolution.
- Increasing the thread count does not always improve scanning speed.
- High thread counts require sufficient system file descriptors.
- Network latency, firewall rules, and connection limits affect scan results.

