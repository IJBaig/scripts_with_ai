# Kali Linux C2 and Malware First-Pass Triage

A read-only, first-pass Bash triage script for Kali Linux and other Debian-based systems. It collects local evidence that can help you investigate suspicious outbound connections, unexpected processes, and common persistence mechanisms.

**Script:** `check_kali_c2.sh`  
**Report format:** Plain-text (`.txt`)  
**Privileges:** Root required  
**Designed for:** Kali Linux / Debian-based systems using systemd and `dpkg`

> **Important:** This is an investigative aid, not an antivirus product or a malware-removal tool. It does not prove that a machine is clean or infected. Treat its output as leads that need human verification.

---

## Contents

- [What the script checks](#what-the-script-checks)
- [Requirements](#requirements)
- [Download and run](#download-and-run)
- [Choose a report location](#choose-a-report-location)
- [Understanding the report](#understanding-the-report)
- [How to investigate suspicious findings](#how-to-investigate-suspicious-findings)
- [False positives and normal results](#false-positives-and-normal-results)
- [Limitations](#limitations)
- [Privacy and handling the report](#privacy-and-handling-the-report)
- [Troubleshooting](#troubleshooting)
- [Safe response if you find strong indicators](#safe-response-if-you-find-strong-indicators)

---

## What the script checks

The script gathers a local snapshot. It does not terminate processes, delete files, disable services, edit configuration files, or upload the report. It does create the report file and set its permissions to owner-only (`600`). If you run it with `sudo`, it attempts to assign the report to the user who invoked `sudo`.

The report contains the following sections.

| Section | Collection | Why it matters |
|---|---|---|
| 1. System and network context | Kernel and distribution details, interface addresses, routes, link state, and resolver status when available | Establishes the host and network context for interpreting later evidence. |
| 2. Established TCP connections | Active TCP connections with process details, where the kernel and `ss` expose ownership | Helps connect an outbound destination to the local process that owns the socket. |
| 3. UDP sockets and listening services | UDP sockets and TCP/UDP listening sockets | Shows local services and UDP activity. UDP does not have a TCP-style established state, so an entry is not automatically an active C2 session. |
| 4. `lsof` network view | Network sockets reported by `lsof`, if installed | Provides a second view of network sockets and owning processes. |
| 5. Process tree | PID, parent PID, user, start time, elapsed time, state, executable name, command line, and process tree | Helps identify unusual process ancestry, arguments, or execution times. |
| 6. Unusual executable locations | Processes whose executable path resolves under `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, `/home`, or `/root` | Highlights locations worth reviewing. These paths are also used by legitimate programs and development tools. |
| 7. Deleted executable still running | Processes whose `/proc/<PID>/exe` link ends in `(deleted)` | A process may continue running after its executable file is unlinked. This deserves review but also occurs during legitimate upgrades and replacement of running binaries. |
| 8. Services and timers | Running services, enabled service unit files, and systemd timers | Finds services and scheduled units that might provide persistence. |
| 9. Local systemd unit files | Selected system and user service, timer, and socket unit files | Helps locate locally defined units, including user-level units in the listed home directories. |
| 10. Cron and scheduled tasks | System cron configuration, cron directory file metadata, relevant cron file contents, and `atq` jobs when available | Finds commands configured to run on a schedule. |
| 11. Desktop autostart | `.desktop` startup entries and selected launch fields | Finds programs configured to start when a graphical user session begins. |
| 12. SSH authorized keys | Fingerprints of root and user `authorized_keys` files | Helps identify keys that should be compared with the keys you expect. It reports fingerprints, not private keys. |
| 13. Shell startup files | Lines containing selected command patterns such as `curl`, `wget`, `socat`, reverse-shell-like arguments, or persistence commands | Highlights startup commands worth checking. Matching text is not proof of malicious activity. |
| 14. Temporary executable files | Executable files directly inside `/tmp`, `/var/tmp`, and `/dev/shm` | Finds files in common temporary locations. The search is limited to those directories and does not classify the files. |
| 15. Recently changed persistence locations | Files modified in the last 14 days under selected systemd, cron, autostart, and home paths | Helps narrow a review to recent changes. File modification times are clues, not proof of when or why a file was created. |
| 16. Package verification | `dpkg -V`, and `debsums -s` if `debsums` is installed | Reports package-file verification differences where package metadata or checksums are available. Local configuration changes and legitimate package modifications can appear. |
| 17. Optional rootkit scanners | Warning-only `rkhunter` check and quiet `chkrootkit` check, only when already installed | Adds another source of leads. Scanner warnings can be false positives and do not establish compromise. |
| 18. Interpretation guide | Reminders for correlating findings | Explains why one unfamiliar IP, process, port, or warning is not enough to declare a compromise. |

### Why these checks are correlated

A suspicious remote IP alone is weak evidence. A browser, package manager, VPN, cloud sync client, or development tool might contact an unfamiliar server for legitimate reasons.

A stronger lead appears when several unrelated observations line up, for example:

1. An unexplained process owns an outbound connection.
2. Its executable runs from an unexpected directory or has an unusual command line.
3. The process or a related unit appears in a startup mechanism such as systemd, cron, or desktop autostart.
4. The activity has no match in the software or services you intentionally installed.

Even this combination needs investigation. It is an indicator, not a final verdict.

---

## Requirements

### Required

- Kali Linux or a compatible Debian-based distribution.
- Bash.
- Root privileges, normally through `sudo`.
- Common system utilities used by the script, including `ps`, `ip`, `ss`, `systemctl`, `find`, `grep`, `readlink`, `getent`, and `dpkg`.

### Optional tools

- `lsof`: adds a second view of network sockets.
- `debsums`: checks installed package files against available recorded checksums.
- `rkhunter`: performs its local rootkit warning checks if already installed.
- `chkrootkit`: performs its quiet rootkit checks if already installed.
- `atq`: lists queued `at` jobs when the utility is available.
- `resolvectl`: reports resolver status when available.
- `lsb_release`: reports distribution details when available.

The script does **not** install missing tools. To add `lsof` on Kali/Debian:

```bash
sudo apt update
sudo apt install lsof
```

Optional package installation changes the system and requires repository access. Do this only when appropriate for your investigation. If you are preserving a potentially compromised machine, avoid making unnecessary changes before collecting evidence.

---

## Download and run

Place `check_kali_c2.sh` in a working directory. From that directory, run:

```bash
chmod +x check_kali_c2.sh
sudo ./check_kali_c2.sh
```

The script requires root. If you omit the output path, it saves a timestamped report in the home directory of the user who invoked `sudo`. For example:

```text
/home/ijbaig/kali-c2-triage-20261110_030000.txt
```

The exact timestamp and location depend on your system and the account used to run the command.

You can also run it through Bash without setting the executable bit:

```bash
sudo bash check_kali_c2.sh
```

### Choose a report location

Pass an output path as the first argument:

```bash
sudo ./check_kali_c2.sh /home/ijbaig/reports/kali-triage.txt
```

The script creates the parent directory when needed. It then restricts the report permissions to owner read/write (`600`). When `sudo` supplies a calling user, the script attempts to make that user the report owner.

Avoid writing the report to a shared directory unless you intend other users to access it.

---

## Understanding the report

### 1. Start with established TCP connections

Find the section:

```text
2. Established TCP connections with process ownership
```

Look for the local process, PID, local address, and remote address. Pay attention to connections owned by processes you do not recognize.

A remote address is not inherently malicious. Identify the owning process first. Then inspect its executable path, package ownership, parent process, command line, and reason for running.

Useful follow-up commands for a PID you are investigating:

```bash
sudo ps -fp <PID>
sudo pstree -aps <PID>
sudo readlink -f /proc/<PID>/exe
sudo tr '\0' ' ' < /proc/<PID>/cmdline; echo
sudo lsof -nP -p <PID>
```

Replace `<PID>` with the numeric process ID. These commands inspect a process; they do not establish whether its network destination is malicious.

### 2. Review UDP carefully

UDP does not establish a session in the same way TCP does. UDP socket output might show a process that is ready to send or receive datagrams, or a socket associated with a peer. Do not label every UDP socket a C2 connection.

DNS, NTP, VPNs, voice/video applications, and many ordinary programs use UDP.

### 3. Review process ancestry and command lines

In the process tree, look for:

- A process with an unexpected parent.
- A program running as root without a clear reason.
- An unfamiliar executable launched by a shell or script.
- Encoded or heavily obfuscated command-line arguments.
- A process name that imitates a system component but runs from an unusual path.

Process names can be copied. Verify the executable path and package ownership rather than trusting the displayed name.

For a candidate executable:

```bash
sudo file /path/to/executable
sudo stat /path/to/executable
sudo sha256sum /path/to/executable
dpkg -S /path/to/executable 2>/dev/null
```

The final command checks whether a Debian package claims ownership of the path. A result does not guarantee the file is safe, and no result does not prove malware; locally installed software often has no `dpkg` owner.

### 4. Check persistence entries against your own changes

Review enabled services, timers, cron entries, autostart launchers, shell startup lines, and SSH key fingerprints. Ask:

- Do I recognize the service or scheduled task?
- Does its executable path match the software package or project I installed?
- Does its creation or modification time match a change I made?
- Does the command contact an unfamiliar host or download and execute remote content?
- Do I recognize every SSH key fingerprint?

Do not remove an entry solely because its name looks unusual. First inspect its full unit file, script, package source, and execution history.

### 5. Interpret package verification results

`dpkg -V` and `debsums` compare installed files with package metadata or checksums when verification data exists. Differences can arise from:

- Expected edits to configuration files.
- Legitimate updates or locally patched binaries.
- Missing files.
- Unexpected replacement or modification.

Prioritize unexpected changes to executable files and security-sensitive components. Compare them with trusted package contents and a known-good system when possible.

### 6. Interpret rootkit scanner warnings cautiously

`rkhunter` and `chkrootkit` use heuristics and known checks. They can flag legitimate custom kernels, tools, files, or configuration choices. A warning is a reason to inspect the specific item, not proof of a rootkit.

The script runs these scanners only if their commands are already installed. It does not install or update them.

---

## How to investigate suspicious findings

Use this order to avoid jumping to conclusions:

1. **Identify the process.** Record its PID, owner, executable path, command line, start time, parent, and open files.
2. **Identify the destination.** Record the remote IP, port, protocol, and observation time. Determine whether the destination belongs to a service or software you use.
3. **Verify the executable.** Check its package owner, file metadata, hash, and origin. Compare the hash with a trusted vendor or distribution source where possible.
4. **Check persistence.** Determine whether a systemd unit, timer, cron job, autostart entry, shell startup file, or other mechanism launches it.
5. **Collect additional evidence.** Review relevant system logs and, when appropriate, collect a short packet-header capture. A single network snapshot can miss periodic callbacks.
6. **Form a conclusion with confidence.** Separate confirmed facts, suspicious indicators, benign explanations, and questions that remain unresolved.

### Optional live connection view

To watch established TCP connections refresh every two seconds:

```bash
sudo watch -n 2 'ss -tpno state established'
```

To list sockets with process information:

```bash
sudo lsof -nP -i
```

To list listening TCP and UDP sockets:

```bash
sudo ss -lntup
```

These are manual follow-up commands. They are not run continuously by the script.

---

## False positives and normal results

The following can be legitimate, depending on your setup:

- Processes running from a home directory, virtual environment, project folder, `/tmp`, or `/dev/shm`.
- A deleted executable still in use after a package upgrade or application replacement.
- SSH, VPN, browser, cloud, package-manager, container, development, and remote-access connections.
- Locally modified configuration files reported by package verification.
- Systemd services or cron jobs created by installed applications.
- Rootkit scanner warnings caused by custom Kali tools or system configuration.
- UDP sockets with no active TCP-like session.

Use context, installation history, package ownership, file hashes, logs, and repeated observations before deciding that a finding is malicious.

---

## Limitations

This tool is intentionally a first-pass local inventory. It has important limits:

- It does not perform antivirus signature scanning or full filesystem malware scanning.
- It does not query threat-intelligence services or check IP/domain reputation online.
- It does not capture packets or DNS traffic itself.
- It does not continuously monitor the host. It records a snapshot while the script runs.
- It might miss short-lived or periodic C2 connections that are inactive during collection.
- It might not identify malware that uses a legitimate browser, system process, injected code, kernel component, or trusted remote-management tool.
- It does not comprehensively inspect every persistence method, user account, kernel module, container, browser extension, application profile, or firmware component.
- It does not determine whether an unfamiliar destination is malicious from its IP address alone.
- It cannot guarantee that a compromised host reports truthful process and network information. A sufficiently privileged rootkit can hide activity from local tools.
- A clean report does not prove the machine is free of malware. A warning does not prove compromise.

For a higher-confidence investigation, correlate endpoint evidence with firewall/router logs, DNS resolver logs, network captures, trusted offline scans, and a known-good environment.

---

## Privacy and handling the report

The report can contain sensitive host information, including:

- Usernames and home-directory paths.
- Internal and public IP addresses.
- Process command lines and file paths.
- Network destinations and listening ports.
- Service names, scheduled commands, and SSH key fingerprints.

The script does not upload the report. Review and redact sensitive details before sharing it with another person or posting it publicly. Do not share passwords, private keys, tokens, session cookies, or other secrets.

The report is created with restrictive permissions (`600`) so only its owner and root can read or write it by default. Preserve an original copy if you need to maintain investigation evidence.

---

## Troubleshooting

### `Run with sudo` appears

Run the script with root privileges:

```bash
sudo ./check_kali_c2.sh
```

### `ss` is missing

The script reports that `ss` is unavailable. On Kali, it is normally provided by the `iproute2` package. Check your package state before installing anything:

```bash
command -v ss
dpkg -l iproute2
```

### `lsof is not installed`

The main report still runs. Install `lsof` only if you want the additional socket listing:

```bash
sudo apt install lsof
```

### The report is not in the current directory

By default, the report is written to the home directory of the user who invoked `sudo`, not necessarily the current working directory. Read the final `Report saved to:` line, or pass an explicit path as the first argument.

### The report contains command errors

Some commands or directories do not exist on every Kali installation. The script records non-zero command results and continues. Review the surrounding section to decide whether the missing data matters to your system.

### The script stops because of a permission or filesystem issue

Check that the output directory exists or is writable by root, and ensure the filesystem has free space. The script needs root to inspect many process and system locations.

---

## Safe response if you find strong indicators

If you find a process or persistence entry with strong evidence of unauthorized activity:

1. Do not immediately delete the executable or persistence file. Preserve its path, timestamps, hash, process details, and related logs.
2. Avoid entering passwords or using sensitive accounts on the suspected machine.
3. If active harm is likely, isolate the host from the network in a controlled way. Consider the impact on evidence collection and other systems before disconnecting it.
4. From a separate trusted device, rotate credentials that might have been exposed. Revoke active sessions and keys where appropriate.
5. Preserve relevant logs and a copy of the triage report.
6. For a high-confidence compromise, prefer rebuilding from trusted installation media and restoring only verified data over attempting to clean an untrusted system in place.

If this is a work, school, or managed device, follow the applicable incident-response process and notify the responsible administrator.

---

## License and use

Use this script only on systems you own or are authorized to administer. It is intended for defensive inspection and incident triage. Review the script before running it, especially on production or evidence-sensitive systems.

