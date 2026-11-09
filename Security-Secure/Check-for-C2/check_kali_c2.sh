#!/usr/bin/env bash
# Read-only first-pass triage for suspicious outbound connections and persistence on Kali/Debian.
# This script does not kill processes, modify configuration, or upload data.
set -u
umask 077

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run with sudo: sudo bash $0"
  exit 1
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
CALLER="${SUDO_USER:-root}"
CALLER_HOME="$(getent passwd "$CALLER" 2>/dev/null | cut -d: -f6)"
[[ -n "$CALLER_HOME" && -d "$CALLER_HOME" ]] || CALLER_HOME="/root"
OUT="${1:-$CALLER_HOME/kali-c2-triage-${STAMP}.txt}"
mkdir -p "$(dirname "$OUT")"

section() {
  printf '\n\n=====================================================================\n'
  printf ' %s\n' "$1"
  printf '=====================================================================\n'
}

run() {
  echo "+ $*"
  "$@" 2>&1 || echo "[command returned non-zero: $*]"
}

{
  echo "Kali Linux C2 / malware first-pass triage"
  echo "Generated: $(date -Is)"
  echo "Hostname: $(hostname 2>/dev/null || true)"
  echo "Report: $OUT"
  echo "Scope: read-only local inventory; findings require human verification."

  section "1. System and network context"
  run uname -a
  if command -v lsb_release >/dev/null 2>&1; then run lsb_release -a; fi
  if command -v ip >/dev/null 2>&1; then
    run ip -brief address
    run ip route
    run ip -brief link
  fi
  if command -v resolvectl >/dev/null 2>&1; then run resolvectl status; fi

  section "2. Established TCP connections with process ownership"
  if command -v ss >/dev/null 2>&1; then
    run ss -H -tpno state established
  else
    echo "ss is not installed."
  fi

  section "3. UDP sockets and listening services"
  if command -v ss >/dev/null 2>&1; then
    run ss -H -uapn
    run ss -H -lntup
  fi

  section "4. Network connections from lsof (when installed)"
  if command -v lsof >/dev/null 2>&1; then
    run lsof -nP -i
  else
    echo "lsof is not installed. Install with: sudo apt install lsof"
  fi

  section "5. Process tree and full command lines"
  run ps -eo pid,ppid,user,lstart,etime,stat,comm,args --forest

  section "6. Processes executing from unusual or temporary locations"
  echo "Review these entries. Development tools and scripts in home/temp paths are not automatically malicious."
  for proc in /proc/[0-9]*; do
    pid=${proc##*/}
    exe=$(readlink "$proc/exe" 2>/dev/null || true)
    [[ -n "$exe" ]] || continue
    case "$exe" in
      /tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*|/home/*|/root/*)
        cmd=$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)
        user=$(ps -o user= -p "$pid" 2>/dev/null | xargs || true)
        printf 'PID=%s USER=%s EXE=%s CMD=%s\n' "$pid" "$user" "$exe" "$cmd"
        ;;
    esac
  done

  section "7. Deleted executable files still held open"
  found_deleted=0
  for proc in /proc/[0-9]*; do
    pid=${proc##*/}
    exe=$(readlink "$proc/exe" 2>/dev/null || true)
    case "$exe" in
      *" (deleted)")
        found_deleted=1
        cmd=$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)
        printf 'PID=%s EXE=%s CMD=%s\n' "$pid" "$exe" "$cmd"
        ;;
    esac
  done
  [[ $found_deleted -eq 1 ]] || echo "No deleted process executables observed."

  section "8. Enabled and running system services"
  if command -v systemctl >/dev/null 2>&1; then
    run systemctl list-units --type=service --state=running --no-pager
    run systemctl list-unit-files --type=service --state=enabled --no-pager
    run systemctl list-timers --all --no-pager
  else
    echo "systemctl not found."
  fi

  section "9. Locally defined systemd units and user service files"
  for dir in /etc/systemd/system /usr/local/lib/systemd/system /root/.config/systemd/user /home/*/.config/systemd/user; do
    [[ -d "$dir" ]] || continue
    find "$dir" -maxdepth 3 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \) -print 2>/dev/null
  done

  section "10. Cron jobs and scheduled tasks"
  for f in /etc/crontab /etc/anacrontab; do
    if [[ -f "$f" ]]; then echo "--- $f"; sed -n '1,240p' "$f"; fi
  done
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs; do
    if [[ -d "$d" ]]; then
      echo "--- Files in $d"
      find "$d" -maxdepth 1 -type f -printf '%M %u:%g %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null
      if [[ "$d" == /etc/cron.d || "$d" == /var/spool/cron/crontabs ]]; then
        find "$d" -maxdepth 1 -type f -exec sh -c 'for f do echo "--- $f"; sed -n "1,200p" "$f"; done' sh {} + 2>/dev/null
      fi
    fi
  done
  if command -v atq >/dev/null 2>&1; then run atq; fi

  section "11. Desktop autostart entries"
  for d in /etc/xdg/autostart /root/.config/autostart /home/*/.config/autostart; do
    [[ -d "$d" ]] || continue
    find "$d" -maxdepth 1 -type f -name '*.desktop' -print -exec grep -H -E '^(Name|Exec|TryExec|Hidden|X-GNOME-Autostart-enabled)=' {} \; 2>/dev/null
  done

  section "12. SSH authorized-key locations and fingerprints"
  for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [[ -f "$f" ]] || continue
    echo "--- $f"
    if command -v ssh-keygen >/dev/null 2>&1; then ssh-keygen -lf "$f" 2>&1 || true; else echo "ssh-keygen unavailable"; fi
  done

  section "13. Shell startup files with potentially relevant launch commands"
  echo "Only matching lines are shown. These commands also have legitimate uses."
  for f in /etc/profile /etc/bash.bashrc /etc/profile.d/* /root/.profile /root/.bashrc /home/*/.profile /home/*/.bashrc /home/*/.zshrc; do
    [[ -f "$f" ]] || continue
    grep -nHEi '(curl|wget|nc |ncat|netcat|socat|bash -i|sh -i|python.*socket|perl.*socket|base64 -d|/dev/tcp|nohup|setsid|systemctl enable|crontab)' "$f" 2>/dev/null || true
  done

  section "14. Executable files in common temporary drop locations"
  for d in /tmp /var/tmp /dev/shm; do
    [[ -d "$d" ]] || continue
    echo "--- $d"
    find "$d" -xdev -type f -perm /111 -printf '%M %u:%g %TY-%Tm-%Td %TH:%TM %s bytes %p\n' 2>/dev/null
  done

  section "15. Recently changed files in common persistence locations (last 14 days)"
  for d in /etc/systemd/system /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/xdg/autostart /root/.config/autostart /home; do
    [[ -d "$d" ]] || continue
    echo "--- $d"
    find "$d" -xdev -type f -mtime -14 -printf '%TY-%Tm-%Td %TH:%TM %u:%g %p\n' 2>/dev/null | head -n 300
  done

  section "16. Package verification (may take a while)"
  if command -v dpkg >/dev/null 2>&1; then
    echo "dpkg -V reports package files whose recorded metadata/checksums differ, where verification data exists. Local modifications are not automatically malware."
    run dpkg -V
  fi
  if command -v debsums >/dev/null 2>&1; then
    echo "--- debsums summary"
    run debsums -s
  else
    echo "debsums not installed. Optional: sudo apt install debsums, then sudo debsums -s"
  fi

  section "17. Optional rootkit scanners already installed"
  if command -v rkhunter >/dev/null 2>&1; then
    echo "Running rkhunter warning-only check. Results can include false positives."
    rkhunter --check --skip-keypress --report-warnings-only 2>&1 || true
  else
    echo "rkhunter not installed; not installed automatically."
  fi
  if command -v chkrootkit >/dev/null 2>&1; then
    echo "Running chkrootkit quiet check. Results can include false positives."
    chkrootkit -q 2>&1 || true
  else
    echo "chkrootkit not installed; not installed automatically."
  fi

  section "18. Quick interpretation guide"
  cat <<'GUIDE'
Do not label a host infected based on one unfamiliar IP, port, process name, or scanner warning.
Investigate correlations:
- An established outbound connection plus an unexplained process and unusual executable path is higher priority.
- A process running from /tmp, /dev/shm, or a hidden home-directory path deserves review, but developers often run legitimate tools there.
- A deleted executable still running deserves review; package upgrades and normal process replacement can also cause this.
- Unknown enabled services, cron jobs, timers, autostart entries, or SSH keys deserve verification against changes you made.
- A clean snapshot does not rule out dormant malware, periodic callbacks, kernel-level compromise, or C2 using normal browser/system processes.
GUIDE

} | tee "$OUT"

chmod 600 "$OUT"
if [[ -n "${SUDO_USER:-}" ]]; then
  chown "$SUDO_USER" "$OUT" 2>/dev/null || true
fi
echo
 echo "Report saved to: $OUT"
echo "The report can contain usernames, paths, IP addresses, and command lines. Review/redact it before sharing."
