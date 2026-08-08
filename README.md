# Phantom

An eBPF-based tool for hiding red team infrastructure during adversary simulations and training exercises.

## What it does

Phantom hides files, processes, ports, interfaces, and IP addresses from standard Linux tools like `ls`, `ps`, `ss`, `ip a`, `tcpdump`, and others. It uses eBPF to intercept syscalls and modify results before userspace sees them.

This lets learners focus on threat hunting, malware analysis, or system administration without getting confused by background services, remote monitoring tools (RMM, Veyon, VNC), or other simulation infrastructure.

## Why I built this

When I was teaching threat hunting and malware analysis, some students would confuse the program that launched the simulation with being part of the files to analyze. While they received extra points, they skipped over the instructions to ignore that file.

The background services used to administer the simulation or remote monitoring tools could be confused with being part of the learning material.

**Note for advanced simulations:** Learners could discover the hidden files and ports, so it is recommended to name files and folders with names like `FOR-440-infrastructure` or `CTF_XXX` so they know to ignore them.

## Getting started

### Prerequisites

- Linux kernel 5.4+ (5.15+ recommended)
- `CONFIG_DEBUG_INFO_BTF=y` and `CONFIG_BPF_SYSCALL=y`
- clang, llvm, libelf-dev, zlib1g-dev, make
- Root or `CAP_BPF` + `CAP_NET_ADMIN` capabilities

### Build

```bash
cd phantom
./build.sh
```

This generates `vmlinux.h`, compiles the BPF program, and links the binary at `build/bin/phantom`.

### Quick usage

```bash
# Hide files and run
sudo phantom add file hide-prefix redteam_
sudo phantom add enable-files
sudo phantom daemon

# Hide processes and ports
sudo phantom add process hide c2agent
sudo phantom add port hide 4444
sudo phantom add enable-procs
sudo phantom add enable-ports
sudo phantom daemon
```

### Cross-compilation

Build for arm64 on an x86_64 host:

```bash
# Requires aarch64-linux-gnu-gcc and cross-compiled libbpf
make CROSS_COMPILE=aarch64-linux-gnu-
```

## Resources I learned from

- [ebpf.io](https://ebpf.io/)
- [eunomia.dev](https://eunomia.dev/)
- [Sysdig: eBPF offensive capabilities](https://www.sysdig.com/blog/ebpf-offensive-capabilities)
- [Acceis](https://www.acceis.fr/)

## How this project started

This project started by going through those tutorials and hacking together C code the best I could to modify and get it working. This is my first time sitting down to learn C. I always need a project to learn a language to help it "stick." I primarily use Go.

The last two months, I worked on it virtually every day after I was laid off to keep myself busy and take breaks from job hunting.

AI was used to help decode a lot of the errors and to better understand C programming. While I will support this program and keep adding on to it, it will likely be the only C program I work on. I prefer Go. :)

## Documentation

See [HOWTO.md](docs/HOWTO.md) for the full usage guide with sample configurations.

## License

MIT License. See [LICENSE](LICENSE) for details.
