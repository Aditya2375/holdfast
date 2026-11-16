# holdfast

An original rootless Linux container runtime in C, with an interactive policy inspector. One local program, six namespaces, one fixed policy. No daemon, image downloads or insecure fallback.

The browser companion builds launch plans and explains the policy. It does **not** execute containers or report simulated execution as a real result. Native execution happens only in the C runtime.

## Quick start

Requires Linux x86-64, kernel 5.9 or newer, a C compiler, glibc static development libraries for the included fixture, Python 3 and `strace` for tests. Unprivileged user namespaces, mount/PID/network/IPC/UTS namespaces and seccomp must be permitted by the host. A new enough kernel alone is not sufficient. Do not run as root, change host security settings or use `sudo` to work around a denial.

```sh
make
root=$(mktemp -d /tmp/holdfast-root.XXXXXX)
mkdir -p "$root/bin" "$root/proc" "$root/tmp"
cp build/payload "$root/bin/payload"
./build/holdfast "$root" -- /bin/payload inspect
./build/holdfast "$root" -- /bin/payload deny
./build/holdfast "$root" -- /bin/payload limits
./build/holdfast --timeout 1 "$root" -- /bin/payload sleep
# The last command intentionally exits 124 after the deadline.
rm -rf -- "$root"
```

The native fixture is original, harmless C code in `tests/payload.c`. The inspection mode checks mapped UID/GID 0, PID 2 with supervisor PID 1 and the private hostname, then prints `/proc/self/status`. Other modes test the syscall, filesystem and resource boundaries. No downloaded rootfs or personal data is needed.

```text
holdfast [--timeout 1..30] ROOTFS -- /absolute/program [args...]
```

`ROOTFS` must be caller-owned, not writable by group/others, and have real `proc/` and `tmp/` directories, not symlinks. The final root component cannot be a symlink. `/`, `/home`, `/tmp` and the caller's `$HOME` are rejected. Keep the entire tree and its ancestors trusted and quiescent. A root directory is opened, pinned by device/inode and checked again in the new mount namespace. This is not a general adversarial path resolver or image validator.

Your program must be an executable already in the root. Dynamic executables need their interpreter and libraries there too. No host binaries, libraries, devices or working directory are automatically exposed. Arguments go directly to `execve`; the runtime does not invoke a shell.

## What the runtime does

1. `clone` creates fresh user, mount, PID, network, IPC and UTS namespaces. Only the caller UID and primary GID are mapped to 0. A pipe handshake waits for mapping and covers the parent-death startup race. `setgroups` is denied before writing `gid_map`.
2. Mount propagation becomes recursively private. A **nonrecursive** bind mount prevents copying nested host mounts. A fresh, read-only proc filesystem belongs to the new PID namespace. A private 16MiB tmpfs is mounted at `/tmp` with 4,096 inodes, `nosuid,nodev,noexec`.
3. `pivot_root` switches roots, the old root is detached, cwd is `/`, and root is remounted `ro,nosuid,nodev`. No chroot-only fallback is available.
4. stdin becomes `/dev/null`. Descriptors 3 and above are closed with `close_range`. stdout/stderr are intentionally inherited, not sealed or captured by the runtime. The payload gets only `PATH=/bin:/usr/bin`, `LANG=C`, `LC_ALL=C`, `HOME=/` and `TMPDIR=/tmp`.
5. Securebits lock `NOROOT`, `NO_SETUID_FIXUP` and `NO_CAP_AMBIENT_RAISE`. Ambient, bounding, permitted, effective and inheritable capabilities are cleared. `no_new_privs` is set. Namespace UID 0 does not grant the payload capabilities back on exec.
6. PID 1 forks once, then the payload installs seccomp before `execve`. The native x86-64 architecture must match; foreign ABIs and x32-tagged calls are killed with `SIGSYS`. Only the 74 syscalls listed in `src/policy.h` are allowed. The default filter result is `EPERM`. A host that rejects an unimplemented syscall earlier can return `ENOSYS` instead.
7. PID 1 waits, reaps and forwards TERM, INT, HUP and QUIT. The host monitor kills PID 1 at the wall deadline, terminating the PID namespace. `PDEATHSIG` kills init if the monitor dies. Setup failures stop without executing the payload on the host.

## Resource policy

| Bound                              | Fixed policy                               |
| ---------------------------------- | ------------------------------------------ |
| Address space (`RLIMIT_AS`)        | 256MiB per process                         |
| CPU (`RLIMIT_CPU`)                 | 2 seconds, soft and hard                   |
| Regular file size (`RLIMIT_FSIZE`) | 1MiB per file                              |
| Open descriptors (`RLIMIT_NOFILE`) | 64 including standard descriptors          |
| Core dumps / locked memory         | 0                                          |
| Temporary filesystem               | 16MiB, 4,096 inodes                        |
| Wall deadline                      | 5 seconds by default, configurable 1 to 30 |

Existing lower host hard limits remain lower. PID 1 and the payload have per-process limits; these are **not** cgroup aggregate memory/CPU limits. A stalled kernel or uninterruptible I/O can delay cleanup. There is no output-byte cap, so direct stdout/stderr to endpoints appropriate for your workload.

Exit status is the payload's exit status, or 128 plus its terminating signal. The monitor returns 124 on its wall timeout and 125 on input/setup failure. Payloads may themselves return 124 or 125, so the numeric code alone does not disambiguate those cases; runtime diagnostics go to stderr.

## Scope and limits

This is a small systems implementation, **not a security product, VM, Docker replacement or promise that hostile code is safe**. Use a VM for untrusted code. The kernel remains shared and kernel vulnerabilities are out of scope.

- Exactly one single-threaded payload process. `fork`, `vfork`, `clone` and `clone3` are blocked after startup. Multi-process programs, threads and shell pipelines will not work. PID 1 itself is the trusted reaper and is not under the payload seccomp filter.
- No OCI compatibility, images, archive extraction, registries, overlays, daemon, general networking, device setup, cgroup management, time namespace or interactive terminal.
- Root contents and ancestor paths must be trusted and stay unchanged during a run. Read-only bind mounts do not prevent host-side modifications or validate file provenance. The runtime does not sanitize a malicious rootfs.
- No configured network links and no socket syscalls. stdout/stderr remain host endpoints and can be written, truncated or otherwise affected if the inherited endpoint permits it. stdin is null, but this is not an output sanitizer.
- Inherited supplementary host group credentials are not cleared: rootless single-GID mapping requires denying `setgroups`. Unmapped groups can still matter for host-side filesystem permission checks. Only the supplied trusted tree is intentionally made visible.
- Global kernel metrics in proc, such as memory/CPU details, are not virtualized. Resource bounds are not a complete denial-of-service boundary. No hostile-kernel or resource-exhaustion guarantee is made.
- Only native x86-64 Linux is compiled. There is no macOS, Windows, ARM, general image or broad libc compatibility claim. The fixed allowlist may reject legitimate single-process programs too. There is no flag to disable it.
- The web planner checks text syntax only. It cannot inspect your filesystem, validate executable compatibility or know whether your host allows namespaces. Its expected-behavior cards describe the included native fixture; they are not execution receipts.

## Build and test

```sh
make test                         # actual-kernel tests, not a simulation
make ubsan                        # same suite with UndefinedBehaviorSanitizer
python3 tools/export-policy.py    # regenerate browser allowlist
npm ci --ignore-scripts
npm test                          # model, policy parity, shell-quoting checks
npx playwright install --with-deps chromium
npm run test:browser              # actual Chromium at five viewport widths
python3 -m http.server 8080 --directory docs
```

Native tests exercise all six namespace IDs, UID/PID/hostname, zero capability sets, `no_new_privs`, seccomp mode, fixed environment, descriptor closure, literal argument arrays, mount flags, read-only root, temporary storage, memory/file/CPU/descriptor bounds, signal forwarding, exit propagation, monitor-death cleanup, ABI guards and failure injection at ten setup operations. An unlisted-number sweep accepts only `EPERM` or `ENOSYS`; named blocked-operation tests require `EPERM`. The test process adopts and reaps the deliberately orphaned test descendants.

A namespace or mount denial fails the test suite; it is not silently skipped. The runtime never requests privileged execution or changes sysctls. GitHub-hosted CI uses an ephemeral Ubuntu runner; it must actually permit this rootless flow for the native test job to pass.

The browser allowlist is generated from the same header the C filter compiles. Browser tests cover plan editing, invalid inputs, all stage cards, the full allowlist, default deny, HTML-looking literal strings, keyboard focus, overflow and console/network errors at 1440, 1024, 768, 390 and 320px. Chromium is tested, not native Safari, Firefox or Android. Production web code has no dependencies, remote fonts, analytics, storage or outbound runtime requests.

## Repository map

- `src/runtime.c`: native setup, lifecycle and fixed seccomp filter.
- `src/policy.h`: resource constants and syscall allowlist.
- `tests/`: original static fixture, actual-kernel integration tests and browser/model tests.
- `docs/`: dependency-free static web companion. No native container runs in the browser.
- `tools/export-policy.py`: C-to-web allowlist export.

## API references

Implementation is original; these sources informed the Linux API choices and limits.

- [User namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html), [mount namespaces](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html), [PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html).
- [pivot_root](https://man7.org/linux/man-pages/man2/pivot_root.2.html), [close_range](https://man7.org/linux/man-pages/man2/close_range.2.html), [resource limits](https://man7.org/linux/man-pages/man2/getrlimit.2.html).
- [Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html), [seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html), [no_new_privs](https://docs.kernel.org/userspace-api/no_new_privs.html).
- [Rootless Containers: user namespaces](https://rootlesscontaine.rs/how-it-works/userns/) and [OCI Linux configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md) for context. holdfast does not implement OCI.

## License

Dual-licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
