import { allowed } from "./policy.js";
export { allowed };
export const stages = Object.freeze([
  {
    name: "Pin the root",
    api: "open + fstat",
    detail:
      "Require a caller-owned, non-writable-by-others directory and real proc/ and tmp/ directories. Reopen in the new mount namespace and compare device/inode identity. You must keep the tree and its ancestors trusted and quiescent.",
  },
  {
    name: "Split the view",
    api: "clone + uid_map + gid_map",
    detail:
      "Create fresh user, mount, PID, network, IPC and UTS namespaces. Map only the caller UID/GID to 0. Deny setgroups. The new network has no configured interfaces; no host network is attached.",
  },
  {
    name: "Switch the root",
    api: "mount + pivot_root",
    detail:
      "Make propagation recursively private. Nonrecursively bind the root. Mount fresh read-only proc and a 16MiB noexec tmpfs, then pivot_root and detach the old root. Remount root read-only, nosuid and nodev.",
  },
  {
    name: "Close the doors",
    api: "close_range + setrlimit",
    detail:
      "Replace stdin with /dev/null and close descriptors 3 and above. stdout/stderr are deliberate host endpoints. Set hard and soft per-process address-space, CPU, file-size, descriptor, core and locked-memory bounds.",
  },
  {
    name: "Remove privilege",
    api: "securebits + capset + no_new_privs",
    detail:
      "Lock NOROOT, NO_SETUID_FIXUP and NO_CAP_AMBIENT_RAISE. Clear ambient, bounding, permitted, effective and inheritable capabilities. Set no_new_privs before any payload exec.",
  },
  {
    name: "Filter and execute",
    api: "seccomp + execve",
    detail:
      "PID 1 forks the payload once. The payload installs an x86-64 architecture guard, kills x32/foreign-ABI calls, allows only the fixed syscall list and returns EPERM for the rest. execve receives an argument array and fixed environment, never a shell string.",
  },
  {
    name: "Wait and clean up",
    api: "waitpid + signals + wall clock",
    detail:
      "PID 1 reaps the payload and forwards TERM, INT, HUP and QUIT. The host monitor enforces the wall deadline by killing PID 1, terminating its namespace. A parent-death signal and startup handshake cover monitor death. Setup errors never fall back to host execution.",
  },
]);
export const examples = Object.freeze({
  inspect: {
    label: "Inspect isolation",
    args: "inspect",
    syscall: "openat",
    expected:
      "The native fixture reports PID 2, PPID 1, mapped UID/GID 0, zero capability sets, NoNewPrivs 1 and Seccomp 2.",
  },
  deny: {
    label: "Probe a denied call",
    args: "deny",
    syscall: "clone",
    expected:
      "The native fixture attempts process creation, sockets, mount, ptrace and other blocked calls. The fixed filter returns EPERM.",
  },
  timeout: {
    label: "Reach the deadline",
    args: "sleep",
    syscall: "clock_nanosleep",
    expected:
      "The native fixture sleeps longer than the wall bound. The host monitor kills the namespace and returns 124.",
  },
  resources: {
    label: "Check resource bounds",
    args: "limits",
    syscall: "mmap",
    expected:
      "The native fixture checks rlimits, fails a 512MiB mapping with ENOMEM, a file over 1MiB with EFBIG and excess descriptors with EMFILE.",
  },
});
export function syscallDecision(raw) {
  const name = String(raw)
    .trim()
    .replace(/^__NR_/, "");
  if (!/^[a-z][a-z0-9_]{0,47}$/.test(name))
    return {
      state: "invalid",
      title: "Enter a syscall name",
      detail: "Use a Linux x86-64 name such as openat, clone or socket.",
    };
  if (allowed.includes(name))
    return {
      state: "allow",
      title: name + " is allowlisted",
      detail:
        "The filter permits this syscall. Kernel permissions, mount flags and resource limits still apply. Allowlisted does not mean every call succeeds.",
    };
  return {
    state: "deny",
    title: name + " is not allowlisted",
    detail:
      "If this is a native x86-64 syscall, the filter returns EPERM. Unknown names are not resolved to syscall numbers here. x32 and foreign ABIs terminate the process.",
  };
}
export function shellQuote(value) {
  return "'" + value.replaceAll("'", "'\\''") + "'";
}
export function launchPlan({ root, program, args, timeout }) {
  for (const v of [root, program, args])
    if (
      typeof v !== "string" ||
      v.length > 8192 ||
      /[\x00-\x08\x0b-\x1f\x7f]/.test(v)
    )
      throw Error(
        "Use text without control characters, at most 8192 characters per field.",
      );
  if (
    !root.startsWith("/") ||
    root === "/" ||
    root.endsWith("/") ||
    /[\r\n]/.test(root)
  )
    throw Error("Use an absolute root path, not /, without a trailing slash.");
  if (
    !program.startsWith("/") ||
    program.length >= 4096 ||
    /[\r\n]/.test(program)
  )
    throw Error("The program must be an absolute path inside the root.");
  if (!/^([1-9]|[12][0-9]|30)$/.test(String(timeout)))
    throw Error("Choose a wall timeout from 1 to 30 seconds.");
  const argv = args === "" ? [] : args.split("\n");
  return {
    command: [
      "./build/holdfast",
      "--timeout",
      String(timeout),
      shellQuote(root),
      "--",
      shellQuote(program),
      ...argv.map(shellQuote),
    ].join(" "),
    argc: argv.length + 1,
    timeout: Number(timeout),
  };
}
