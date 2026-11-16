#!/usr/bin/env python3
"""Actual-kernel tests. Namespace failures fail the suite; never a simulated PASS."""
import ctypes
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

BASE = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("HOLDFAST_BIN", BASE / "build/holdfast")).resolve()
COUNT = 0
# Adopt and reap the intentionally orphaned test descendants.
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "test subreaper")


def check(ok, label):
    global COUNT
    if not ok:
        raise AssertionError(label)
    COUNT += 1


def run(root, *args, timeout=5, expect=0, env=None, pass_fds=()):
    p = subprocess.run(
        [str(BIN), "--timeout", str(timeout), str(root), "--", "/bin/payload", *args],
        text=True,
        capture_output=True,
        timeout=timeout + 3,
        env=env,
        pass_fds=pass_fds,
    )
    check(
        p.returncode == expect,
        f"{args}: status {p.returncode}, expected {expect}: {p.stdout} {p.stderr}",
    )
    check("FAIL" not in p.stdout, f"{args}: payload assertion: {p.stdout}")
    return p


def children(pid):
    try:
        return [
            int(n) for n in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
        ]
    except FileNotFoundError:
        return []


def dead(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] == "Z"
    except FileNotFoundError:
        return True


with tempfile.TemporaryDirectory(prefix="holdfast-test-") as tmp:
    root = Path(tmp) / "root"
    for name in ("bin", "proc", "tmp"):
        (root / name).mkdir(parents=True, exist_ok=True)
    shutil.copy2(BASE / "build/payload", root / "bin/payload")
    original = (root / "bin/payload").read_bytes()
    (Path(tmp) / "outside-secret").write_text("owned harmless isolation fixture")
    p = run(root)
    for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        check(f"{field}:\t0000000000000000" in p.stdout, f"{field} zero")
    check("NoNewPrivs:\t1" in p.stdout, "no_new_privs")
    check("Seccomp:\t2" in p.stdout, "seccomp filter")
    for mode in ("deny", "sweep", "limits", "tmpfill", "filesystem", "fd"):
        p = run(root, mode)
        COUNT += p.stdout.count("OK ")
    check(not list((root / "tmp").iterdir()), "host tmp not written")
    check(not (root / "should-not-exist").exists(), "host root not written")
    check((root / "bin/payload").read_bytes() == original, "executable unchanged")
    check(
        "host path not present"
        in run(root, "sentinel", str(Path(tmp) / "outside-secret")).stdout,
        "absent host root paths",
    )
    for line in run(root, "namespaces").stdout.splitlines():
        name, namespace = line.split()
        check(
            namespace != os.readlink(f"/proc/self/ns/{name}"), f"fresh {name} namespace"
        )
    mounts = run(root, "mounts").stdout.splitlines()
    check(len(mounts) == 3, "only root, proc and tmp mounts")
    for line in mounts:
        fields = line.split()
        opts = set(fields[5].split(","))
        check({"nosuid", "nodev"} <= opts, "nosuid,nodev mount")
        if fields[4] in ("/", "/proc"):
            check("ro" in opts, f"{fields[4]} readonly")
        if fields[4] in ("/proc", "/tmp"):
            check("noexec" in opts, f"{fields[4]} noexec")
    check("size=16384k,nr_inodes=4096" in mounts[-1], "tmp bytes/inode policy")
    env = dict(os.environ, HOLDFast_SECRET="never inherited")
    check(
        set(run(root, "env", env=env).stdout.splitlines())
        == {"PATH=/bin:/usr/bin", "LANG=C", "LC_ALL=C", "HOME=/", "TMPDIR=/tmp"},
        "fixed environment",
    )
    fd = os.open(root / "bin/payload", os.O_RDONLY)
    os.dup2(fd, 55)
    run(root, "fd", pass_fds=(55,))
    os.close(55)
    os.close(fd)
    args = (
        "hello world",
        "literal ' quote",
        "$(touch /tmp/never)",
        "; echo unsafe",
        "",
        "a" * 1024,
    )
    check(
        run(root, "args", *args).stdout.splitlines() == ["arg=" + a for a in args],
        "literal exec array, no shell",
    )
    for code in (0, 1, 7, 42, 124, 125, 255):
        run(root, "exit", str(code), expect=code)
    for mode in ("x32", "i386"):
        run(root, mode, expect=128 + signal.SIGSYS)
    start = time.monotonic()
    run(root, "sleep", timeout=1, expect=124)
    check(0.9 <= time.monotonic() - start < 2.5, "wall deadline measured")
    run(root, "cpu", timeout=5, expect=128 + signal.SIGKILL)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
        p = subprocess.Popen(
            [str(BIN), str(root), "--", "/bin/payload", "sleep"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        check(p.stdout.readline().strip() == "READY", "signal payload ready")
        p.send_signal(sig)
        out, err = p.communicate(timeout=2)
        check(
            p.returncode == 128 + sig,
            f"signal {sig} exit propagated {p.returncode} {out} {err}",
        )
    p = subprocess.Popen(
        [str(BIN), str(root), "--", "/bin/payload", "sleep"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    check(p.stdout.readline().strip() == "READY", "death test ready")
    init = children(p.pid)
    check(len(init) == 1, "one namespace init")
    payload = children(init[0])
    check(len(payload) == 1, "one payload")
    p.kill()
    p.communicate(timeout=2)
    for _ in range(100):
        if all(dead(pid) for pid in init + payload):
            break
        time.sleep(0.01)
    check(
        all(dead(pid) for pid in init + payload), "parent death kills init and payload"
    )
    while True:
        try:
            waited, _ = os.waitpid(-1, os.WNOHANG)
            if waited == 0:
                break
        except ChildProcessError:
            break
    for i in range(30):
        run(root, "exit", str(i), expect=i)
    for args in (
        [],
        ["--timeout", "0"],
        ["--timeout", "-1"],
        ["--timeout", "31"],
        ["--timeout", "1x"],
        [str(root), "--", "relative"],
        [str(root), "--", "x" * 4096],
        ["/tmp", "--", "/bin/payload"],
        ["/", "--", "/bin/payload"],
        [str(Path.home()), "--", "/bin/payload"],
    ):
        r = subprocess.run([str(BIN), *args], capture_output=True, timeout=2)
        check(r.returncode == 125, f"invalid input {args}")
    linked = Path(tmp) / "linked"
    linked.symlink_to(root)
    r = subprocess.run(
        [str(BIN), str(linked), "--", "/bin/payload"], capture_output=True
    )
    check(r.returncode == 125, "symlink root rejected")
    (root / "proc").rmdir()
    (root / "proc").symlink_to("/proc")
    r = subprocess.run([str(BIN), str(root), "--", "/bin/payload"], capture_output=True)
    check(r.returncode == 125, "symlink proc rejected")
    (root / "proc").unlink()
    (root / "proc").mkdir()
    (root / "bin/payload").chmod(0o644)
    run(root, expect=125)
    (root / "bin/payload").chmod(0o755)
    root.chmod(0o777)
    run(root, expect=125)
    root.chmod(0o700)
    if shutil.which("strace"):
        for call in (
            "clone",
            "mount",
            "pivot_root",
            "capset",
            "seccomp",
            "close_range",
            "fchdir",
            "sethostname",
            "dup2",
            "prctl",
        ):
            p = subprocess.run(
                [
                    "strace",
                    "-f",
                    "-qq",
                    "-o",
                    os.devnull,
                    "-e",
                    f"inject={call}:error=EPERM:when=1",
                    str(BIN),
                    str(root),
                    "--",
                    "/bin/payload",
                    "sleep",
                ],
                text=True,
                capture_output=True,
                timeout=3,
            )
            check(
                p.returncode == 125 and "READY" not in p.stdout,
                f"{call} setup failure prevents payload: {p.returncode} {p.stderr}",
            )
    else:
        raise AssertionError("strace required for fail-closed injection tests")
print(json.dumps({"status": "PASS", "assertions": COUNT, "actual_kernel": True}))
