#define _GNU_SOURCE
#include "policy.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/securebits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#if !defined(__x86_64__) || defined(__ILP32__)
#error holdfast supports only the native x86-64 Linux ABI
#endif
#define HF_VERSION "1.0.0"
static volatile sig_atomic_t signal_seen;
static void signal_handler(int sig) { signal_seen = sig; }
static void die(const char *step) {
  int saved = errno;
  fprintf(stderr, "holdfast: setup failed at %s: %s; payload not started\n",
          step, strerror(saved));
  _exit(125);
}
static void need(int okay, const char *step) {
  if (!okay)
    die(step);
}
static void handler(int sig) {
  struct sigaction a = {0};
  a.sa_handler = signal_handler;
  sigemptyset(&a.sa_mask);
  need(sigaction(sig, &a, NULL) == 0, "signal handler");
}
static void write_all(int fd, const char *text) {
  size_t left = strlen(text);
  while (left) {
    ssize_t n = write(fd, text, left);
    if (n < 0 && errno == EINTR)
      continue;
    need(n > 0, "mapping write");
    text += n;
    left -= (size_t)n;
  }
}
static void map_file(pid_t pid, const char *leaf, const char *value) {
  char path[96];
  int n = snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, leaf);
  need(n > 0 && (size_t)n < sizeof(path), "mapping path");
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  need(fd >= 0, "mapping open");
  write_all(fd, value);
  need(close(fd) == 0, "mapping close");
}
static int read_byte(int fd) {
  char c;
  ssize_t n;
  do
    n = read(fd, &c, 1);
  while (n < 0 && errno == EINTR);
  return n == 1 && c == 'G';
}
static void send_byte(int fd) {
  char c = 'G';
  ssize_t n;
  do
    n = write(fd, &c, 1);
  while (n < 0 && errno == EINTR);
  need(n == 1, "supervisor handshake");
}
static void set_limit(int resource, rlim_t value) {
  struct rlimit old;
  need(getrlimit(resource, &old) == 0, "getrlimit");
  struct rlimit r = {value < old.rlim_max ? value : old.rlim_max,
                     value < old.rlim_max ? value : old.rlim_max};
  need(setrlimit(resource, &r) == 0, "setrlimit");
}
static void drop_caps(void) {
  need(prctl(PR_SET_SECUREBITS,
             SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP |
                 SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NO_CAP_AMBIENT_RAISE |
                 SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED,
             0, 0, 0) == 0,
       "securebits");
  need(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) == 0,
       "clear ambient capabilities");
  for (unsigned cap = 0;; cap++) {
    errno = 0;
    int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
    if (present < 0 && errno == EINVAL)
      break;
    need(present >= 0 && cap < 64, "read capability bounding set");
    need(prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) == 0,
         "drop capability bounding set");
  }
  struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct d[2] = {{0}, {0}};
  need(syscall(SYS_capset, &h, d) == 0, "clear capabilities");
  need(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "no_new_privs");
}
static void filter(void) {
#define ALLOW(name)                                                            \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1),                      \
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  struct sock_filter code[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000u, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      HF_ALLOWED_SYSCALLS(ALLOW)
          BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)};
#undef ALLOW
  struct sock_fprog program = {(unsigned short)(sizeof(code) / sizeof(code[0])),
                               code};
  need(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == 0,
       "seccomp allowlist");
}
struct config {
  int root, go[2], ready[2], nullfd;
  char **args;
  char rootpath[PATH_MAX];
};
static void root_switch(int fd, const char *path) {
  need(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0,
       "private mount propagation");
  need(fchdir(fd) == 0, "root directory");
  need(mount(".", ".", NULL, MS_BIND, NULL) == 0, "nonrecursive root bind");
  need(chdir(path) == 0, "enter root bind mount");
  need(mount("proc", "proc", "proc",
             MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0,
       "private read-only proc");
  need(mount("tmpfs", "tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
             "size=16m,nr_inodes=4096,mode=1777") == 0,
       "bounded temporary RAM");
  need(syscall(SYS_pivot_root, ".", ".") == 0, "pivot_root");
  need(umount2(".", MNT_DETACH) == 0, "detach old root");
  need(chdir("/") == 0, "new cwd");
  need(mount(NULL, "/", NULL,
             MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV,
             NULL) == 0,
       "read-only root");
}
static int init(void *opaque) {
  struct config *c = opaque;
  need(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == 0, "parent death signal");
  close(c->go[1]);
  close(c->ready[0]);
  send_byte(c->ready[1]);
  close(c->ready[1]);
  if (!read_byte(c->go[0]))
    _exit(125);
  close(c->go[0]);
  need(getpid() == 1, "PID namespace init");
  need(sethostname("holdfast", 8) == 0, "private hostname");
  struct stat before, after;
  need(fstat(c->root, &before) == 0, "pinned root identity");
  int localroot =
      open(c->rootpath, O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  need(localroot >= 0 && fstat(localroot, &after) == 0 &&
           before.st_dev == after.st_dev && before.st_ino == after.st_ino,
       "root identity in new mount namespace");
  root_switch(localroot, c->rootpath);
  need(dup2(c->nullfd, STDIN_FILENO) == STDIN_FILENO, "null stdin");
  need(fcntl(1, F_SETFD, 0) == 0 && fcntl(2, F_SETFD, 0) == 0,
       "output descriptors");
  need(syscall(SYS_close_range, 3, ~0u, 0) == 0, "close inherited descriptors");
  umask(077);
  set_limit(RLIMIT_AS, HF_RAM_BYTES);
  set_limit(RLIMIT_CPU, HF_CPU_SECONDS);
  set_limit(RLIMIT_FSIZE, HF_FILE_BYTES);
  set_limit(RLIMIT_NOFILE, HF_NOFILE);
  set_limit(RLIMIT_CORE, 0);
  set_limit(RLIMIT_MEMLOCK, 0);
  drop_caps();
  handler(SIGTERM);
  handler(SIGINT);
  handler(SIGHUP);
  handler(SIGQUIT);
  pid_t child = fork();
  need(child >= 0, "payload fork");
  if (child == 0) {
    struct sigaction a = {0};
    a.sa_handler = SIG_DFL;
    sigemptyset(&a.sa_mask);
    for (int i = 1; i < NSIG; i++)
      if (i != SIGKILL && i != SIGSTOP)
        sigaction(i, &a, NULL);
    sigset_t empty;
    sigemptyset(&empty);
    need(sigprocmask(SIG_SETMASK, &empty, NULL) == 0, "payload signal mask");
    filter();
    char *const env[] = {"PATH=/bin:/usr/bin", "LANG=C", "LC_ALL=C", "HOME=/",
                         "TMPDIR=/tmp",        NULL};
    execve(c->args[0], c->args, env);
    die("execve");
  }
  int status;
  for (;;) {
    if (signal_seen) {
      int sig = signal_seen;
      signal_seen = 0;
      if (kill(child, sig) < 0 && errno != ESRCH)
        die("forward signal");
    }
    pid_t got = waitpid(-1, &status, WNOHANG);
    if (got == 0) {
      struct timespec tick = {0, 10000000};
      nanosleep(&tick, NULL);
      continue;
    }
    if (got == child)
      return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    if (got < 0 && errno == EINTR)
      continue;
    if (got < 0)
      die("reap payload");
  }
}
static double seconds(void) {
  struct timespec t;
  need(clock_gettime(CLOCK_MONOTONIC, &t) == 0, "monotonic clock");
  return t.tv_sec + t.tv_nsec / 1e9;
}
static int root_open(const char *path) {
  int fd = open(path, O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return -1;
  struct stat s;
  if (fstat(fd, &s) < 0 || s.st_uid != getuid() || (s.st_mode & 0022)) {
    close(fd);
    errno = EPERM;
    return -1;
  }
  char resolved[PATH_MAX];
  if (!realpath(path, resolved) || !strcmp(resolved, "/") ||
      !strcmp(resolved, "/home") || !strcmp(resolved, "/tmp") ||
      (getenv("HOME") && !strcmp(resolved, getenv("HOME")))) {
    close(fd);
    errno = EPERM;
    return -1;
  }
  for (unsigned i = 0; i < 2; i++) {
    int sub = openat(fd, i ? "tmp" : "proc",
                     O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (sub < 0) {
      close(fd);
      return -1;
    }
    close(sub);
  }
  return fd;
}
static void usage(void) {
  puts("holdfast 1.0.0 - rootless single-process Linux containers\nusage: "
       "holdfast [--timeout 1..30] ROOTFS -- /absolute/program "
       "[args...]\nROOTFS must be a trusted, quiescent, caller-owned directory "
       "with real proc/ and tmp/.\nNo root, OCI images, network, forks, "
       "threads or insecure fallback. Linux x86-64, kernel >=5.9.\nFixed "
       "policy: read-only root; 16MiB /tmp; no capabilities; seccomp "
       "allowlist; 256MiB AS; 2s CPU; 1MiB/file.\nDefault wall timeout 5s. "
       "STDIN is null; STDOUT/STDERR are intentionally inherited.\nExit: "
       "payload status, 124 timeout, 125 setup/input failure. These can "
       "overlap payload exit codes.");
}
int main(int argc, char **argv) {
  if (argc == 2 &&
      (!strcmp(argv[1], "--help") || !strcmp(argv[1], "--version"))) {
    usage();
    return 0;
  }
  unsigned timeout = 5;
  int pos = 1;
  if (argc > 2 && !strcmp(argv[pos], "--timeout")) {
    char *end;
    errno = 0;
    unsigned long v = strtoul(argv[pos + 1], &end, 10);
    if (errno || !*argv[pos + 1] || *end || v < 1 || v > 30) {
      fprintf(stderr, "holdfast: timeout must be 1..30 seconds\n");
      return 125;
    }
    timeout = (unsigned)v;
    pos += 2;
  }
  if (argc < pos + 3 || strcmp(argv[pos + 1], "--") ||
      argv[pos + 2][0] != '/' || strlen(argv[pos + 2]) >= PATH_MAX) {
    usage();
    return 125;
  }
  if (getuid() == 0 || geteuid() != getuid() || getegid() != getgid()) {
    fprintf(stderr,
            "holdfast: run as an ordinary user, never root or setuid/setgid\n");
    return 125;
  }
  if (fcntl(1, F_GETFD) < 0 || fcntl(2, F_GETFD) < 0)
    return 125;
  double deadline = seconds() + timeout;
  struct config c = {0};
  c.args = &argv[pos + 2];
  c.root = root_open(argv[pos]);
  need(realpath(argv[pos], c.rootpath) != NULL, "root path");
  if (c.root < 0) {
    perror("holdfast: invalid rootfs");
    return 125;
  }
  c.nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  need(c.nullfd >= 0, "null input");
  need(pipe2(c.go, O_CLOEXEC) == 0 && pipe2(c.ready, O_CLOEXEC) == 0,
       "synchronization pipes");
  sigset_t empty;
  sigemptyset(&empty);
  need(sigprocmask(SIG_SETMASK, &empty, NULL) == 0, "signal mask");
  struct sigaction a = {0};
  a.sa_handler = SIG_DFL;
  sigemptyset(&a.sa_mask);
  need(sigaction(SIGCHLD, &a, NULL) == 0, "SIGCHLD");
  a.sa_handler = SIG_IGN;
  need(sigaction(SIGPIPE, &a, NULL) == 0, "SIGPIPE");
  handler(SIGTERM);
  handler(SIGINT);
  handler(SIGHUP);
  handler(SIGQUIT);
  const size_t stacksize = 1024 * 1024;
  void *stack = malloc(stacksize);
  need(stack != NULL, "init stack");
  pid_t child = clone(init, (char *)stack + stacksize,
                      CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
                          CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | SIGCHLD,
                      &c);
  if (child < 0) {
    fprintf(stderr,
            "holdfast: namespaces unavailable: %s; no payload executed\n",
            strerror(errno));
    free(stack);
    return 125;
  }
  close(c.go[0]);
  close(c.ready[1]);
  struct pollfd ready = {c.ready[0], POLLIN, 0};
  int polled;
  do {
    double left = deadline - seconds();
    polled = left > 0 ? poll(&ready, 1, (int)(left * 1000)) : 0;
  } while (polled < 0 && errno == EINTR);
  int okay = polled > 0 && read_byte(c.ready[0]);
  close(c.ready[0]);
  if (!okay) {
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return 125;
  }
  char mapping[96];
  snprintf(mapping, sizeof(mapping), "0 %lu 1\n", (unsigned long)getuid());
  map_file(child, "uid_map", mapping);
  map_file(child, "setgroups", "deny\n");
  snprintf(mapping, sizeof(mapping), "0 %lu 1\n", (unsigned long)getgid());
  map_file(child, "gid_map", mapping);
  send_byte(c.go[1]);
  close(c.go[1]);
  close(c.root);
  close(c.nullfd);
  int status = 0, timedout = 0;
  for (;;) {
    pid_t got = waitpid(child, &status, WNOHANG);
    if (got == child)
      break;
    if (got < 0 && errno != EINTR)
      die("wait container");
    if (signal_seen) {
      int sig = signal_seen;
      signal_seen = 0;
      kill(child, sig);
    }
    if (seconds() >= deadline) {
      timedout = 1;
      kill(child, SIGKILL);
      while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
      }
      break;
    }
    struct timespec pause = {0, 10000000};
    nanosleep(&pause, NULL);
  }
  free(stack);
  if (timedout) {
    fprintf(stderr, "holdfast: wall timeout after %us; namespace terminated\n",
            timeout);
    return 124;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
