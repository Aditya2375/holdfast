#define _GNU_SOURCE
#include "policy.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
extern char **environ;
static int failures;
static void check(int pass, const char *what) {
  printf("%s %s\n", pass ? "OK" : "FAIL", what);
  if (!pass)
    failures++;
}
static void denied(long result, const char *name) {
  check(result == -1 && errno == EPERM, name);
}
static void show(const char *path) {
  char buf[8192];
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    perror(path);
    exit(3);
  }
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = write(1, buf + off, (size_t)(n - off));
      if (w <= 0)
        exit(4);
      off += w;
    }
  }
  close(fd);
}
int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  const char *mode = argc > 1 ? argv[1] : "inspect";
  if (!strcmp(mode, "exit"))
    return argc > 2 ? atoi(argv[2]) : 0;
  if (!strcmp(mode, "sleep")) {
    puts("READY");
    sleep(20);
    return 0;
  }
  if (!strcmp(mode, "cpu")) {
    puts("READY");
    for (;;)
      __asm__ volatile("" ::: "memory");
  }
  if (!strcmp(mode, "x32")) {
    syscall(0x40000000UL | SYS_getpid);
    return 99;
  }
  if (!strcmp(mode, "i386")) {
    __asm__ volatile("int $0x80" ::"a"(20) : "memory");
    return 99;
  }
  if (!strcmp(mode, "args")) {
    for (int i = 2; i < argc; i++)
      printf("arg=%s\n", argv[i]);
    return 0;
  }
  if (!strcmp(mode, "status")) {
    show("/proc/self/status");
    return 0;
  }
  if (!strcmp(mode, "mounts")) {
    show("/proc/self/mountinfo");
    return 0;
  }
  if (!strcmp(mode, "env")) {
    for (char **p = environ; *p; p++)
      puts(*p);
    return 0;
  }
  if (!strcmp(mode, "namespaces")) {
    const char *ns[] = {"user", "mnt", "pid", "net", "ipc", "uts"};
    for (int i = 0; i < 6; i++) {
      char path[64], out[128];
      snprintf(path, sizeof(path), "/proc/self/ns/%s", ns[i]);
      ssize_t n = readlink(path, out, sizeof(out) - 1);
      if (n < 0)
        return 3;
      out[n] = 0;
      printf("%s %s\n", ns[i], out);
    }
    return 0;
  }
  if (!strcmp(mode, "sentinel")) {
    if (argc < 3 || argv[2][0] != '/')
      return 3;
    check(access(argv[2], F_OK) < 0 && errno == ENOENT,
          "host path not present");
    char path[8192];
    int n = snprintf(path, sizeof(path), "/proc/1/root%s", argv[2]);
    check(n > 0 && (size_t)n < sizeof(path) && access(path, F_OK) < 0,
          "PID1 root is isolated");
    return failures;
  }
  if (!strcmp(mode, "fd")) {
    char b;
    check(read(0, &b, 1) == 0, "stdin is EOF");
    check(fcntl(55, F_GETFD) < 0 && errno == EBADF, "inherited fd 55 closed");
    return failures;
  }
  if (!strcmp(mode, "sweep")) {
#define NUMBER(name) __NR_##name,
    const long allowed[] = {HF_ALLOWED_SYSCALLS(NUMBER)};
#undef NUMBER
    unsigned tested = 0;
    for (long nr = 0; nr < 1024; nr++) {
      int permitted = 0;
      for (unsigned i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
        if (nr == allowed[i])
          permitted = 1;
      if (permitted)
        continue;
      errno = 0;
      long ret = syscall(nr, 0, 0, 0, 0, 0, 0);
      if (ret != -1 || (errno != EPERM && errno != ENOSYS)) {
        printf("FAIL syscall %ld result=%ld errno=%d\n", nr, ret, errno);
        return 1;
      }
      tested++;
    }
    printf("OK %u unlisted syscall numbers denied or unimplemented\n", tested);
    return 0;
  }
  if (!strcmp(mode, "deny")) {
    denied(syscall(SYS_fork), "fork");
    denied(syscall(SYS_vfork), "vfork");
    denied(syscall(SYS_clone, 0, 0, 0, 0, 0), "clone");
    denied(syscall(SYS_clone3, NULL, 0), "clone3");
    denied(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0), "socket");
    denied(syscall(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, NULL),
           "socketpair");
    denied(syscall(SYS_unshare, CLONE_NEWUSER), "unshare");
    denied(syscall(SYS_setns, -1, 0), "setns");
    denied(syscall(SYS_mount, "none", "/tmp", "tmpfs", 0, NULL), "mount");
    denied(syscall(SYS_umount2, "/tmp", 0), "umount2");
    denied(syscall(SYS_ptrace, 0, 0, 0, 0), "ptrace");
    denied(syscall(SYS_ioctl, 1, 0, 0), "ioctl");
    denied(syscall(SYS_bpf, 0, NULL, 0), "bpf");
    denied(syscall(SYS_keyctl, 0), "keyctl");
    denied(syscall(SYS_prctl, 0), "prctl");
    denied(syscall(SYS_capset, NULL, NULL), "capset");
    denied(syscall(SYS_kill, 1, SIGTERM), "kill");
    denied(syscall(SYS_chroot, "/tmp"), "chroot");
    denied(syscall(SYS_setuid, 0), "setuid");
    denied(syscall(SYS_reboot, 0, 0, 0, 0), "reboot");
    denied(syscall(SYS_pidfd_getfd, 0, 1, 0), "pidfd_getfd");
    denied(syscall(SYS_open_by_handle_at, 0, NULL, 0), "open_by_handle_at");
    return failures;
  }
  if (!strcmp(mode, "limits")) {
    const int kinds[] = {RLIMIT_AS,     RLIMIT_CPU,  RLIMIT_FSIZE,
                         RLIMIT_NOFILE, RLIMIT_CORE, RLIMIT_MEMLOCK};
    const unsigned long values[] = {
        256UL * 1024 * 1024, 2, 1024 * 1024, 64, 0, 0};
    for (unsigned i = 0; i < 6; i++) {
      struct rlimit r;
      check(syscall(SYS_getrlimit, kinds[i], &r) == 0 &&
                r.rlim_cur <= values[i] && r.rlim_max <= values[i],
            "hard and soft resource bound");
    }
    void *m = mmap(NULL, 512UL * 1024 * 1024, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(m == MAP_FAILED && errno == ENOMEM,
          "address-space allocation blocked");
    int fd = open("/tmp/file", O_CREAT | O_RDWR, 0600);
    check(fd >= 0, "tmp file created");
    check(ftruncate(fd, 1024 * 1024) == 0, "file at size bound");
    signal(SIGXFSZ, SIG_IGN);
    check(ftruncate(fd, 1024 * 1024 + 1) < 0 && errno == EFBIG,
          "file above size bound blocked");
    close(fd);
    int fds[100], n = 0;
    while (n < 100 && (fds[n] = open("/tmp/file", O_RDONLY)) >= 0)
      n++;
    check(n == 61 && errno == EMFILE, "file descriptor limit enforced");
    for (int i = 0; i < n; i++)
      close(fds[i]);
    return failures;
  }
  if (!strcmp(mode, "tmpfill")) {
    char b[65536] = {0};
    int fds[20], count = 0;
    size_t sum = 0;
    for (int i = 0; i < 20; i++) {
      char path[32];
      snprintf(path, sizeof(path), "/tmp/f%d", i);
      int fd = open(path, O_CREAT | O_RDWR, 0600);
      if (fd < 0)
        break;
      fds[count++] = fd;
      for (int j = 0; j < 16; j++) {
        ssize_t n = write(fd, b, sizeof(b));
        if (n > 0)
          sum += (size_t)n;
        else {
          check(errno == ENOSPC, "tmpfs total bound error");
          goto done;
        }
      }
    }
  done:
    check(sum == 16UL * 1024 * 1024, "tmpfs total is 16MiB");
    for (int i = 0; i < count; i++)
      close(fds[i]);
    return failures;
  }
  if (!strcmp(mode, "filesystem")) {
    int fd = open("/should-not-exist", O_CREAT | O_RDWR, 0600);
    check(fd < 0 && errno == EROFS, "root read-only");
    fd = open("/tmp/temporary", O_CREAT | O_RDWR, 0600);
    check(fd >= 0, "private tmp writable");
    if (fd >= 0) {
      check(write(fd, "hello", 5) == 5, "write temporary file");
      close(fd);
    }
    check(access("/dev", F_OK) < 0, "no host device tree");
    check(access("/sys", F_OK) < 0, "no sysfs tree");
    return failures;
  }
  struct utsname u;
  uname(&u);
  check(getuid() == 0 && getgid() == 0, "single mapped root identity");
  check(getpid() == 2 && getppid() == 1, "payload PID2, supervisor PID1");
  check(!strcmp(u.nodename, "holdfast"), "private hostname");
  show("/proc/self/status");
  return failures;
}
