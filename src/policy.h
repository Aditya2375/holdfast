#ifndef HOLDFAST_POLICY_H
#define HOLDFAST_POLICY_H
#define HF_RAM_BYTES (256UL * 1024 * 1024)
#define HF_FILE_BYTES (1024UL * 1024)
#define HF_CPU_SECONDS 2
#define HF_NOFILE 64
/* x86-64 only. Everything not listed returns EPERM. No process creation or
 * sockets. */
#define HF_ALLOWED_SYSCALLS(X)                                                 \
  X(read)                                                                      \
  X(write)                                                                     \
  X(readv) X(writev) X(close) X(lseek) X(openat) X(newfstatat) X(fstat)        \
      X(stat) X(lstat) X(access) X(faccessat) X(faccessat2) X(readlink) X(     \
          readlinkat) X(getdents64) X(getcwd) X(chdir) X(mmap) X(mprotect)     \
          X(munmap) X(mremap) X(madvise) X(brk) X(rt_sigaction) X(             \
              rt_sigprocmask) X(rt_sigreturn) X(sigaltstack) X(exit)           \
              X(exit_group) X(execve) X(arch_prctl) X(set_tid_address) X(      \
                  set_robust_list) X(rseq) X(getpid) X(getppid) X(gettid)      \
                  X(getuid) X(geteuid) X(getgid) X(getegid) X(getgroups) X(    \
                      uname) X(clock_gettime) X(clock_nanosleep) X(nanosleep)  \
                      X(gettimeofday) X(time) X(getrandom) X(futex)            \
                          X(sched_getaffinity) X(sched_yield) X(getrlimit)     \
                              X(getrusage) X(sysinfo) X(statfs) X(fstatfs)     \
                                  X(fcntl) X(dup) X(dup2) X(dup3) X(mkdir)     \
                                      X(mkdirat) X(unlink) X(unlinkat)         \
                                          X(rename) X(renameat) X(renameat2)   \
                                              X(fsync) X(fdatasync)            \
                                                  X(ftruncate) X(truncate)     \
                                                      X(umask) X(chmod)        \
                                                          X(fchmod)            \
                                                              X(fchmodat)
#endif
