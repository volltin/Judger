#include <stdio.h>
#include <seccomp.h>

#include "../runner.h"


int python_seccomp_rules(struct config *_config) {
    int syscalls_whitelist[] = {SCMP_SYS(read), SCMP_SYS(fstat),
                                SCMP_SYS(mmap), SCMP_SYS(mprotect),
                                SCMP_SYS(munmap), SCMP_SYS(open),
                                SCMP_SYS(arch_prctl), SCMP_SYS(brk),
                                SCMP_SYS(access), SCMP_SYS(exit_group),
                                SCMP_SYS(close), SCMP_SYS(readlink),
                                SCMP_SYS(uname),
								// add for python
								SCMP_SYS(rt_sigprocmask),
								SCMP_SYS(rt_sigaction),
								SCMP_SYS(rt_sigreturn),
								SCMP_SYS(rt_sigpending),
								SCMP_SYS(sigaltstack),
								SCMP_SYS(stat),
								SCMP_SYS(lstat),
								SCMP_SYS(exit),
								SCMP_SYS(futex),
								SCMP_SYS(getrlimit),
								SCMP_SYS(set_tid_address),
								SCMP_SYS(set_robust_list),
								SCMP_SYS(getcwd),
								SCMP_SYS(getuid),
								SCMP_SYS(getgid),
								SCMP_SYS(geteuid),
								SCMP_SYS(getegid),
								SCMP_SYS(openat),
								SCMP_SYS(getdents),
								SCMP_SYS(getdents64),
								SCMP_SYS(readv),
								SCMP_SYS(writev),
								SCMP_SYS(unlinkat),
								SCMP_SYS(readlinkat),
								SCMP_SYS(dup),
								SCMP_SYS(dup2),
								SCMP_SYS(dup3),
								SCMP_SYS(mremap),
								SCMP_SYS(msync),
								SCMP_SYS(mincore),
								SCMP_SYS(madvise),
								
								
								// ioctl
								SCMP_SYS(ioctl),
								SCMP_SYS(fcntl),
								
								};
    int syscalls_whitelist_length = sizeof(syscalls_whitelist) / sizeof(int);
    scmp_filter_ctx ctx = NULL;
    // load seccomp rules
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        return LOAD_SECCOMP_FAILED;
    }
    for (int i = 0; i < syscalls_whitelist_length; i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscalls_whitelist[i], 0) != 0) {
            return LOAD_SECCOMP_FAILED;
        }
    }
	
    // add extra rule for execve
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 1, SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)("/usr/bin/python"))) != 0) {
        return LOAD_SECCOMP_FAILED;
    }
    // only fd 0 1 2 are allowed
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_LE, 2)) != 0) {
       return LOAD_SECCOMP_FAILED;
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 1, SCMP_A0(SCMP_CMP_LE, 3)) != 0) {
       return LOAD_SECCOMP_FAILED;
    }
    if (seccomp_load(ctx) != 0) {
        return LOAD_SECCOMP_FAILED;
    }
    seccomp_release(ctx);
    return 0;
}