/*
 * t9-seccomp-notify.c — Broker v2 L-C 可行性验证（非特权 seccomp user notification）
 *
 * 验证链：prctl(PR_SET_NO_NEW_PRIVS) → seccomp(NEW_LISTENER) 装 filter
 *         （execve/execveat → RET_USER_NOTIF，其余 ALLOW）→ fork 子进程 execve
 *         → 父进程（Broker 角色）收到通知并 CONTINUE 放行 → 子进程正常执行。
 *
 * 判定：输出 T9_PASS 即"无 root 下可同步拦截子进程 execve"成立；
 *       filter 跨 exec/fork 继承且目标不可移除（nnp），把 filter 里的
 *       系统调用号扩展到 connect/bind/listen 即是 L-C 的完整形态。
 *
 * 构建：gcc -O2 -o t9 t9-seccomp-notify.c
 * 运行：./t9
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <poll.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

/* 头文件兜底（openEuler 5.10 头文件一般都有，缺了用常量） */
#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xC00000B7U   /* EM_AARCH64|LE|64BIT */
#endif
#ifndef SYS_seccomp
#define SYS_seccomp 277                  /* aarch64 __NR_seccomp */
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOC_MAGIC       '!'
#define SECCOMP_IOCTL_NOTIF_RECV  _IOWR(SECCOMP_IOC_MAGIC, 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND  _IOWR(SECCOMP_IOC_MAGIC, 1, struct seccomp_notif_resp)
#endif

static int install_filter(void)
{
    struct sock_filter filter[] = {
        /* 校验架构，防跨架构 syscall 号误匹配 */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        /* execve / execveat → 送 Broker 裁决；其余放行 */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                   SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

int main(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        printf("T9_FAIL: prctl(NO_NEW_PRIVS): %s\n", strerror(errno));
        return 1;
    }
    puts("STEP1 no_new_privs OK");

    int nfd = install_filter();
    if (nfd < 0) {
        printf("T9_FAIL: seccomp NEW_LISTENER: %s "
               "(errno=%d，EPERM=容器禁用非特权 seccomp-notify)\n",
               strerror(errno), errno);
        return 1;
    }
    printf("STEP2 filter installed, notify fd=%d\n", nfd);

    pid_t pid = fork();
    if (pid == 0) {
        execlp("echo", "echo",
               "STEP5 child execve ran — filter 跨 exec 继承且被 Broker CONTINUE 放行",
               NULL);
        _exit(127);
    }

    struct pollfd pfd = { .fd = nfd, .events = POLLIN };
    if (poll(&pfd, 1, 5000) <= 0) {
        puts("T9_FAIL: 5s 内未收到 execve 通知（filter 未生效或未继承）");
        kill(pid, SIGKILL);
        return 1;
    }

    struct seccomp_notif req;
    struct seccomp_notif_resp resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));

    if (ioctl(nfd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
        printf("T9_FAIL: NOTIF_RECV: %s\n", strerror(errno));
        return 1;
    }
    printf("STEP3 notification: pid=%d nr=%d (%s)\n",
           req.pid, req.data.nr, req.data.nr == __NR_execve ? "execve" : "execveat");

    resp.id = req.id;
    resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;   /* 交还内核继续执行 */
    if (ioctl(nfd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        printf("T9_FAIL: NOTIF_SEND: %s\n", strerror(errno));
        return 1;
    }
    puts("STEP4 responded CONTINUE");

    int st;
    waitpid(pid, &st, 0);
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        puts("T9_PASS");
        return 0;
    }
    printf("T9_FAIL: child exit status=0x%x\n", st);
    return 1;
}
