/*
 * t4-fanotify-audit.c — 非特权 fanotify 审计可行性 + PERM 阻塞不可用性确认
 *
 * 判定：
 *   T4_AUDIT_PASS       → 非特权可做文件访问审计（文件灰名单的审计路径成立）
 *   T4_AUDIT_FAIL:*     → 审计也不可用，文件灰名单只剩 L-A 命令解析 + userns ro-bind
 *   T4_PERM_DENIED:*    → 阻塞式（FAN_OPEN_PERM）按预期被拒（"灰名单阻塞确认需
 *                         CAP_SYS_ADMIN、无 root 不可用"结论的实测确认）
 *   T4_PERM_UNEXPECTED_OK → 非特权 PERM 居然可用，重大发现，请回报
 *
 * 构建：gcc -O2 -o t4 t4-fanotify-audit.c
 * 运行：./t4
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/fanotify.h>

int main(void)
{
    const char *dir = "/home/sandbox";
    const char *probe = "/home/sandbox/t4_probe.txt";

    /* 0. 造探测文件 */
    int pf = open(probe, O_CREAT | O_WRONLY, 0600);
    if (pf < 0) { printf("T4_SETUP_FAIL: %s\n", strerror(errno)); return 1; }
    (void)write(pf, "x", 1);
    close(pf);

    /* 1. 通知类（非特权预期可用）：监控目录下子文件的 OPEN */
    int fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
                           O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("T4_AUDIT_FAIL: fanotify_init(NOTIF): %s\n", strerror(errno));
    } else if (fanotify_mark(fd, FAN_MARK_ADD,
                             FAN_OPEN | FAN_EVENT_ON_CHILD, AT_FDCWD, dir) < 0) {
        printf("T4_AUDIT_FAIL: mark inode: %s\n", strerror(errno));
        close(fd);
    } else {
        /* 2. 子进程打开探测文件，父进程等事件 */
        pid_t pid = fork();
        if (pid == 0) {
            int f = open(probe, O_RDONLY);
            if (f >= 0) close(f);
            _exit(0);
        }
        int st;
        waitpid(pid, &st, 0);

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, 3000) <= 0) {
            puts("T4_AUDIT_FAIL: 3s 内未收到事件");
        } else {
            char buf[4096];
            ssize_t n = read(fd, buf, sizeof(buf));
            int seen = 0;
            struct fanotify_event_metadata *m = (void *)buf;
            for (; n > 0 && FAN_EVENT_OK(m, n); m = FAN_EVENT_NEXT(m, n)) {
                if (m->vers != FANOTIFY_METADATA_VERSION) break;
                if (m->mask & FAN_OPEN) {
                    seen = 1;
                    printf("event FAN_OPEN pid=%d\n", m->pid);
                }
                if (m->fd >= 0) close(m->fd);
            }
            puts(seen ? "T4_AUDIT_PASS" : "T4_AUDIT_FAIL: 未收到 FAN_OPEN");
        }
        close(fd);
    }

    /* 3. 阻塞式（预期 EPERM） */
    int fd2 = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC,
                            O_RDONLY | O_CLOEXEC);
    if (fd2 < 0) {
        printf("T4_PERM_DENIED: init(CONTENT): %s\n", strerror(errno));
    } else if (fanotify_mark(fd2, FAN_MARK_ADD,
                             FAN_OPEN_PERM | FAN_EVENT_ON_CHILD,
                             AT_FDCWD, dir) < 0) {
        printf("T4_PERM_DENIED: mark FAN_OPEN_PERM: %s\n", strerror(errno));
        close(fd2);
    } else {
        puts("T4_PERM_UNEXPECTED_OK");
        close(fd2);
    }

    unlink(probe);
    return 0;
}
