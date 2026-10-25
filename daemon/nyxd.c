#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>

#define SOCK_PATH  "/data/adb/nyx/nyx.sock"
#define ALLOW_PATH "/data/adb/nyx/allow"
#define DEV_PATH   "/dev/rt_kpm"
#define RT_MAGIC   'R'

struct rw_req { pid_t pid; uintptr_t addr; void *buf; size_t size; };
#define IOCTL_READ  _IOWR(RT_MAGIC, 1, struct rw_req)
#define IOCTL_WRITE _IOWR(RT_MAGIC, 2, struct rw_req)

typedef struct { uint32_t op, pad; uint64_t addr, buf, size; } req_t;
static int g_fd = -1;

static int is_allowed(uid_t uid) {
    FILE *f = fopen(ALLOW_PATH, "r"); if (!f) return 0;
    char line[64]; int ok = 0;
    while (fgets(line, sizeof(line), f)) if ((uid_t)atoi(line) == uid) { ok = 1; break; }
    fclose(f); return ok;
}

static void *conn_thread(void *arg) {
    int c = (int)(intptr_t)arg;
    struct ucred cred; socklen_t cl = sizeof(cred);
    uid_t uid = (uid_t)-1;
    if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cred, &cl) == 0) uid = cred.uid;
    if (!is_allowed(uid)) { req_t deny = {0xFFFFFFFF, 0, 0, 0, 0}; write(c, &deny, sizeof(deny)); close(c); return NULL; }
    
    static __thread uint8_t tls_buf[1 << 20];
    for (;;) {
        req_t r; if (read(c, &r, sizeof(r)) <= 0) break;
        pid_t pid = (pid_t)(r.size >> 32); size_t size = (size_t)(uint32_t)r.size;
        if (size > sizeof(tls_buf)) size = sizeof(tls_buf);
        struct rw_req ireq = { .pid = pid, .addr = r.addr, .buf = tls_buf, .size = size };

        if (r.op == 0) {
            if (ioctl(g_fd, IOCTL_READ, &ireq) < 0) ireq.size = 0;
            r.addr = ireq.size; 
            if (write(c, &r, sizeof(r)) != sizeof(r)) break;
            if (ireq.size > 0 && write(c, tls_buf, ireq.size) != ireq.size) break;
        } else if (r.op == 1) {
            if (read(c, tls_buf, size) != (ssize_t)size) break;
            if (ioctl(g_fd, IOCTL_WRITE, &ireq) < 0) ireq.size = 0;
            r.addr = ireq.size; 
            if (write(c, &r, sizeof(r)) != sizeof(r)) break;
        }
    }
    close(c); return NULL;
}

int main(void) {
    mkdir("/data/adb/nyx", 0700);
    g_fd = open(DEV_PATH, O_RDWR); if (g_fd < 0) return 1;
    unlink(SOCK_PATH);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    strncpy(a.sun_path, SOCK_PATH, sizeof(a.sun_path) - 1);
    bind(s, (void *)&a, sizeof(a)); chmod(SOCK_PATH, 0666); listen(s, 16);
    for (;;) { int c = accept(s, NULL, NULL); pthread_t t; pthread_create(&t, NULL, conn_thread, (void *)(intptr_t)c); pthread_detach(t); }
}
