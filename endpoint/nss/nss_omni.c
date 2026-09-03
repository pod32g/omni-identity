/*
 * libnss_omni — glibc NSS source that resolves Omni Identity users through
 * the omni-enrollment daemon's read-only identity socket, so a user can log
 * in over SSH before ever having had a local account (sshd looks the name up
 * before PAM runs). Answers come from the daemon's local cache, or — for a
 * name it has never seen, while online — from a single lookup at Omni.
 *
 *   /etc/nsswitch.conf:   passwd: files omni      group: files omni
 *
 * Protocol (docs/LINUX-LOGIN-ARCHITECTURE.md §6): one request line, one reply
 * line. The module holds no state, opens no network connection, and fails
 * closed to NSS_STATUS_UNAVAIL (the next source is consulted) when the
 * daemon is not running.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <nss.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/run/omni-enrollment/nss.sock"
#define REPLY_MAX 2048

/* query sends one line and reads one reply line into reply (NUL-terminated).
 * Returns 0 on success, -1 when the daemon is unreachable. */
static int query(const char *req, char *reply, size_t cap) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { close(fd); return -1; }
    size_t n = strlen(req);
    if (write(fd, req, n) != (ssize_t)n || write(fd, "\n", 1) != 1) { close(fd); return -1; }
    size_t got = 0;
    while (got + 1 < cap) {
        ssize_t r = read(fd, reply + got, cap - got - 1);
        if (r <= 0) break;
        got += (size_t)r;
        if (memchr(reply, '\n', got)) break;
    }
    close(fd);
    if (got == 0) return -1;
    reply[got] = '\0';
    char *nl = strchr(reply, '\n');
    if (nl) *nl = '\0';
    return 0;
}

/* place copies s into the caller's buffer, returning the pointer or NULL if full. */
static char *place(const char *s, char **buf, size_t *left) {
    size_t n = strlen(s) + 1;
    if (n > *left) return NULL;
    char *out = *buf;
    memcpy(out, s, n);
    *buf += n;
    *left -= n;
    return out;
}

/* Reply: "PW <name> <uid> <gid> <home> <shell> <gecos...>" */
static enum nss_status fill_passwd(char *reply, struct passwd *pwd, char *buffer, size_t buflen, int *errnop) {
    if (strncmp(reply, "PW ", 3) != 0) return NSS_STATUS_NOTFOUND;
    char *save = NULL;
    char *name = strtok_r(reply + 3, " ", &save);
    char *uid = strtok_r(NULL, " ", &save);
    char *gid = strtok_r(NULL, " ", &save);
    char *home = strtok_r(NULL, " ", &save);
    char *shell = strtok_r(NULL, " ", &save);
    char *gecos = save ? save : "";
    if (!name || !uid || !gid || !home || !shell) return NSS_STATUS_NOTFOUND;
    char *buf = buffer;
    size_t left = buflen;
    pwd->pw_name = place(name, &buf, &left);
    pwd->pw_passwd = place("*", &buf, &left);
    pwd->pw_gecos = place(gecos, &buf, &left);
    pwd->pw_dir = place(home, &buf, &left);
    pwd->pw_shell = place(shell, &buf, &left);
    if (!pwd->pw_name || !pwd->pw_passwd || !pwd->pw_gecos || !pwd->pw_dir || !pwd->pw_shell) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    pwd->pw_uid = (uid_t)strtoul(uid, NULL, 10);
    pwd->pw_gid = (gid_t)strtoul(gid, NULL, 10);
    return NSS_STATUS_SUCCESS;
}

/* Reply: "GR <name> <gid>" — the user's private group with the user as sole member. */
static enum nss_status fill_group(char *reply, struct group *grp, char *buffer, size_t buflen, int *errnop) {
    if (strncmp(reply, "GR ", 3) != 0) return NSS_STATUS_NOTFOUND;
    char *save = NULL;
    char *name = strtok_r(reply + 3, " ", &save);
    char *gid = strtok_r(NULL, " ", &save);
    if (!name || !gid) return NSS_STATUS_NOTFOUND;
    char *buf = buffer;
    size_t left = buflen;
    /* members array must be pointer-aligned */
    uintptr_t pad = ((uintptr_t)buf) % sizeof(char *);
    if (pad) { pad = sizeof(char *) - pad; if (pad > left) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; } buf += pad; left -= pad; }
    if (left < 2 * sizeof(char *)) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
    char **members = (char **)buf;
    buf += 2 * sizeof(char *);
    left -= 2 * sizeof(char *);
    grp->gr_name = place(name, &buf, &left);
    grp->gr_passwd = place("*", &buf, &left);
    members[0] = place(name, &buf, &left);
    members[1] = NULL;
    if (!grp->gr_name || !grp->gr_passwd || !members[0]) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
    grp->gr_gid = (gid_t)strtoul(gid, NULL, 10);
    grp->gr_mem = members;
    return NSS_STATUS_SUCCESS;
}

static int valid_name(const char *name) {
    size_t n = strlen(name);
    if (n == 0 || n > 32) return 0;
    for (const char *p = name; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')) return 0;
    }
    return 1;
}

enum nss_status _nss_omni_getpwnam_r(const char *name, struct passwd *pwd, char *buffer, size_t buflen, int *errnop) {
    if (!valid_name(name)) return NSS_STATUS_NOTFOUND;
    char req[64], reply[REPLY_MAX];
    snprintf(req, sizeof req, "PWNAM %s", name);
    if (query(req, reply, sizeof reply) != 0) return NSS_STATUS_UNAVAIL;
    return fill_passwd(reply, pwd, buffer, buflen, errnop);
}

enum nss_status _nss_omni_getpwuid_r(uid_t uid, struct passwd *pwd, char *buffer, size_t buflen, int *errnop) {
    char req[64], reply[REPLY_MAX];
    snprintf(req, sizeof req, "PWUID %lu", (unsigned long)uid);
    if (query(req, reply, sizeof reply) != 0) return NSS_STATUS_UNAVAIL;
    return fill_passwd(reply, pwd, buffer, buflen, errnop);
}

enum nss_status _nss_omni_getgrnam_r(const char *name, struct group *grp, char *buffer, size_t buflen, int *errnop) {
    if (!valid_name(name)) return NSS_STATUS_NOTFOUND;
    char req[64], reply[REPLY_MAX];
    snprintf(req, sizeof req, "GRNAM %s", name);
    if (query(req, reply, sizeof reply) != 0) return NSS_STATUS_UNAVAIL;
    return fill_group(reply, grp, buffer, buflen, errnop);
}

enum nss_status _nss_omni_getgrgid_r(gid_t gid, struct group *grp, char *buffer, size_t buflen, int *errnop) {
    char req[64], reply[REPLY_MAX];
    snprintf(req, sizeof req, "GRGID %lu", (unsigned long)gid);
    if (query(req, reply, sizeof reply) != 0) return NSS_STATUS_UNAVAIL;
    return fill_group(reply, grp, buffer, buflen, errnop);
}
