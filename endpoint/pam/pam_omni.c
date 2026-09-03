/*
 * pam_omni.so — thin PAM module relaying the conversation to the
 * omni-enrollment daemon over a root-only Unix socket.
 *
 * It deliberately contains no networking, crypto, JSON, or credential
 * handling: every security-relevant step happens in the daemon. Protocol:
 * docs/LINUX-LOGIN-ARCHITECTURE.md §6.
 *
 *   auth    sufficient pam_omni.so [socket=/run/omni-enrollment/pam.sock]
 *   account sufficient pam_omni.so
 *
 * Unknown (non-Omni) users and a missing daemon yield PAM_IGNORE so local
 * accounts (root, omni-recovery) continue through pam_unix untouched.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define DEFAULT_SOCKET "/run/omni-enrollment/pam.sock"
#define LINE_MAX_LEN 4096

static const char *socket_path(int argc, const char **argv) {
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "socket=", 7) == 0) return argv[i] + 7;
    }
    return DEFAULT_SOCKET;
}

static int connect_daemon(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_line(FILE *out, const char *prefix, const char *text) {
    if (fprintf(out, "%s%s%s\n", prefix, text ? " " : "", text ? text : "") < 0) return -1;
    return fflush(out);
}

/* Runs one request/response conversation. Returns a PAM status. */
static int converse(pam_handle_t *pamh, const char *path, const char *request) {
    int fd = connect_daemon(path);
    if (fd < 0) {
        pam_syslog(pamh, LOG_WARNING, "omni daemon not reachable at %s: %m (ignoring)", path);
        return PAM_IGNORE;
    }
    FILE *in = fdopen(fd, "r");
    FILE *out = fdopen(dup(fd), "w");
    if (!in || !out) {
        close(fd);
        return PAM_IGNORE;
    }
    int status = PAM_AUTH_ERR;
    if (send_line(out, request, NULL) != 0) goto done;

    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, in)) > 0) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (line[0] == '\0') continue;
        char kind = line[0];
        const char *text = line[1] == ' ' ? line + 2 : line + 1;

        if (kind == 'I' || kind == 'W') {
            pam_prompt(pamh, kind == 'I' ? PAM_TEXT_INFO : PAM_ERROR_MSG, NULL, "%s", text);
        } else if (kind == 'P' || kind == 'E') {
            char *resp = NULL;
            int rc = pam_prompt(pamh, kind == 'P' ? PAM_PROMPT_ECHO_OFF : PAM_PROMPT_ECHO_ON, &resp, "%s", text);
            if (rc != PAM_SUCCESS || resp == NULL) {
                send_line(out, "A", "");
                status = PAM_CONV_ERR;
                free(resp);
                break;
            }
            /* Answers are single lines; strip anything that would break framing. */
            for (char *p = resp; *p; p++) if (*p == '\n' || *p == '\r') *p = ' ';
            int src = send_line(out, "A", resp);
            memset(resp, 0, strlen(resp));
            free(resp);
            if (src != 0) break;
        } else if (kind == 'R') {
            if (strncmp(text, "OK", 2) == 0) status = PAM_SUCCESS;
            else if (strncmp(text, "IGNORE", 6) == 0) status = PAM_IGNORE;
            else {
                status = PAM_AUTH_ERR;
                pam_syslog(pamh, LOG_NOTICE, "omni: %s", text);
            }
            break;
        }
    }
    free(line);
done:
    fclose(out);
    fclose(in);
    return status;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL || *user == '\0') return PAM_USER_UNKNOWN;
    const char *service = NULL, *rhost = NULL;
    pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);

    char req[LINE_MAX_LEN];
    snprintf(req, sizeof req, "AUTH %s %s %s", user, service ? service : "-", (rhost && *rhost) ? rhost : "-");
    /* Refuse anything that would break line framing. */
    for (char *p = req; *p; p++) if (*p == '\n' || *p == '\r') return PAM_AUTH_ERR;
    return converse(pamh, socket_path(argc, argv), req);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) return PAM_USER_UNKNOWN;
    const char *service = NULL;
    pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    char req[LINE_MAX_LEN];
    snprintf(req, sizeof req, "ACCT %s %s", user, service ? service : "-");
    for (char *p = req; *p; p++) if (*p == '\n' || *p == '\r') return PAM_AUTH_ERR;
    int rc = converse(pamh, socket_path(argc, argv), req);
    return rc == PAM_AUTH_ERR ? PAM_ACCT_EXPIRED : rc;
}
