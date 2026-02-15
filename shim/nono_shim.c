/**
 * nono DYLD interposition shim for macOS
 *
 * Loaded via DYLD_INSERT_LIBRARIES into the sandboxed child process.
 * Interposes open() and openat() to detect EPERM from Seatbelt denials,
 * then requests capability expansion from the supervisor via the IPC socket.
 *
 * Protocol: length-prefixed JSON matching SupervisorSocket framing.
 *   Send: {"ShimRequest":{"path":"...","access":"..."}}
 *   Recv: {"ExtensionToken":{"token":"...","path":"...","access":"..."}}
 *      or {"Decision":{"request_id":"...","decision":"Denied"|"Timeout"|...}}
 *
 * Thread safety: A global pthread_mutex serializes all IPC. This is acceptable
 * since the supervisor response time (human approval) dominates.
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* sandbox extension API -- not in public <sandbox.h>, declared here */
extern int64_t sandbox_extension_consume(const char *token);
extern int sandbox_extension_release(int64_t handle);

/* Maximum number of consumed extension handles to track */
#define MAX_EXT_HANDLES 256

/* Maximum path length in JSON messages */
#define MAX_PATH_LEN 4096

/* Maximum JSON message size (matches SupervisorSocket MAX_MESSAGE_SIZE) */
#define MAX_MSG_SIZE (64 * 1024)

/* Supervisor socket fd (set from NONO_SUPERVISOR_FD env var) */
static int g_supervisor_fd = -1;

/* Global mutex for socket serialization */
static pthread_mutex_t g_shim_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Consumed extension handles for cleanup */
static int64_t g_ext_handles[MAX_EXT_HANDLES];
static int g_ext_handle_count = 0;

/* Track initialization state */
static int g_initialized = 0;

/* Original function pointers (resolved via dlsym) */
static int (*real_open)(const char *, int, ...);
static int (*real_openat)(int, const char *, int, ...);

/**
 * Write exactly `len` bytes to fd, handling partial writes.
 * Returns 0 on success, -1 on error.
 */
static int write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        remaining -= (size_t)n;
    }
    return 0;
}

/**
 * Read exactly `len` bytes from fd, handling partial reads.
 * Returns 0 on success, -1 on error.
 */
static int read_all(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            /* EOF - supervisor closed connection */
            return -1;
        }
        p += n;
        remaining -= (size_t)n;
    }
    return 0;
}

/**
 * Escape a path for JSON string embedding.
 * Handles backslash and double-quote. Output buffer must be at least 2*len+1.
 * Returns length of escaped string.
 */
static size_t json_escape(char *out, size_t out_size, const char *in) {
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j + 2 < out_size; i++) {
        char c = in[i];
        if (c == '\\' || c == '"') {
            out[j++] = '\\';
        }
        /* Control characters: escape as \uXXXX */
        if ((unsigned char)c < 0x20) {
            int written = snprintf(out + j, out_size - j, "\\u%04x", (unsigned char)c);
            if (written > 0) j += (size_t)written;
            continue;
        }
        out[j++] = c;
    }
    out[j] = '\0';
    return j;
}

/**
 * Determine access mode string from open flags.
 */
static const char *access_from_flags(int flags) {
    int accmode = flags & O_ACCMODE;
    if (accmode == O_RDONLY) return "Read";
    if (accmode == O_WRONLY) return "Write";
    return "ReadWrite";  /* O_RDWR or unknown */
}

/**
 * Find a simple JSON string value by key in a buffer.
 * This is a minimal parser -- sufficient for our well-known response format.
 * Returns pointer to start of value (after opening quote), or NULL.
 * Sets *value_len to the length of the value (excluding quotes).
 */
static const char *json_find_string(const char *json, size_t json_len,
                                     const char *key, size_t *value_len) {
    /* Search for "key":" pattern */
    size_t key_len = strlen(key);
    /* We need: "key":"value" -> search for "key":" */
    for (size_t i = 0; i + key_len + 4 < json_len; i++) {
        if (json[i] == '"' &&
            memcmp(json + i + 1, key, key_len) == 0 &&
            json[i + 1 + key_len] == '"' &&
            json[i + 2 + key_len] == ':' &&
            json[i + 3 + key_len] == '"') {
            /* Found "key":" -- value starts after the quote */
            const char *val_start = json + i + 4 + key_len;
            const char *val_end = val_start;
            /* Find closing quote (handle escaped quotes) */
            while ((size_t)(val_end - json) < json_len) {
                if (*val_end == '"' && (val_end == val_start || *(val_end - 1) != '\\')) {
                    break;
                }
                val_end++;
            }
            *value_len = (size_t)(val_end - val_start);
            return val_start;
        }
    }
    return NULL;
}

/**
 * Store an extension handle for cleanup.
 */
static void track_handle(int64_t handle) {
    if (handle >= 0 && g_ext_handle_count < MAX_EXT_HANDLES) {
        g_ext_handles[g_ext_handle_count++] = handle;
    }
}

/**
 * Send a ShimRequest to the supervisor and receive the response.
 * Caller must hold g_shim_mutex.
 *
 * Returns:
 *   1  if an extension token was consumed (caller should retry the syscall)
 *   0  if denied/timeout/error (caller should return original errno)
 */
static int request_expansion(const char *path, int flags) {
    if (g_supervisor_fd < 0) return 0;

    const char *access = access_from_flags(flags);

    /* Build JSON: {"ShimRequest":{"path":"...","access":"..."}} */
    char escaped_path[MAX_PATH_LEN * 2 + 1];
    json_escape(escaped_path, sizeof(escaped_path), path);

    char msg_buf[MAX_MSG_SIZE];
    int msg_len = snprintf(msg_buf, sizeof(msg_buf),
        "{\"ShimRequest\":{\"path\":\"%s\",\"access\":\"%s\"}}",
        escaped_path, access);

    if (msg_len < 0 || (size_t)msg_len >= sizeof(msg_buf)) return 0;

    /* Write length-prefixed frame: [4 bytes u32 BE][JSON] */
    uint32_t frame_len = htonl((uint32_t)msg_len);
    if (write_all(g_supervisor_fd, &frame_len, 4) < 0) return 0;
    if (write_all(g_supervisor_fd, msg_buf, (size_t)msg_len) < 0) return 0;

    /* Read response frame */
    uint32_t resp_len_be;
    if (read_all(g_supervisor_fd, &resp_len_be, 4) < 0) return 0;

    uint32_t resp_len = ntohl(resp_len_be);
    if (resp_len == 0 || resp_len > MAX_MSG_SIZE) return 0;

    char resp_buf[MAX_MSG_SIZE];
    if (read_all(g_supervisor_fd, resp_buf, resp_len) < 0) return 0;

    /* Check if response is an ExtensionToken */
    size_t token_len = 0;
    const char *token_val = json_find_string(resp_buf, resp_len, "token", &token_len);
    if (token_val != NULL && token_len > 0 && token_len < MAX_MSG_SIZE - 1) {
        /* Extract token into null-terminated string */
        char token[MAX_MSG_SIZE];
        memcpy(token, token_val, token_len);
        token[token_len] = '\0';

        /* Consume the extension token to expand sandbox access */
        int64_t handle = sandbox_extension_consume(token);
        if (handle >= 0) {
            track_handle(handle);
            return 1;  /* Success -- caller should retry */
        }
        /* sandbox_extension_consume failed -- fall through to deny */
    }

    /* Response was Decision (Denied/Timeout/Granted-without-token) or parse failed */
    return 0;
}

/**
 * Check if an errno indicates a Seatbelt sandbox denial.
 * Seatbelt returns EPERM (Operation not permitted) for default denials
 * and EACCES (Permission denied) for some explicit deny rules.
 * The shim must intercept both.
 */
static int is_sandbox_denial(int err) {
    return err == EACCES || err == EPERM;
}

/**
 * Ensure real_open is resolved. Called lazily because __DATA,__interpose
 * activates before constructors run -- if any dylib constructor calls open(),
 * we'd crash on a NULL pointer without this guard.
 */
static int ensure_real_open(void) {
    if (real_open) return 1;
    real_open = dlsym(RTLD_NEXT, "open");
    return real_open != NULL;
}

static int ensure_real_openat(void) {
    if (real_openat) return 1;
    real_openat = dlsym(RTLD_NEXT, "openat");
    return real_openat != NULL;
}

/* Interposed open() */
static int shim_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    if (!ensure_real_open()) {
        errno = ENOSYS;
        return -1;
    }

    int result = real_open(path, flags, mode);
    if (result >= 0 || !is_sandbox_denial(errno)) {
        return result;
    }

    /* EPERM/EACCES from Seatbelt -- attempt expansion */
    if (!g_initialized || g_supervisor_fd < 0) {
        return -1;
    }

    int saved_errno = errno;

    pthread_mutex_lock(&g_shim_mutex);
    int expanded = request_expansion(path, flags);
    pthread_mutex_unlock(&g_shim_mutex);

    if (expanded) {
        /* Extension consumed -- retry the original call */
        result = real_open(path, flags, mode);
        if (result < 0) {
            /* Retry failed despite extension -- restore original errno */
            errno = saved_errno;
        }
        return result;
    }

    /* Denied -- restore original errno */
    errno = saved_errno;
    return -1;
}

/* Interposed openat() */
static int shim_openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    if (!ensure_real_openat()) {
        errno = ENOSYS;
        return -1;
    }

    int result = real_openat(dirfd, path, flags, mode);
    if (result >= 0 || !is_sandbox_denial(errno)) {
        return result;
    }

    /* EPERM/EACCES from Seatbelt -- attempt expansion */
    if (!g_initialized || g_supervisor_fd < 0) {
        return -1;
    }

    int saved_errno = errno;

    /* For relative paths with dirfd, resolve to absolute for the supervisor */
    char resolved[MAX_PATH_LEN];
    const char *request_path = path;

    if (path[0] != '/' && dirfd != AT_FDCWD) {
        /* Resolve dirfd to a path using fcntl F_GETPATH */
        char dirpath[MAX_PATH_LEN];
        if (fcntl(dirfd, F_GETPATH, dirpath) >= 0) {
            int n = snprintf(resolved, sizeof(resolved), "%s/%s", dirpath, path);
            if (n > 0 && (size_t)n < sizeof(resolved)) {
                request_path = resolved;
            }
        }
    }

    pthread_mutex_lock(&g_shim_mutex);
    int expanded = request_expansion(request_path, flags);
    pthread_mutex_unlock(&g_shim_mutex);

    if (expanded) {
        result = real_openat(dirfd, path, flags, mode);
        if (result < 0) {
            errno = saved_errno;
        }
        return result;
    }

    errno = saved_errno;
    return -1;
}

/* DYLD interposition structs */
typedef struct {
    const void *replacement;
    const void *replacee;
} interpose_t;

__attribute__((used))
static const interpose_t interposers[]
    __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)shim_open,   (const void *)open },
    { (const void *)shim_openat, (const void *)openat },
};

/* Constructor: initialize shim state */
__attribute__((constructor))
static void nono_shim_init(void) {
    /* Resolve real function pointers via RTLD_NEXT */
    real_open = dlsym(RTLD_NEXT, "open");
    real_openat = dlsym(RTLD_NEXT, "openat");

    if (!real_open || !real_openat) {
        /* Cannot function without real implementations */
        return;
    }

    const char *fd_str = getenv("NONO_SUPERVISOR_FD");
    if (!fd_str) {
        /* No supervisor -- shim is a no-op */
        return;
    }

    char *endptr;
    long fd = strtol(fd_str, &endptr, 10);
    if (*endptr != '\0' || fd < 0 || fd > 1024) {
        /* Invalid fd value */
        return;
    }

    g_supervisor_fd = (int)fd;
    g_initialized = 1;
}

/* Destructor: release all consumed extension handles */
__attribute__((destructor))
static void nono_shim_fini(void) {
    for (int i = 0; i < g_ext_handle_count; i++) {
        sandbox_extension_release(g_ext_handles[i]);
    }
    g_ext_handle_count = 0;
}
