#include <CoreFoundation/CoreFoundation.h>
#include <os/log.h>
#include <signal.h>
#include <libproc.h>
#include <pthread/pthread.h>
#include <execinfo.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

// The tripwire cannot write the Safe Mode marker itself.
//
// This runs inside Dock, Finder, WindowServer and the wallpaper extensions,
// none of which is root, while the marker lives in a root:wheel 755 directory.
// Every path tried before failed the same way: safemode.txt sat in that same
// directory, and /var/run is root:daemon 775. So the handler does not write the
// marker -- it drops a REQUEST that the privileged helper promotes.
//
// The helper's LaunchDaemon declares this path in WatchPaths, so launchd starts
// it when the file appears; nothing has to be running at crash time. On
// startup the helper creates the real marker root-owned and deletes this file.
//
// Ordering matters, and it is the reason the notify comes first and the
// re-raise immediately after: this process is dying, and it should finish dying
// before anything acts on the request. Dropping the file is a bounded
// open/write/close; the helper is started by launchd afterwards, by which time
// the default handler has already taken this process down.
#define SAFE_MODE_REQUEST_PATH "/tmp/.tweakinject-safemode-request"

/// Logging is OFF by default and should normally stay that way.
#define ENABLE_LOGS 0

#if ENABLE_LOGS
#include <os/log.h>
#define TL_LOG(fmt, ...) os_log(OS_LOG_DEFAULT, fmt, ##__VA_ARGS__)
#else
#define TL_LOG(fmt, ...) do {} while (0)
#endif

// Async-signal-safe formatting primitives. Both return the number of bytes
// written and never exceed the buffer.
static size_t append_str(char *dst, size_t cap, const char *src) {
    size_t i = 0;
    while (src[i] != '\0' && i + 1 < cap) { dst[i] = src[i]; i++; }
    return i;
}

static size_t append_int(char *dst, size_t cap, long v) {
    char tmp[24];
    size_t t = 0;
    int neg = v < 0;
    unsigned long u = neg ? (unsigned long)(-v) : (unsigned long)v;
    do { tmp[t++] = (char)('0' + (u % 10)); u /= 10; } while (u && t < sizeof(tmp));
    if (neg && t < sizeof(tmp)) tmp[t++] = '-';
    size_t i = 0;
    while (t > 0 && i + 1 < cap) { dst[i++] = tmp[--t]; }
    return i;
}

void handle_crash_signal(int signo, siginfo_t *info, void *context) {
    (void)context; // Unused parameter
    
    // Name of the process that is crashing (us), not the one that signalled us.
    char selfName[256] = {0};
    if (proc_name(getpid(), selfName, sizeof(selfName)) <= 0) {
        strncpy(selfName, "unknown", sizeof(selfName) - 1);
    }

    TL_LOG("[safeMode] %{public}s (pid %d) received signal %d\n", selfName, getpid(), signo);

    // si_pid is the SENDER. ldrestart terminates processes deliberately, so its
    // signals are not crashes and must not trip safe mode.
    char senderName[256] = {0};
    proc_name(info->si_pid, senderName, sizeof(senderName));
    if (strstr(senderName, "ldrestart")){
        return;
    }
    
    // open/write/close only. The fopen/fprintf this replaces allocated and took
    // stdio locks inside a signal handler, in a process that had just crashed.
    // The record is assembled by hand for the same reason -- snprintf is not
    // async-signal-safe either.
    char rec[512];
    size_t n = 0;
    n += append_str(rec + n, sizeof(rec) - n, "[safeMode] ");
    n += append_str(rec + n, sizeof(rec) - n, selfName);
    n += append_str(rec + n, sizeof(rec) - n, " (pid ");
    n += append_int(rec + n, sizeof(rec) - n, (long)getpid());
    n += append_str(rec + n, sizeof(rec) - n, ") received signal ");
    n += append_int(rec + n, sizeof(rec) - n, (long)signo);
    n += append_str(rec + n, sizeof(rec) - n, "\n");

    int fd = open(SAFE_MODE_REQUEST_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    if (fd >= 0) {
        ssize_t w = write(fd, rec, n);
        (void)w;
        close(fd);
    }

    
    // Restore default signal handler and re-raise the signal to terminate normally
    signal(signo, SIG_DFL);
    raise(signo);
}

__attribute__((constructor))
static void init_safe_mode(void) {
    struct sigaction sa;
    sa.sa_sigaction = handle_crash_signal;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND; // Get signal info and reset handler after first use
    sigemptyset(&sa.sa_mask);

    // List of signals to catch
    int signals[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGTRAP};
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
        if (sigaction(signals[i], &sa, NULL) == -1) {
            TL_LOG("sigaction");
        }
    }
}
