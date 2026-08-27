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

#define safePath "/Library/TweakInject/SafeMode/safemode.txt"

/// Logging is OFF by default and should normally stay that way.
#define ENABLE_LOGS 0

#if ENABLE_LOGS
#include <os/log.h>
#define TL_LOG(fmt, ...) os_log(OS_LOG_DEFAULT, fmt, ##__VA_ARGS__)
#else
#define TL_LOG(fmt, ...) do {} while (0)
#endif

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
    
    FILE *fp = fopen(safePath, "a");
    if (fp) {
        fprintf(fp, "[safeMode] %s (pid %d) received signal %d\n", selfName, getpid(), signo);
        fclose(fp);
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
