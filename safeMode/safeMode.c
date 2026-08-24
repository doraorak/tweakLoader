//
//  safeMode.m
//  safeMode
//
//  Created by Dora Orak on 2.04.2025.
//

#import <CoreFoundation/CoreFoundation.h>
#import <os/log.h>
#import <signal.h>
#import <libproc.h>
#import <pthread/pthread.h>
#import <execinfo.h>
#import <dlfcn.h>

#define safePath "/Library/TweakInject/SafeMode/safemode.txt"

#define PRINT(...) os_log(OS_LOG_DEFAULT, __VA_ARGS__);


void handle_signal(int signo, siginfo_t *info, void *context) {
    (void)context; // Unused parameter
    
    PRINT("[safeMode] pid: %d. Signal received: %d\n", getpid(), signo);
    
    char name[256];
    proc_name(info->si_pid, name, 256);
    if (strstr(name, "ldrestart")){
        return;
    }
    
    FILE *fp = fopen(safePath, "a");
    if (fp) {
        fprintf(fp, "[safeMode] pid: %d. Signal received: %d\n", getpid(), signo);
        fclose(fp);
    }
    
    
    // Restore default signal handler and re-raise the signal to terminate normally
    signal(signo, SIG_DFL);
    raise(signo);
}

__attribute__((constructor))
static void entry(void) {
    struct sigaction sa;
        sa.sa_sigaction = handle_signal;
        sa.sa_flags = SA_SIGINFO | SA_RESETHAND; // Get signal info and reset handler after first use
        sigemptyset(&sa.sa_mask);

        // List of signals to catch
        int signals[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGTRAP};
        for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
            if (sigaction(signals[i], &sa, NULL) == -1) {
                PRINT("sigaction");
            }
        }
}
