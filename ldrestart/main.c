#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <signal.h>
#include <errno.h>

/*
 A clean macOS userspace restart resets the graphical session by sending SIGHUP
 to WindowServer. WindowServer is the root display server and session master
 for the graphical login session. When it receives SIGHUP, it cleanly tears down
 all connected AppKit/GUI client processes and exits. launchd immediately recreates
 the graphical console session and spawns a fresh WindowServer and loginwindow,
 landing smoothly on a working login screen without killing hardware drivers.
 */

static struct kinfo_proc *copy_running_processes(size_t *out_count) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};

    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0) {
        fprintf(stderr, "sysctl (size): %s\n", strerror(errno));
        return NULL;
    }

    size += size / 4;

    struct kinfo_proc *procs = malloc(size);
    if (!procs) {
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        return NULL;
    }

    if (sysctl(mib, 4, procs, &size, NULL, 0) < 0) {
        fprintf(stderr, "sysctl (data): %s\n", strerror(errno));
        free(procs);
        return NULL;
    }

    *out_count = size / sizeof(struct kinfo_proc);
    return procs;
}

int main(int argc, char *argv[]) {
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    setsid();

    size_t proc_count = 0;
    struct kinfo_proc *procs = copy_running_processes(&proc_count);
    if (!procs)
        exit(1);

    pid_t windowserver_pid = 0;
    pid_t self = getpid();

    for (size_t i = 0; i < proc_count; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        const char *name = procs[i].kp_proc.p_comm;

        if (pid <= 1 || pid == self)
            continue;

        if (strcmp(name, "WindowServer") == 0) {
            windowserver_pid = pid;
            break;
        }
    }

    free(procs);

    if (windowserver_pid > 0) {
        if (kill(windowserver_pid, SIGHUP) != 0) {
            fprintf(stderr, "SIGHUP WindowServer (%d): %s\n", windowserver_pid, strerror(errno));
            return 1;
        }
    } else {
        fprintf(stderr, "WindowServer process not found\n");
        return 1;
    }

    return 0;
}
