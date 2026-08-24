#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <signal.h>
#include <errno.h>

/*
 A userspace restart terminates every process so that launchd respawns them with
 the tweakloader inserted. loginwindow and WindowServer cannot be SIGKILLed:

 The two own the console session and take each other down -- kill either and the
 other exits too. launchd cannot rebuild the session from scratch, so loginwindow
 comes back, enumerates users, and then stops: it never reaches StartedAuthCopy,
 never spawns SecurityAgent, and never creates the gui/<uid> domain. The console
 ends up owned by _windowserver and the machine sits at the login window forever --
 entering a password does nothing.

 SIGHUP to WindowServer is the supported teardown instead. It tears the session
 down cleanly and launchd brings both back (fresh pids, so both pick up the
 tweakloader on spawn), landing on a working login window. So these two are held
 back from the sweep and WindowServer is HUPed once everything else is gone.
 */
static const char *protected_processes[] = {
    "WindowServer",
    "loginwindow",
};


/* Processes we intend to kill, pinned by start time so a recycled pid is never
   mistaken for the original on a retry pass. */
struct target {
    pid_t pid;
    struct timeval start;
};

static int is_protected(const char *name) {
    for (size_t i = 0; i < sizeof(protected_processes) / sizeof(*protected_processes); i++) {
        if (strcmp(name, protected_processes[i]) == 0)
            return 1;
    }
    return 0;
}

static struct kinfo_proc *snapshot(size_t *out_count) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};

    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0) {
        fprintf(stderr, "sysctl (size): %s\n", strerror(errno));
        return NULL;
    }

    /* The table can grow between sizing it and reading it, which would truncate
       the result and silently leave processes running. */
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

static int same_process(const struct kinfo_proc *proc, const struct target *target) {
    return proc->kp_proc.p_pid == target->pid &&
           proc->kp_proc.p_starttime.tv_sec == target->start.tv_sec &&
           proc->kp_proc.p_starttime.tv_usec == target->start.tv_usec;
}

int main(int argc, char *argv[]) {

    /* Without the SIGHUP the console session is left running, so everything is
       restarted except loginwindow and WindowServer and the user stays logged in. */
    int keep_session = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--keep-session") == 0) {
            keep_session = 1;
        } else {
            fprintf(stderr, "usage: %s [--keep-session]\n", argv[0]);
            exit(2);
        }
    }

    /* Killing the process that owns our controlling terminal (sshd, Terminal)
       hangs the tty up, which SIGHUPs our foreground process group. That killed
       ldrestart partway through the sweep and left the rest of the system
       running -- the reason a restart only worked some of the time. */
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    setsid();

    size_t proc_count = 0;
    struct kinfo_proc *procs = snapshot(&proc_count);
    if (!procs)
        exit(1);

    struct target *targets = malloc(proc_count * sizeof(struct target));
    if (!targets) {
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        free(procs);
        exit(1);
    }

    pid_t self = getpid();
    size_t target_count = 0;
    struct target windowserver = {0};

    for (size_t i = 0; i < proc_count; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;

        // Skip the kernel, launchd and ourselves
        if (pid == 0 || pid == 1 || pid == self)
            continue;

        if (is_protected(procs[i].kp_proc.p_comm)) {
            if (strcmp(procs[i].kp_proc.p_comm, "WindowServer") == 0) {
                windowserver.pid = pid;
                windowserver.start = procs[i].kp_proc.p_starttime;
            }
            continue;
        }

        targets[target_count].pid = pid;
        targets[target_count].start = procs[i].kp_proc.p_starttime;
        target_count++;
    }

    free(procs);

    for (size_t i = 0; i < target_count; i++) {
        if (kill(targets[i].pid, SIGKILL) != 0 && errno != ESRCH)
            fprintf(stderr, "kill %d: %s\n", targets[i].pid, strerror(errno));
    }

    /* A process that was mid-exec when we signalled it can outlive the first
       pass, so re-check the snapshot and finish off whatever is still there. */
    for (int pass = 0; pass < 3; pass++) {
        usleep(200 * 1000);

        size_t live_count = 0;
        struct kinfo_proc *live = snapshot(&live_count);
        if (!live)
            break;

        size_t survivors = 0;
        for (size_t i = 0; i < live_count; i++) {
            for (size_t j = 0; j < target_count; j++) {
                if (!same_process(&live[i], &targets[j]))
                    continue;

                if (kill(targets[j].pid, SIGKILL) != 0 && errno != ESRCH)
                    fprintf(stderr, "kill %d: %s\n", targets[j].pid, strerror(errno));
                survivors++;
                break;
            }
        }

        free(live);

        if (survivors == 0)
            break;
    }

    free(targets);

    /* Everything else is gone, so tear the console session down the supported
       way. Both processes come back under the hooked launchd. */
    if (!keep_session && windowserver.pid != 0) {
        if (kill(windowserver.pid, SIGHUP) != 0)
            fprintf(stderr, "SIGHUP %d: %s\n", windowserver.pid, strerror(errno));
    }

    return 0;
}
