#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <signal.h>
#include <errno.h>

/*
 A clean macOS userspace restart:
 1. Instantly terminates all non-GUI daemons and background agents so launchd
    respawns them with fresh state and injection hooks.
 2. Protects low-level hardware drivers (DriverKit, bluetoothd, powerd, etc.)
    to avoid USB/Bluetooth hardware disconnects and keyboard assistant popups.
 3. Sends SIGHUP last to WindowServer (and loginwindow) to cleanly dismantle
    the console session and bring up a fresh login window.
 */

static const char *protected_processes[] = {
    "launchd",
    "kernel_task",
    "WindowServer",
    "loginwindow",
    "SecurityAgent",
    // Core hardware, driver, and system security daemons (NEVER SIGKILL)
    "bluetoothd",
    "corebrightnessd",
    "powerd",
    "diskarbitrationd",
    "kernelmanagerd",
    "syspolicyd",
    "amfid",
    "trustd",
    "securityd",
    "securityd_system",
    "opendirectoryd",
    "configd",
    "notifyd",
    "distnoted",
    "logd",
    "syslogd",
    "diagnosticd",
    "TweakInject",
    "com.doraorak.tweakinject.helper",
};

static int is_protected_process_name(const char *name) {
    if (!name || !name[0]) return 0;
    if (strncmp(name, "IOUser", 6) == 0 || strncmp(name, "DriverKit", 9) == 0) {
        return 1;
    }
    for (size_t i = 0; i < sizeof(protected_processes) / sizeof(*protected_processes); i++) {
        if (strcmp(name, protected_processes[i]) == 0)
            return 1;
    }
    return 0;
}

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

struct target {
    pid_t pid;
    struct timeval start;
};

static int is_same_process_instance(const struct kinfo_proc *proc, const struct target *target) {
    return proc->kp_proc.p_pid == target->pid &&
           proc->kp_proc.p_starttime.tv_sec == target->start.tv_sec &&
           proc->kp_proc.p_starttime.tv_usec == target->start.tv_usec;
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

    struct target *targets = malloc(proc_count * sizeof(struct target));
    if (!targets) {
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        free(procs);
        exit(1);
    }

    pid_t windowserver_pid = 0;
    pid_t loginwindow_pid = 0;
    pid_t self = getpid();
    size_t target_count = 0;

    for (size_t i = 0; i < proc_count; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        const char *name = procs[i].kp_proc.p_comm;

        if (pid <= 1 || pid == self)
            continue;

        if (strcmp(name, "WindowServer") == 0) {
            windowserver_pid = pid;
            continue;
        }
        if (strcmp(name, "loginwindow") == 0) {
            loginwindow_pid = pid;
            continue;
        }

        // Protect driverkit, bluetooth, and core hardware daemons
        if (is_protected_process_name(name))
            continue;

        targets[target_count].pid = pid;
        targets[target_count].start = procs[i].kp_proc.p_starttime;
        target_count++;
    }

    free(procs);

    // 1. Instantly kill non-GUI daemons & background processes so they respawn under launchd
    for (size_t i = 0; i < target_count; i++) {
        if (kill(targets[i].pid, SIGKILL) != 0 && errno != ESRCH) {
            // Suppress error if process already exited
        }
    }

    // 2. Quick pass to ensure stubborn processes are dead
    usleep(80 * 1000); // 80ms
    size_t live_count = 0;
    struct kinfo_proc *live = copy_running_processes(&live_count);
    if (live) {
        for (size_t i = 0; i < live_count; i++) {
            for (size_t j = 0; j < target_count; j++) {
                if (!is_same_process_instance(&live[i], &targets[j]))
                    continue;

                kill(targets[j].pid, SIGKILL);
                break;
            }
        }
        free(live);
    }

    free(targets);

    // 3. SIGHUP WindowServer (and loginwindow) LAST to cleanly cycle the graphical session
    if (loginwindow_pid > 0) {
        kill(loginwindow_pid, SIGHUP);
    }

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
