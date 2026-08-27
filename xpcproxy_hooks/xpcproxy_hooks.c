#include <CoreFoundation/CoreFoundation.h>
#include <dyld-interposing.h>
#include <spawn.h>

/// Logging is OFF by default and should normally stay that way.
///
/// This code runs inside EVERY process that launches, logd included. os_log() from
/// a constructor in logd deadlocks logd, and once logging is wedged the rest of the
/// system follows — a machine in that state usually needs a reboot to recover.
/// Enable only while debugging something you cannot reach otherwise, and only when
/// you can afford to lose the box.
#define ENABLE_LOGS 0

#if ENABLE_LOGS
#include <os/log.h>
#define TL_LOG(fmt, ...) os_log(OS_LOG_DEFAULT, fmt, ##__VA_ARGS__)
#else
#define TL_LOG(fmt, ...) do {} while (0)
#endif
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>

#define TWEAK_LOADER_DYLIB_PATH "/Library/TweakInject/libtweakLoader.dylib"

char* sandbox_token = NULL;

static const char *process_blacklist[] = {
    // Core system log & diagnostics
    "logd",
    "syslogd",
    "diagnosticd",
    "notifyd",
    "distnoted",
    "configd",
    // Security, Authentication & Login Framework (DO NOT INJECT — causes loginwindow deadlocks on ldrestart)
    "opendirectoryd",
    "sandboxd",
    "securityd",
    "securityd_system",
    "secd",
    "secinitd",
    "trustd",
    "amfid",
    "GSSCred",
    "loginwindow",
    "LoginUserService",
    "SecurityAgent",
    "authorizationhost",
    "authd",
    "coreauthd",
    "online-auth-agent",
    "applekeystored",
    "keybagd",
    "biometrickitd",
    "taskgated",
    "UserSelector",
    "ScreenTimeAgent",
    "UserEventAgent",
    "runningboardd",
    "containermanagerd",
    "containermanagerd_system",
    "systemstats",
    "AccessibilityUIServer",
    // Storage & Power
    "diskarbitrationd",
    "powerd",
    "kernelmanagerd",
    // The managing front-end and privileged helper
    "TweakInject",
    "com.doraorak.tweakinject.helper",
};

#define INJECTION_DISABLED_MARKER "/var/run/tweakinject.disabled"
#define INJECTION_DISABLED_DIR    "/Library/TweakInject/.disabled"

static int is_injection_disabled(void) {
    if (access(TWEAK_LOADER_DYLIB_PATH, F_OK) != 0) {
        return 1;
    }
    if (access(INJECTION_DISABLED_MARKER, F_OK) == 0 || access(INJECTION_DISABLED_DIR, F_OK) == 0) {
        return 1;
    }
    return 0;
}

/// Returns an environment with every injection variable removed.
///
/// Used on the paths where we have decided NOT to inject: leaving an inherited
/// DYLD_INSERT_LIBRARIES in place is indistinguishable from injecting on purpose.
/// Returns __envp untouched when there is nothing to strip or the allocation
/// fails, so the spawn always proceeds.
static char *const *strip_injection_env(char *const *__envp, char ***out_allocated) {
    if (__envp == NULL) {
        return __envp;
    }

    size_t count = 0, dirty = 0;
    while (__envp[count] != NULL) {
        if (strncmp(__envp[count], "DYLD_INSERT_LIBRARIES=", 22) == 0 ||
            strncmp(__envp[count], "TL_SANDBOX_TOKEN=", 17) == 0 ||
            strncmp(__envp[count], "SANDBOX_TOKEN=", 14) == 0) {
            dirty++;
        }
        count++;
    }
    if (dirty == 0) {
        return __envp;
    }

    char **clean = malloc((count + 1) * sizeof(char *));
    if (!clean) {
        return __envp;
    }

    size_t dst = 0;
    for (size_t i = 0; i < count; i++) {
        if (strncmp(__envp[i], "DYLD_INSERT_LIBRARIES=", 22) == 0) continue;
        if (strncmp(__envp[i], "TL_SANDBOX_TOKEN=", 17) == 0) continue;
        if (strncmp(__envp[i], "SANDBOX_TOKEN=", 14) == 0) continue;
        clean[dst++] = __envp[i];
    }
    clean[dst] = NULL;
    *out_allocated = clean;
    return clean;
}

static int is_path_blacklisted_from_injection(const char *path) {
    if (path == NULL) {
        return 0;
    }

    if (strstr(path, ".dext/") != NULL) {
        return 1;
    }

    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;

    for (size_t i = 0; i < sizeof(process_blacklist) / sizeof(*process_blacklist); i++) {
        if (strcmp(name, process_blacklist[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

static int posix_spawn_xpcproxy(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict], void *original_function) {
    
    char *const *envp = __envp;
    char *allocated_sandbox_token = NULL;
    char **allocated_envp = NULL;

    int should_hook = !is_path_blacklisted_from_injection(path) && !is_injection_disabled() && __envp != NULL;

    if (!should_hook) {
        // This process is the reason the blacklist exists, and it is about to
        // inherit our DYLD_INSERT_LIBRARIES from the xpcproxy that is exec'ing
        // it. Take it back out.
        envp = strip_injection_env(__envp, &allocated_envp);
    }

    if (should_hook) {
        size_t count = 0;
        while (__envp[count] != NULL) {
            count++;
        }

        char **new_envp = malloc((count + 4) * sizeof(char *));
        if (new_envp) {
            size_t dst = 0;
            for (size_t i = 0; i < count; i++) {
                if (strncmp(__envp[i], "DYLD_INSERT_LIBRARIES=", 22) == 0) continue;
                if (strncmp(__envp[i], "TL_SANDBOX_TOKEN=", 17) == 0) continue;
                if (strncmp(__envp[i], "SANDBOX_TOKEN=", 14) == 0) continue;
                new_envp[dst++] = __envp[i];
            }

            new_envp[dst++] = "DYLD_INSERT_LIBRARIES=" TWEAK_LOADER_DYLIB_PATH;

            if (sandbox_token) {
                size_t sandbox_token_env_size = strlen(sandbox_token) + sizeof("TL_SANDBOX_TOKEN=");
                char *sandbox_token_env = malloc(sandbox_token_env_size);
                if (sandbox_token_env) {
                    snprintf(sandbox_token_env, sandbox_token_env_size, "TL_SANDBOX_TOKEN=%s", sandbox_token);
                    allocated_sandbox_token = sandbox_token_env;
                    new_envp[dst++] = sandbox_token_env;
                }
            }

            new_envp[dst] = NULL;
            envp = new_envp;
            allocated_envp = new_envp;
        }
    }

    int ret = ((int (*)(pid_t * __restrict, const char * __restrict, const posix_spawn_file_actions_t *, const posix_spawnattr_t * __restrict, char *const __argv[__restrict], char *const __envp[__restrict]))original_function)(pid, path, file_actions, attrp, __argv, envp);

    if (allocated_sandbox_token) {
        free(allocated_sandbox_token);
    }
    if (allocated_envp) {
        free(allocated_envp);
    }

    return ret;
}

static int posix_spawn_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict]) {
    return posix_spawn_xpcproxy(pid, path, file_actions, attrp, __argv, __envp, posix_spawn);
}

static int posix_spawnp_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict]) {
    return posix_spawn_xpcproxy(pid, path, file_actions, attrp, __argv, __envp, posix_spawnp);
}

DYLD_INTERPOSE(posix_spawn_hook, posix_spawn);
DYLD_INTERPOSE(posix_spawnp_hook, posix_spawnp);

static void __attribute__((constructor)) init_xpcproxy_hooks(void) {
    char *token = getenv("TL_SANDBOX_TOKEN");
    if (!token) {
        token = getenv("SANDBOX_TOKEN");
    }
    if (token) {
        sandbox_token = strdup(token);
    }
}
