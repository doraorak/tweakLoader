#include <CoreFoundation/CoreFoundation.h>
#include <spawn.h>
#include <dyld-interposing.h>

#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
#include <sys/stat.h>

#define TWEAKINJECT_LOG_PATH     "/Library/TweakInject/tweakinject.log"
#define TWEAKINJECT_LOG_FALLBACK "/tmp/tweakinject.log"

/// Safe, deadlock-free file logging that avoids os_log / logd IPC deadlocks.
static void tl_safe_log(const char* fmt, ...) {
    const char* prog = getprogname();
    if (prog && (strcmp(prog, "logd") == 0 || strcmp(prog, "diagnosticd") == 0)) {
        return;
    }

    char body[1024];
    va_list args;
    va_start(args, fmt);
    int bodyLen = vsnprintf(body, sizeof(body) - 2, fmt, args);
    va_end(args);

    if (bodyLen <= 0) return;

    if (body[bodyLen - 1] != '\n') {
        body[bodyLen] = '\n';
        body[bodyLen + 1] = '\0';
        bodyLen++;
    }

    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char timeStr[32];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tm_buf);

    char line[1280];
    int lineLen = snprintf(line, sizeof(line), "[%s] [%s:%d] %s", timeStr, prog ? prog : "unknown", getpid(), body);
    if (lineLen <= 0) return;

    int fd = open(TWEAKINJECT_LOG_PATH, O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK | O_CLOEXEC, 0666);
    if (fd < 0) {
        fd = open(TWEAKINJECT_LOG_FALLBACK, O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK | O_CLOEXEC, 0666);
    }
    if (fd >= 0) {
        fchmod(fd, 0666);
        write(fd, line, (size_t)lineLen);
        close(fd);
    }
}

#define TL_LOG(fmt, ...) tl_safe_log(fmt, ##__VA_ARGS__)

char* sandbox_token = NULL;
char* (* _sandbox_extension_issue_file)(const char*, const char*, uint32_t);

#define XPCPROXY_HOOKS_DYLIB_PATH "/Library/TweakInject/LaunchdHook/xpcproxy_hooks.dylib"
#define LAUNCHD_HOOKS_DYLIB_PATH  "/Library/TweakInject/LaunchdHook/launchd_hooks.dylib"
#define TWEAK_LOADER_DYLIB_PATH   "/Library/TweakInject/libtweakLoader.dylib"
#define ELLEKIT_DYLIB_PATH        "/Library/TweakInject/libellekit.dylib"
#define TWEAK_INJECT_PATH         "/Library/TweakInject/"
#define HOOKED_MARKER_PATH        "/var/run/tweakinject.hooked"

#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

static void (*_MSHookFunction)(void *symbol, void *replace, void **result);
static void *orig_posix_spawn;
static void *orig_posix_spawnp;

static const char *process_blacklist[] = {
    "logd",
    "syslogd",
    "diagnosticd",
    "notifyd",
    "distnoted",
    "configd",
    "opendirectoryd",
    "sandboxd",
    "securityd",
    "trustd",
    "amfid",
    "GSSCred",
    "systemstats",
    "AccessibilityUIServer",
    "UserSelector",
    "ScreenTimeAgent",
    // The managing front-end and its privileged helper. Whatever installs and
    // controls tweaks is the trusted path, and a tweak loaded into it could
    // subvert the very thing meant to govern tweaks. denyInjectionList.plist
    // already stops tweaks loading there, but that check runs INSIDE the loader,
    // i.e. after our code is in the process — excluding them here means the loader
    // is never mapped in at all.
    "TweakInject",
    "com.doraorak.tweakinject.helper",
};

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

static int posix_spawn_launchd(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict], void *original_function) {
    
    char *const *envp = __envp;
    char *allocated_sandbox_token = NULL;
    char **allocated_envp = NULL;
    
    if (is_path_blacklisted_from_injection(path)) {
        goto exec;
    }
    
    int notLaunchd = path != NULL && strcmp(path, "/sbin/launchd") != 0;
    if (notLaunchd && __envp != NULL) {
        int is_xpcproxy = strstr(path, "xpcproxy") != NULL;
        char *dylib_to_inject = is_xpcproxy ? "DYLD_INSERT_LIBRARIES=" XPCPROXY_HOOKS_DYLIB_PATH : "DYLD_INSERT_LIBRARIES=" TWEAK_LOADER_DYLIB_PATH;
        
        size_t envp_size = 0;
        while (__envp[envp_size] != NULL) {
            envp_size++;
        }
        envp_size++;
        
        if (sandbox_token) {
            size_t new_size = envp_size + 2;
            char **new_envp = malloc(new_size * sizeof(char *));
            if (new_envp) {
                for (size_t i = 0; i < envp_size - 1; i++) {
                    new_envp[i] = __envp[i];
                }
                
                size_t sandbox_token_env_size = strlen(sandbox_token) + sizeof("TL_SANDBOX_TOKEN=");
                char *sandbox_token_env = malloc(sandbox_token_env_size);
                if (sandbox_token_env) {
                    snprintf(sandbox_token_env, sandbox_token_env_size, "TL_SANDBOX_TOKEN=%s", sandbox_token);
                    allocated_sandbox_token = sandbox_token_env;
                }
                
                new_envp[new_size - 3] = dylib_to_inject;
                new_envp[new_size - 2] = sandbox_token_env;
                new_envp[new_size - 1] = NULL;
                envp = new_envp;
                allocated_envp = new_envp;
            }
        } else {
            size_t new_size = envp_size + 1;
            char **new_envp = malloc(new_size * sizeof(char *));
            if (new_envp) {
                for (size_t i = 0; i < envp_size - 1; i++) {
                    new_envp[i] = __envp[i];
                }
                
                new_envp[new_size - 2] = dylib_to_inject;
                new_envp[new_size - 1] = NULL;
                envp = new_envp;
                allocated_envp = new_envp;
            }
        }
    }

exec:;
    int ret = ((int (*)(pid_t * __restrict, const char * __restrict, const posix_spawn_file_actions_t *, const posix_spawnattr_t * __restrict, char *const __argv[__restrict], char *const __envp[__restrict]))original_function)(pid, path, file_actions, attrp, __argv, envp);
    
    if (ret == 0 && notLaunchd && path) {
        TL_LOG("[LaunchdHook] Armed tweakLoader injection for %s (pid %d)", path, pid ? *pid : 0);
    }

    if (allocated_sandbox_token) {
        free(allocated_sandbox_token);
    }
    if (allocated_envp) {
        free(allocated_envp);
    }
    
    return ret;
}

static int posix_spawn_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict]) {
    return posix_spawn_launchd(pid, path, file_actions, attrp, __argv, __envp, orig_posix_spawn);
}

static int posix_spawnp_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict]) {
    return posix_spawn_launchd(pid, path, file_actions, attrp, __argv, __envp, orig_posix_spawnp);
}

static void __attribute__((constructor)) init_launchd_hooks(void) {
    setenv("DYLD_INSERT_LIBRARIES", LAUNCHD_HOOKS_DYLIB_PATH, 1);
    
    void* libSystemSandboxHandle = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (libSystemSandboxHandle) {
        _sandbox_extension_issue_file = dlsym(libSystemSandboxHandle, "sandbox_extension_issue_file");
        if (_sandbox_extension_issue_file) {
            sandbox_token = _sandbox_extension_issue_file("com.apple.app-sandbox.read", TWEAK_INJECT_PATH, 0);
        }
    }
    
    void *EKHandle = dlopen(ELLEKIT_DYLIB_PATH, RTLD_NOW);
    if (EKHandle) {
        _MSHookFunction = dlsym(EKHandle, "MSHookFunction");
        if (_MSHookFunction) {
            _MSHookFunction((void *)posix_spawn, (void *)posix_spawn_hook, (void **)&orig_posix_spawn);
            _MSHookFunction((void *)posix_spawnp, (void *)posix_spawnp_hook, (void **)&orig_posix_spawnp);

            int marker = open(HOOKED_MARKER_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (marker >= 0) {
                close(marker);
            }
            TL_LOG("[LaunchdHook] Successfully hooked posix_spawn and posix_spawnp");
        }
    }
}
