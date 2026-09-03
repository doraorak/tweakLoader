// These used to arrive transitively via CoreFoundation, which this no longer
// pulls in -- see the per-process cache below for why.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <spawn.h>
#include <dyld-interposing.h>

#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
#include <sys/stat.h>

#define TWEAKINJECT_LOG_PATH     "/Library/TweakInject/logs/tweakinject.log"
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

// Sandbox grants handed to every injected process.
//
// Adding one is a single line in the right array. A grant is needed whenever
// injected code has to reach a path that a sandboxed host would otherwise be
// confined away from -- the preference store below is exactly that case: the
// tweak runs inside someone else's container, and without the grant its reads
// and writes resolve nowhere useful.
//
// A sandbox grant is not a POSIX grant. The path must also be writable by the
// uid that will write it; Preferences/Defaults is root:staff 775 for that
// reason.
static const char *const kSandboxRead[] = {
    "/Library/TweakInject/",
};

static const char *const kSandboxReadWrite[] = {
    "/Library/TweakInject/logs/",
    "/Library/TweakInject/Preferences/Defaults/",
};

#define SANDBOX_READ_COUNT  (sizeof(kSandboxRead) / sizeof(*kSandboxRead))
#define SANDBOX_RW_COUNT    (sizeof(kSandboxReadWrite) / sizeof(*kSandboxReadWrite))
#define SANDBOX_GRANT_COUNT (SANDBOX_READ_COUNT + SANDBOX_RW_COUNT)

static char *sandbox_tokens[SANDBOX_GRANT_COUNT];
static size_t sandbox_token_count = 0;
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
    // Core system log & diagnostics
    "logd",
    "syslogd",
    "diagnosticd",
    "notifyd",
    "distnoted",
    // Preference and launch-services plumbing: nearly every launch goes through
    // these, and the loader hooks CFPreferences, so injecting them is circular.
    "cfprefsd",
    "launchservicesd",
    "configd",
    // Core launch & session supervision
    "launchd",
    "sessionproxy",
    // Security, Authentication & Login Framework (DO NOT INJECT — causes loginwindow deadlocks on ldrestart)
    "opendirectoryd",
    "sandboxd",
    "securityd",
    "securityd_system",
    "secd",
    "secinitd",
    "trustd",
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
    // Code signing: injecting the validator that authorises injection is a
    // loop, and a wedged amfid stalls every exec on the machine.
    "amfid",
    "UserSelector",
    "ScreenTimeAgent",
    "UserEventAgent",
    "runningboardd",
    "containermanagerd",
    "containermanagerd_system",
    "systemstats",
    "AccessibilityUIServer",
    // GPU shader compilation. Every app's Metal work funnels through this XPC
    // service, so a hooked function in it stalls the GPU pipeline machine-wide,
    // not just for the app that triggered the compile. Measured: three
    // instances each burning 2.6s of their 3.6s total CPU inside ElleKit's
    // exception handler, with Chrome blocked behind them on a turnstile --
    // which is what froze a Cloudflare checkbox, and what left processes alive
    // through shutdown until the watchdog reset the machine.
    "MTLCompilerService",
    // Early-boot filesystem tools. launchd runs these to bring the volumes up
    // BEFORE it starts amfid, so a code signature the kernel has not cached
    // yet cannot be validated and dyld aborts the process. These are
    // boot-critical, and a boot-critical task dying panics the kernel exactly
    // the way PID 1 does -- measured, as mount[1668] taking the machine down
    // over libtweakLoader.dylib. ldrestart pre-warms the signatures to stop
    // that happening at all; this list is the belt to that pair of braces, and
    // costs nothing, since none of these is anybody's tweak target.
    "mount",
    "mount_apfs",
    "umount",
    "fsck",
    "fsck_apfs",
    "apfsd",
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
    // 1. If tweakLoader dylib does not exist on disk, injection MUST NOT be armed
    if (access(TWEAK_LOADER_DYLIB_PATH, F_OK) != 0) {
        return 1;
    }
    // 2. If explicit disabled marker exists (e.g. paused/suspended injection)
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
        // Prefix, not exact names: the tokens are TL_SANDBOX_TOKEN_0..N and the
        // count changes whenever a grant is added to the tables above.
        if (strncmp(__envp[count], "DYLD_INSERT_LIBRARIES=", 22) == 0 ||
            strncmp(__envp[count], "TL_SANDBOX_TOKEN", 16) == 0 ||
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
        if (strncmp(__envp[i], "TL_SANDBOX_TOKEN", 16) == 0) continue;
        if (strncmp(__envp[i], "SANDBOX_TOKEN=", 14) == 0) continue;
        clean[dst++] = __envp[i];
    }
    clean[dst] = NULL;
    *out_allocated = clean;
    return clean;
}

/// Append TL_SANDBOX_TOKEN_0..N-1 to a spawn's environment.
///
/// Numbered rather than one delimited variable: the tokens are opaque strings
/// containing ';' and '/', and there is no separator that is safe against a
/// format we do not control.
///
/// Returns the new write index. Each string it allocates is recorded in
/// `allocated` so the caller can free them after the spawn.
static size_t append_sandbox_tokens(char **new_envp, size_t dst,
                                    char **allocated, size_t *allocated_count) {
    for (size_t i = 0; i < sandbox_token_count; i++) {
        size_t size = strlen(sandbox_tokens[i]) + sizeof("TL_SANDBOX_TOKEN_18446744073709551615=");
        char *entry = malloc(size);
        if (!entry) continue;
        snprintf(entry, size, "TL_SANDBOX_TOKEN_%zu=%s", i, sandbox_tokens[i]);
        allocated[(*allocated_count)++] = entry;
        new_envp[dst++] = entry;
    }
    return dst;
}

static int is_setexec_attr(const posix_spawnattr_t *attrp) {
    if (!attrp || !*attrp) return 0;
    short flags = 0;
    if (posix_spawnattr_getflags(attrp, &flags) == 0) {
        return (flags & POSIX_SPAWN_SETEXEC) != 0;
    }
    return 0;
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

#define SAFE_MODE_MARKER_PATH "/Library/TweakInject/SafeMode/.safemode"

// Safe Mode is enforced HERE now, not inside the loader.
//
// It used to be a check in tweakLoader.c, which meant the loader was still
// mapped into every process and its constructors still ran: Safe Mode described
// what the loader declined to do rather than what was in the process. That is
// the same mistake the per-process disable list used to make, and it costs more
// here than anywhere else -- Safe Mode exists because something is already
// broken, so the one thing that should be guaranteed absent is our own code.
//
// One marker, root-owned, and deliberately NOT in /var/run: that directory is
// wiped and repopulated on every userspace reboot, which is the exact operation
// Safe Mode is built on -- write the marker, restart userspace, come up in Safe
// Mode. A marker there is gone before anything can read it. (/var/run is right
// for tweakinject.hooked, which MUST NOT outlive the launchd it describes.)
//
// This mirrors the persistent half of the injection-disable pair,
// /Library/TweakInject/.disabled, which had already solved the same problem.
// It lives in the SafeMode directory beside the two dylibs it governs; the
// leading dot keeps it out of the way of anything listing that directory.
static int is_safe_mode_active(void) {
    return access(SAFE_MODE_MARKER_PATH, F_OK) == 0;
}

// The one exception. Safe Mode has to be able to say so on screen, and the
// indicator is itself an injected tweak -- libsafeModePill.dylib, which
// tweakLoader dlopens here. This host keeps the loader; every other gate still
// applies to it, and tweakLoader's own Safe Mode check stops it loading
// anything besides the pill.
//
// Finder alone. Every host that loads the pill creates its own NSStatusItem, so
// the number of Safe Mode items in the menu bar is just the length of this
// array -- adding a host here adds a duplicate indicator, not a fallback.
// ControlCenter. Both candidates were measured live rather than reasoned about,
// because each fails in a different and non-obvious way.
//
// Signing flags rule most hosts out first: Finder 0x2000 (library-validation),
// so the pill cannot load into it at all where LV is enforced, which is most of
// the point of the feature. SystemUIServer 0x2100, worse. Dock 0x0 but links
// SkyLight and CoreGraphics with no AppKit, so NSStatusBar is not real there.
// That leaves MenuBarAgent and ControlCenter, both 0x0 and both linking AppKit.
//
// Creating a status item in each, with lldb, on the live processes:
//
//     MenuBarAgent   flags 0xa0950   isVisible 1   born visible
//     ControlCenter  flags 0xa0940   isVisible 0   born HIDDEN
//
// which says MenuBarAgent is the better host, and is wrong. Injected into
// MenuBarAgent the item is visible, its button is 101x22, not hidden, alpha 1,
// and its window sits at a real menu bar position -- with the image and the red
// attributed title both set on the button. It still draws NOTHING, and forcing
// setNeedsDisplay/displayIfNeeded does not change that. MenuBarAgent hosts the
// system's own menu bar; it carries a client item's window and never draws its
// content, so the result is a 101pt hole you can click and get a working menu
// from. That is the "renders an empty item" this comment used to claim without
// evidence -- the claim was right, the reasoning behind it was not.
//
// ControlCenter draws correctly. Its cost is that menu bar visibility there is
// user-owned policy, keyed per autosave name -- the machinery System Settings
// uses to hide Wi-Fi or the clock -- so an item is born hidden and the pill has
// to set `visible = YES` explicitly with a stable autosaveName. That is a real
// dependency, and it is the lesser problem: an item that must be switched on
// beats an item that cannot be drawn.
//
// The number of Safe Mode items in the menu bar is the length of this array;
// adding a host here adds a duplicate indicator, not a fallback. The duplicate
// seen earlier was exactly that -- two hosts injected at once.
static const char *const safe_mode_indicator_hosts[] = {
    "ControlCenter",
};

static int is_safe_mode_indicator_host(const char *path) {
    if (path == NULL) return 0;
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    for (size_t i = 0; i < sizeof(safe_mode_indicator_hosts) / sizeof(*safe_mode_indicator_hosts); i++) {
        if (strcmp(name, safe_mode_indicator_hosts[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Safe Mode strips the LOADER, not the hook chain.
//
// Deliberately the last gate consulted at the call sites: it costs an access()
// on a path PID 1 takes for every spawn on the machine, and the cheaper checks
// short-circuit ahead of it.
static int is_stripped_by_safe_mode(const char *path) {
    if (!is_safe_mode_active()) return 0;
    if (is_safe_mode_indicator_host(path)) return 0;
    // xpcproxy carries the chain rather than any tweak. launchd spawns it and
    // it execs the real binary in place, so Dock, Finder and MenuBarAgent all
    // arrive through it -- stripping it here took the indicator hosts down with
    // everything else, and Safe Mode came up with nothing injected anywhere and
    // no way to say so. It is handed xpcproxy_hooks, never the loader, and
    // applies this same gate to whatever it goes on to exec.
    if (path && strstr(path, "xpcproxy") != NULL) return 0;
    return 1;
}

#define PER_PROCESS_TWEAKS_PLIST_PATH "/Library/TweakInject/Config/perProcessTweaks.plist"

// The parsed form of perProcessTweaks.plist: ONLY the keys whose entry carries
// TweakInjectionDisabled=true. Nothing else in that file matters at spawn time
// -- DisabledTweaks is per-tweak and belongs to the loader, inside the process.
//
// Parsed with libSystem alone, no CoreFoundation. Neither host links CF:
// /sbin/launchd pulls libSystem, libobjc, libc++, libauditd, libbsm and the
// Swift runtime, and /usr/libexec/xpcproxy pulls only libSystem and libobjc.
// CFPropertyListCreateWithData was therefore dragging the whole framework into
// PID 1 and into every exec on the machine, and running CF allocation and
// locking on the spawn path -- which is the last place that belongs.
//
// A parse failure leaves the list empty, which means "nothing is disabled" and
// so injects. That is the same way the CF version failed, and it is the safe
// direction: the blacklist and the Safe Mode gate are checked separately.
#define PER_PROC_MAX_KEYS    4096
#define PER_PROC_MAX_KEY_LEN 1024

static char **s_disabled_keys = NULL;
static size_t s_disabled_count = 0;
static time_t s_cached_per_proc_mtime = 0;
static int    s_cache_valid = 0;

// PID 1 spawns from several threads at once, so the cache above is shared
// mutable state on a concurrent path. Everything that touches it runs under
// this lock.
static pthread_mutex_t s_per_proc_lock = PTHREAD_MUTEX_INITIALIZER;

static void per_proc_free_cache(void) {
    if (s_disabled_keys) {
        for (size_t i = 0; i < s_disabled_count; i++) {
            free(s_disabled_keys[i]);
        }
        free(s_disabled_keys);
    }
    s_disabled_keys = NULL;
    s_disabled_count = 0;
    s_cache_valid = 0;
}

// Copy an XML text run, resolving the five predefined entities. Returns 0 if it
// does not fit, in which case the key is skipped rather than truncated -- a
// truncated path could match the wrong process.
static int per_proc_xml_unescape(const char *src, size_t len, char *out, size_t out_size) {
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        if (src[i] == '&') {
            size_t rem = len - i;
            if (rem >= 5 && strncmp(src + i, "&amp;",  5) == 0) { if (o + 1 >= out_size) return 0; out[o++] = '&';  i += 4; continue; }
            if (rem >= 4 && strncmp(src + i, "&lt;",   4) == 0) { if (o + 1 >= out_size) return 0; out[o++] = '<';  i += 3; continue; }
            if (rem >= 4 && strncmp(src + i, "&gt;",   4) == 0) { if (o + 1 >= out_size) return 0; out[o++] = '>';  i += 3; continue; }
            if (rem >= 6 && strncmp(src + i, "&quot;", 6) == 0) { if (o + 1 >= out_size) return 0; out[o++] = '"';  i += 5; continue; }
            if (rem >= 6 && strncmp(src + i, "&apos;", 6) == 0) { if (o + 1 >= out_size) return 0; out[o++] = '\''; i += 5; continue; }
        }
        if (o + 1 >= out_size) return 0;
        out[o++] = src[i];
    }
    out[o] = '\0';
    return 1;
}

static const char *per_proc_skip_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

// Does this <dict> span contain <key>TweakInjectionDisabled</key><true/>?
static int per_proc_span_disabled(const char *p, const char *end) {
    static const char kKey[] = "TweakInjectionDisabled";
    const size_t kKeyLen = sizeof(kKey) - 1;
    while (p < end) {
        const char *k = strstr(p, "<key>");
        if (!k || k >= end) break;
        k += 5;
        const char *ke = strstr(k, "</key>");
        if (!ke || ke > end) break;
        if ((size_t)(ke - k) == kKeyLen && strncmp(k, kKey, kKeyLen) == 0) {
            const char *v = per_proc_skip_ws(ke + 6, end);
            return (end - v) >= 7 && strncmp(v, "<true/>", 7) == 0;
        }
        p = ke + 6;
    }
    return 0;
}

// Walk the top-level <dict>, collecting the keys whose value dict is disabled.
// `buf` is NUL-terminated by the caller so strstr is safe.
static void per_proc_parse(const char *buf, size_t len) {
    const char *end = buf + len;
    const char *p = strstr(buf, "<dict>");
    if (!p) { s_cache_valid = 1; return; }
    p += 6;

    s_disabled_keys = calloc(PER_PROC_MAX_KEYS, sizeof(char *));
    if (!s_disabled_keys) return;

    char key[PER_PROC_MAX_KEY_LEN];
    while (p < end && s_disabled_count < PER_PROC_MAX_KEYS) {
        const char *k = strstr(p, "<key>");
        if (!k || k >= end) break;
        const char *ke = strstr(k + 5, "</key>");
        if (!ke || ke > end) break;

        int ok = per_proc_xml_unescape(k + 5, (size_t)(ke - (k + 5)), key, sizeof(key));
        const char *v = per_proc_skip_ws(ke + 6, end);

        if ((end - v) >= 6 && strncmp(v, "<dict>", 6) == 0) {
            // Matching </dict>, counting nested ones so an entry that grows a
            // sub-dictionary later cannot make us mis-pair the close tag.
            int depth = 1;
            const char *q = v + 6;
            const char *close = NULL;
            while (q < end && depth > 0) {
                const char *o = strstr(q, "<dict>");
                const char *c = strstr(q, "</dict>");
                if (!c || c >= end) break;
                if (o && o < c) { depth++; q = o + 6; }
                else            { depth--; q = c + 7; if (depth == 0) close = c; }
            }
            if (!close) break;
            if (ok && per_proc_span_disabled(v + 6, close)) {
                char *dup = strdup(key);
                if (dup) s_disabled_keys[s_disabled_count++] = dup;
            }
            p = close + 7;
        } else {
            // Not a dictionary value. Our schema never produces one at the top
            // level; skip past it rather than guessing at its shape.
            p = v;
        }
    }
    s_cache_valid = 1;
}

static void reload_per_process_plist_if_needed(void) {
    struct stat st;
    if (stat(PER_PROCESS_TWEAKS_PLIST_PATH, &st) != 0) {
        per_proc_free_cache();
        s_cached_per_proc_mtime = 0;
        return;
    }
    if (s_cache_valid && st.st_mtime == s_cached_per_proc_mtime) {
        return;
    }
    per_proc_free_cache();

    int fd = open(PER_PROCESS_TWEAKS_PLIST_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;

    off_t size = lseek(fd, 0, SEEK_END);
    if (size <= 0 || size > 5 * 1024 * 1024 || lseek(fd, 0, SEEK_SET) != 0) {
        close(fd);
        return;
    }

    char *buf = malloc((size_t)size + 1);
    if (!buf) {
        close(fd);
        return;
    }

    size_t got = 0;
    while (got < (size_t)size) {
        ssize_t n = read(fd, buf + got, (size_t)size - got);
        if (n > 0)                      { got += (size_t)n; continue; }
        if (n < 0 && errno == EINTR)    { continue; }
        break;
    }
    close(fd);

    if (got == (size_t)size) {
        buf[size] = '\0';
        per_proc_parse(buf, (size_t)size);
        s_cached_per_proc_mtime = st.st_mtime;
    }
    free(buf);
}

static int is_entry_disabled(const char *key_str) {
    if (!key_str || key_str[0] == '\0') return 0;
    for (size_t i = 0; i < s_disabled_count; i++) {
        if (strcmp(s_disabled_keys[i], key_str) == 0) return 1;
    }
    return 0;
}

// Caller holds s_per_proc_lock.
static int per_process_disabled_locked(const char *path) {
    reload_per_process_plist_if_needed();
    if (s_disabled_count == 0) return 0;

    // 1. Direct path check
    if (is_entry_disabled(path)) return 1;

    // 2. Basename check
    const char *base = strrchr(path, '/');
    const char *base_name = base ? base + 1 : path;
    if (is_entry_disabled(base_name)) return 1;

    // 3. Enclosing .app / .bundle container check
    const char *app_ext = strstr(path, ".app/");
    if (app_ext) {
        size_t app_path_len = (size_t)(app_ext - path + 4);
        char app_path[1024];
        if (app_path_len < sizeof(app_path)) {
            memcpy(app_path, path, app_path_len);
            app_path[app_path_len] = '\0';
            if (is_entry_disabled(app_path)) return 1;

            const char *app_slash = strrchr(app_path, '/');
            const char *app_name_start = app_slash ? app_slash + 1 : app_path;
            char app_name[256];
            size_t app_name_len = (size_t)(app_path + app_path_len - 4 - app_name_start);
            if (app_name_len < sizeof(app_name)) {
                memcpy(app_name, app_name_start, app_name_len);
                app_name[app_name_len] = '\0';
                if (is_entry_disabled(app_name)) return 1;
            }
        }
    }

    return 0;
}

static int is_process_injection_disabled_in_plist(const char *path) {
    if (!path || path[0] == '\0') return 0;

    // Held across the reload AND the lookups. Two spawns racing through a
    // reload would otherwise both CFRelease the old dictionary -- an
    // over-release inside launchd, which takes the machine with it -- and a
    // reader walking a dictionary another thread just released is the same
    // bug wearing a different hat.
    pthread_mutex_lock(&s_per_proc_lock);
    int disabled = per_process_disabled_locked(path);
    pthread_mutex_unlock(&s_per_proc_lock);
    return disabled;
}

static int posix_spawn_launchd(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict], void *original_function) {
    
    char *const *envp = __envp;
    char *allocated_tokens[SANDBOX_GRANT_COUNT];
    size_t allocated_token_count = 0;
    char **allocated_envp = NULL;
    int armed_injection = 0;

    const char *base_name = path ? strrchr(path, '/') : NULL;
    base_name = base_name ? base_name + 1 : path;
    int is_launchd_binary = (path && (strcmp(path, "/sbin/launchd") == 0 || (base_name && strcmp(base_name, "launchd") == 0)));
    int is_reexec = is_setexec_attr(attrp) || getpid() == 1;

    // 1. If PID 1 is re-executing itself (e.g. `launchctl reboot userspace`):
    // Inject launchd_hooks.dylib into the new launchd image so hooks persist across userspace reboots!
    if (is_launchd_binary && is_reexec && !is_injection_disabled()) {
        char *dylib_to_inject = "DYLD_INSERT_LIBRARIES=" LAUNCHD_HOOKS_DYLIB_PATH;
        
        size_t count = 0;
        if (__envp) {
            while (__envp[count] != NULL) count++;
        }
        
        char **new_envp = malloc((count + SANDBOX_GRANT_COUNT + 4) * sizeof(char *));
        if (new_envp) {
            size_t dst = 0;
            for (size_t i = 0; i < count; i++) {
                if (strncmp(__envp[i], "DYLD_INSERT_LIBRARIES=", 22) == 0) continue;
                if (strncmp(__envp[i], "TL_SANDBOX_TOKEN", 16) == 0) continue;
                if (strncmp(__envp[i], "SANDBOX_TOKEN=", 14) == 0) continue;
                new_envp[dst++] = __envp[i];
            }
            
            new_envp[dst++] = dylib_to_inject;
            
            dst = append_sandbox_tokens(new_envp, dst, allocated_tokens, &allocated_token_count);
            
            new_envp[dst] = NULL;
            envp = new_envp;
            allocated_envp = new_envp;
            armed_injection = 1;
        }
        TL_LOG("[LaunchdHook] Arming launchd_hooks injection for PID 1 re-exec (/sbin/launchd)");
        goto exec;
    }
    
    // The marker says "launchd_hooks is live in PID 1", which is true whether or
    // not THIS spawn ends up armed -- so it is written before every early exit
    // below. It used to sit after the strip branch, and /var/run is cleared
    // during a userspace reboot AFTER the re-executed launchd has run its
    // constructor: in Safe Mode almost every spawn takes that branch, so the
    // marker was never rewritten and the app reported launchd as unhooked while
    // it was plainly hooked.
    if (access(HOOKED_MARKER_PATH, F_OK) != 0) {
        int marker = open(HOOKED_MARKER_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK | O_CLOEXEC, 0644);
        if (marker >= 0) close(marker);
    }

    // 2. Blacklisted or per-process disabled: strip all injection variables cleanly
    if (is_path_blacklisted_from_injection(path) || is_injection_disabled() ||
        is_process_injection_disabled_in_plist(path) || is_stripped_by_safe_mode(path)) {
        envp = strip_injection_env(__envp, &allocated_envp);
        goto exec;
    }
    
    // 3. Regular daemons (WindowServer, etc.) & xpcproxy
    if (path != NULL) {
        int is_xpcproxy = strstr(path, "xpcproxy") != NULL;
        if (is_xpcproxy && access(XPCPROXY_HOOKS_DYLIB_PATH, F_OK) != 0) {
            goto exec;
        }
        char *dylib_to_inject = is_xpcproxy ? "DYLD_INSERT_LIBRARIES=" XPCPROXY_HOOKS_DYLIB_PATH : "DYLD_INSERT_LIBRARIES=" TWEAK_LOADER_DYLIB_PATH;
        
        size_t count = 0;
        if (__envp != NULL) {
            while (__envp[count] != NULL) {
                count++;
            }
        }
        
        // Allocate space for cleaned entries + new injection vars + NULL terminator
        char **new_envp = malloc((count + SANDBOX_GRANT_COUNT + 4) * sizeof(char *));
        if (new_envp) {
            size_t dst = 0;
            if (__envp != NULL) {
                for (size_t i = 0; i < count; i++) {
                    // Deduplicate and strip any existing injection variables
                    if (strncmp(__envp[i], "DYLD_INSERT_LIBRARIES=", 22) == 0) continue;
                    if (strncmp(__envp[i], "TL_SANDBOX_TOKEN", 16) == 0) continue;
                    if (strncmp(__envp[i], "SANDBOX_TOKEN=", 14) == 0) continue;
                    new_envp[dst++] = __envp[i];
                }
            }
            
            new_envp[dst++] = dylib_to_inject;
            
            dst = append_sandbox_tokens(new_envp, dst, allocated_tokens, &allocated_token_count);
            
            new_envp[dst] = NULL;
            envp = new_envp;
            allocated_envp = new_envp;
            armed_injection = 1;
        }
    }

exec:;
    int ret = ((int (*)(pid_t * __restrict, const char * __restrict, const posix_spawn_file_actions_t *, const posix_spawnattr_t * __restrict, char *const __argv[__restrict], char *const __envp[__restrict]))original_function)(pid, path, file_actions, attrp, __argv, envp);
    
    if (ret == 0 && armed_injection && path) {
        TL_LOG("[LaunchdHook] Armed tweakLoader injection for %s (pid %d)", path, pid ? *pid : 0);
    }

    for (size_t i = 0; i < allocated_token_count; i++) {
        free(allocated_tokens[i]);
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

/// Issue one token per table entry, once, at load.
///
/// The trailing-slash retry is kept from the hand-written version: issuing
/// against a directory sometimes only succeeds without it, and a grant that
/// silently fails costs a feature rather than announcing itself.
static void issue_sandbox_tokens(void) {
    if (!_sandbox_extension_issue_file) return;

    for (size_t i = 0; i < SANDBOX_READ_COUNT; i++) {
        char *t = _sandbox_extension_issue_file("com.apple.app-sandbox.read", kSandboxRead[i], 0);
        if (t) sandbox_tokens[sandbox_token_count++] = t;
    }
    for (size_t i = 0; i < SANDBOX_RW_COUNT; i++) {
        char *t = _sandbox_extension_issue_file("com.apple.app-sandbox.read-write", kSandboxReadWrite[i], 0);
        if (!t) {
            char trimmed[1024];
            size_t len = strlen(kSandboxReadWrite[i]);
            if (len && len < sizeof(trimmed) && kSandboxReadWrite[i][len - 1] == '/') {
                memcpy(trimmed, kSandboxReadWrite[i], len - 1);
                trimmed[len - 1] = '\0';
                t = _sandbox_extension_issue_file("com.apple.app-sandbox.read-write", trimmed, 0);
            }
        }
        if (t) sandbox_tokens[sandbox_token_count++] = t;
    }
}

static void __attribute__((constructor)) init_launchd_hooks(void) {
    setenv("DYLD_INSERT_LIBRARIES", LAUNCHD_HOOKS_DYLIB_PATH, 1);
    
    void* libSystemSandboxHandle = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (libSystemSandboxHandle) {
        _sandbox_extension_issue_file = dlsym(libSystemSandboxHandle, "sandbox_extension_issue_file");
        if (_sandbox_extension_issue_file) {
            issue_sandbox_tokens();
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
