//
//  tweakLoader.c
//  tweakLoader
//
//  Created by Dora Orak on 2.04.2025.
//
//  System-wide dynamic tweak loader for macOS.
//  Injected via launchd / DYLD_INSERT_LIBRARIES early in the process lifecycle before main().
//

#include <CoreFoundation/CoreFoundation.h>
#include <crt_externs.h>
#include <dirent.h>
#include <dlfcn.h>
#include <libproc.h>
#include <objc/runtime.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define tl_log_path              "/Library/TweakInject/logs/tweakinject.log"
#define tl_log_fallback          "/tmp/tweakinject.log"
#define tl_active_path           "/tmp/.tweakloader_active"
#define tl_bundles_path          "/Library/TweakInject/Tweaks/Bundles/"
#define tl_dylibs_path           "/Library/TweakInject/Tweaks/DynamicLibraries/"
#define tl_safe_mode_dir         "/Library/TweakInject/SafeMode/"
#define tl_safe_mode_dylib_path  tl_safe_mode_dir "libsafeMode.dylib"
#define tl_safe_mode_pill_path   tl_safe_mode_dir "libsafeModePill.dylib"
// Persistent, not /var/run: that is cleared by the userspace reboot Safe Mode
// uses to take effect. Mirrors /Library/TweakInject/.disabled.
#define tl_safe_mode_marker      tl_safe_mode_dir ".safemode"
#define tl_deny_list_path        "/Library/TweakInject/Config/denyInjectionList.plist"
#define tl_per_proc_tweaks_path  "/Library/TweakInject/Config/perProcessTweaks.plist"

/// Safe, deadlock-free file logging that avoids os_log / logd IPC deadlocks.
static void tl_safe_log(const char* fmt, ...) {
    const char* prog = getprogname();
    if (prog && (strcmp(prog, "logd") == 0 || strcmp(prog, "diagnosticd") == 0)) {
        return;
    }

    char body[1024];
    va_list args;
    va_start(args, fmt);
    int body_len = vsnprintf(body, sizeof(body) - 2, fmt, args);
    va_end(args);

    if (body_len <= 0) return;

    if (body[body_len - 1] != '\n') {
        body[body_len] = '\n';
        body[body_len + 1] = '\0';
        body_len++;
    }

    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

    char line[1280];
    int line_len = snprintf(line, sizeof(line), "[%s] [%s:%d] %s", time_str, prog ? prog : "unknown", getpid(), body);
    if (line_len <= 0) return;

    int fd = open(tl_log_path, O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK | O_CLOEXEC, 0666);
    if (fd < 0) {
        fd = open(tl_log_fallback, O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK | O_CLOEXEC, 0666);
    }
    if (fd >= 0) {
        write(fd, line, (size_t)line_len);
        close(fd);
    }

    // Touch active marker
    int marker = open(tl_active_path, O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK | O_CLOEXEC, 0666);
    if (marker >= 0) {
        char hb[64];
        int hb_len = snprintf(hb, sizeof(hb), "%ld %d\n", (long)now, getpid());
        if (hb_len > 0) write(marker, hb, (size_t)hb_len);
        close(marker);
    }
}

#define TL_LOG(fmt, ...) tl_safe_log(fmt, ##__VA_ARGS__)

// MARK: - Helper Functions

/// Checks if a CFArray of strings contains a given needle string.
static int tl_string_array_contains(CFArrayRef array, const char* needle, int substring, int case_insensitive) {
    if (!array || CFGetTypeID(array) != CFArrayGetTypeID() || !needle) {
        return 0;
    }

    CFIndex count = CFArrayGetCount(array);
    for (CFIndex i = 0; i < count; i++) {
        CFTypeRef entry = CFArrayGetValueAtIndex(array, i);
        if (!entry || CFGetTypeID(entry) != CFStringGetTypeID()) {
            continue;
        }

        char buf[1024];
        if (!CFStringGetCString((CFStringRef)entry, buf, sizeof(buf), kCFStringEncodingUTF8)) {
            continue;
        }

        if (substring) {
            if (case_insensitive ? (strcasestr(needle, buf) != NULL) : (strstr(needle, buf) != NULL)) {
                return 1;
            }
        } else {
            if (case_insensitive ? (strcasecmp(needle, buf) == 0) : (strcmp(needle, buf) == 0)) {
                return 1;
            }
        }
    }
    return 0;
}

/// Safely reads and parses a Property List (.plist) file from disk with a size sanity check.
static CFPropertyListRef tl_read_plist_file(const char* file_path) {
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0 || st.st_size > 2 * 1024 * 1024) {
        close(fd);
        return NULL;
    }

    void* buf = malloc((size_t)st.st_size);
    if (!buf) {
        close(fd);
        return NULL;
    }

    ssize_t got = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (got != st.st_size) {
        free(buf);
        return NULL;
    }

    CFDataRef data = CFDataCreate(kCFAllocatorDefault, (const UInt8*)buf, (CFIndex)got);
    free(buf);
    if (!data) {
        return NULL;
    }

    CFErrorRef error = NULL;
    CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault, data, kCFPropertyListImmutable, NULL, &error);
    CFRelease(data);

    if (error) {
        CFRelease(error);
    }
    return plist;
}

// MARK: - Per-Process Rule Lookup

/// Looks up process rules in perProcessTweaks.plist matching in priority: exec_path, main_bundle_id, proc_name.
static CFDictionaryRef tl_find_process_rule_entry(CFDictionaryRef dict, const char* proc_name, const char* exec_path, CFStringRef main_bundle_id) {
    if (!dict || CFGetTypeID(dict) != CFDictionaryGetTypeID()) {
        return NULL;
    }

    // 1. Direct match with full executable path
    if (exec_path && exec_path[0] != '\0') {
        CFStringRef cf_exec = CFStringCreateWithCString(kCFAllocatorDefault, exec_path, kCFStringEncodingUTF8);
        if (cf_exec) {
            CFTypeRef val = CFDictionaryGetValue(dict, cf_exec);
            CFRelease(cf_exec);
            if (val && CFGetTypeID(val) == CFDictionaryGetTypeID()) {
                return (CFDictionaryRef)val;
            }
        }
    }

    // 2. Direct match with main bundle identifier
    if (main_bundle_id) {
        CFTypeRef val = CFDictionaryGetValue(dict, main_bundle_id);
        if (val && CFGetTypeID(val) == CFDictionaryGetTypeID()) {
            return (CFDictionaryRef)val;
        }
    }

    // 3. Direct match with process base name
    if (proc_name && proc_name[0] != '\0') {
        CFStringRef cf_proc = CFStringCreateWithCString(kCFAllocatorDefault, proc_name, kCFStringEncodingUTF8);
        if (cf_proc) {
            CFTypeRef val = CFDictionaryGetValue(dict, cf_proc);
            CFRelease(cf_proc);
            if (val && CFGetTypeID(val) == CFDictionaryGetTypeID()) {
                return (CFDictionaryRef)val;
            }
        }
    }

    return NULL;
}



/// Checks if a specific tweak is disabled for this process in perProcessTweaks.plist.
static int tl_is_tweak_disabled_for_process(const char* tweak_base_name, const char* proc_name, const char* exec_path, CFStringRef main_bundle_id, CFPropertyListRef per_proc_plist) {
    if (!per_proc_plist || !tweak_base_name || CFGetTypeID(per_proc_plist) != CFDictionaryGetTypeID()) {
        return 0;
    }

    CFDictionaryRef dict = (CFDictionaryRef)per_proc_plist;
    CFDictionaryRef proc_entry = tl_find_process_rule_entry(dict, proc_name, exec_path, main_bundle_id);

    if (proc_entry) {
        CFArrayRef disabled_tweaks = (CFArrayRef)CFDictionaryGetValue(proc_entry, CFSTR("DisabledTweaks"));
        if (disabled_tweaks && CFGetTypeID(disabled_tweaks) == CFArrayGetTypeID()) {
            return tl_string_array_contains(disabled_tweaks, tweak_base_name, 0, 1);
        }
    }

    return 0;
}

// MARK: - Safe Boot Detection

/// Checks if macOS booted into Safe Mode via kern.bootargs.
static int tl_is_booted_in_safe_mode(void) {
    size_t size = 0;
    if (sysctlbyname("kern.bootargs", NULL, &size, NULL, 0) != 0 || size == 0)
        return 0;

    char* boot_args = malloc(size);
    if (!boot_args)
        return 0;

    if (sysctlbyname("kern.bootargs", boot_args, &size, NULL, 0) != 0) {
        free(boot_args);
        return 0;
    }

    int is_safe = (strstr(boot_args, "-x") != NULL);
    free(boot_args);
    return is_safe;
}

// MARK: - Filter Plist Evaluation

/// Evaluates a tweak's Filter dictionary against the current process.
static bool tl_is_injection_allowed_for_process_by_filter(
    CFDictionaryRef filters,
    const char* proc_name,
    const char* exec_path,
    CFBundleRef main_bundle,
    const char* bundle_path,
    CFStringRef main_bundle_id
) {
    if (!filters || CFGetTypeID(filters) != CFDictionaryGetTypeID()) {
        return false;
    }

    // 1. ExcludeBundles (Hard veto: if matched, reject tweak immediately)
    CFArrayRef exclude_bundles = (CFArrayRef)CFDictionaryGetValue(filters, CFSTR("ExcludeBundles"));
    if (exclude_bundles && CFGetTypeID(exclude_bundles) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(exclude_bundles);
        for (CFIndex i = 0; i < count; i++) {
            CFTypeRef item = CFArrayGetValueAtIndex(exclude_bundles, i);
            if (!item || CFGetTypeID(item) != CFStringGetTypeID()) continue;
            CFStringRef excl_id = (CFStringRef)item;

            if (CFBundleGetBundleWithIdentifier(excl_id) != NULL) {
                return false;
            }
            if (main_bundle_id && CFStringCompare(main_bundle_id, excl_id, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                return false;
            }
        }
    }

    // 2. Type Gate ("All", "App", "Binary" - Hard veto on mismatch)
    CFStringRef type_filter = (CFStringRef)CFDictionaryGetValue(filters, CFSTR("Type"));
    bool is_app_proc = false;
    if ((bundle_path[0] != '\0' && strstr(bundle_path, ".app") != NULL) ||
        (exec_path && strstr(exec_path, ".app/") != NULL)) {
        is_app_proc = true;
    }

    if (type_filter && CFGetTypeID(type_filter) == CFStringGetTypeID()) {
        if (CFStringCompare(type_filter, CFSTR("App"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (!is_app_proc) return false;
        } else if (CFStringCompare(type_filter, CFSTR("Binary"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (is_app_proc) return false;
        }
    }

    // 3. Privilege Gate ("Any" | "Root" | "User" - hard veto on mismatch)
    CFStringRef priv_filter = (CFStringRef)CFDictionaryGetValue(filters, CFSTR("Privilege"));
    if (priv_filter && CFGetTypeID(priv_filter) == CFStringGetTypeID()) {
        uid_t euid = geteuid();
        if (CFStringCompare(priv_filter, CFSTR("Root"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (euid != 0) return false;
        } else if (CFStringCompare(priv_filter, CFSTR("User"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (euid == 0) return false;
        }
    }

    // 4. CoreFoundationVersion Gate ([min] or [min, max])
    CFArrayRef cf_version_filter = (CFArrayRef)CFDictionaryGetValue(filters, CFSTR("CoreFoundationVersion"));
    if (cf_version_filter && CFGetTypeID(cf_version_filter) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(cf_version_filter);
        if (count >= 1) {
            CFTypeRef min_val_ref = CFArrayGetValueAtIndex(cf_version_filter, 0);
            if (min_val_ref && CFGetTypeID(min_val_ref) == CFNumberGetTypeID()) {
                double min_val = 0;
                CFNumberGetValue((CFNumberRef)min_val_ref, kCFNumberDoubleType, &min_val);
                if (kCFCoreFoundationVersionNumber < min_val) {
                    return false;
                }
            }
        }
        if (count >= 2) {
            CFTypeRef max_val_ref = CFArrayGetValueAtIndex(cf_version_filter, 1);
            if (max_val_ref && CFGetTypeID(max_val_ref) == CFNumberGetTypeID()) {
                double max_val = 0;
                CFNumberGetValue((CFNumberRef)max_val_ref, kCFNumberDoubleType, &max_val);
                if (kCFCoreFoundationVersionNumber >= max_val) {
                    return false;
                }
            }
        }
    }

    // 5. Criteria Matching: Bundles, Classes, Executables (OR semantics)
    CFArrayRef bundles_filter = (CFArrayRef)CFDictionaryGetValue(filters, CFSTR("Bundles"));
    if (bundles_filter && CFGetTypeID(bundles_filter) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(bundles_filter);
        for (CFIndex i = 0; i < count; i++) {
            CFTypeRef item = CFArrayGetValueAtIndex(bundles_filter, i);
            if (!item || CFGetTypeID(item) != CFStringGetTypeID()) continue;
            CFStringRef req_id = (CFStringRef)item;

            if (CFBundleGetBundleWithIdentifier(req_id) != NULL) {
                return true;
            }
            if (main_bundle_id && CFStringCompare(main_bundle_id, req_id, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                return true;
            }
        }
    }

    CFArrayRef classes_filter = (CFArrayRef)CFDictionaryGetValue(filters, CFSTR("Classes"));
    if (classes_filter && CFGetTypeID(classes_filter) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(classes_filter);
        for (CFIndex i = 0; i < count; i++) {
            CFTypeRef item = CFArrayGetValueAtIndex(classes_filter, i);
            if (!item || CFGetTypeID(item) != CFStringGetTypeID()) continue;
            char class_name_buf[256];
            if (CFStringGetCString((CFStringRef)item, class_name_buf, sizeof(class_name_buf), kCFStringEncodingUTF8)) {
                if (objc_getClass(class_name_buf) != nil) {
                    return true;
                }
            }
        }
    }

    CFArrayRef executables_filter = (CFArrayRef)CFDictionaryGetValue(filters, CFSTR("Executables"));
    if (executables_filter && CFGetTypeID(executables_filter) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(executables_filter);
        const char* exec_base_name = (exec_path ? strrchr(exec_path, '/') : NULL);
        exec_base_name = exec_base_name ? exec_base_name + 1 : exec_path;

        for (CFIndex i = 0; i < count; i++) {
            CFTypeRef item = CFArrayGetValueAtIndex(executables_filter, i);
            if (!item || CFGetTypeID(item) != CFStringGetTypeID()) continue;
            char exec_name_buf[256];
            if (CFStringGetCString((CFStringRef)item, exec_name_buf, sizeof(exec_name_buf), kCFStringEncodingUTF8)) {
                if (proc_name && strcasecmp(proc_name, exec_name_buf) == 0) {
                    return true;
                }
                if (exec_base_name && strcasecmp(exec_base_name, exec_name_buf) == 0) {
                    return true;
                }
            }
        }
    }

    bool has_any_criteria = (bundles_filter && CFGetTypeID(bundles_filter) == CFArrayGetTypeID() && CFArrayGetCount(bundles_filter) > 0) ||
                            (classes_filter && CFGetTypeID(classes_filter) == CFArrayGetTypeID() && CFArrayGetCount(classes_filter) > 0) ||
                            (executables_filter && CFGetTypeID(executables_filter) == CFArrayGetTypeID() && CFArrayGetCount(executables_filter) > 0);

    if (!has_any_criteria && (type_filter != NULL || priv_filter != NULL)) {
        return true;
    }

    return false;
}

static int tl_filter_bundle_files(const struct dirent* entry) {
    if (!entry || entry->d_name[0] == '.') {
        return 0;
    }
    size_t len = strlen(entry->d_name);
    return (len > 7 && strcmp(entry->d_name + len - 7, ".bundle") == 0) ? 1 : 0;
}

static int tl_filter_plist_files(const struct dirent* entry) {
    if (!entry || entry->d_name[0] == '.') {
        return 0;
    }
    size_t len = strlen(entry->d_name);
    return (len > 6 && strcmp(entry->d_name + len - 6, ".plist") == 0) ? 1 : 0;
}

/// Helper to find the dynamic library executable inside a .bundle directory
static bool tl_find_bundle_executable(const char* bundle_path, char* out_exec_path, size_t out_size) {
    char macos_dir[1024];
    snprintf(macos_dir, sizeof(macos_dir), "%s/Contents/MacOS", bundle_path);

    DIR* dir = opendir(macos_dir);
    if (dir) {
        struct dirent* ent;
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            snprintf(out_exec_path, out_size, "%s/%s", macos_dir, ent->d_name);
            closedir(dir);
            return true;
        }
        closedir(dir);
    }

    // Fallback: search direct dynamic library in bundle root
    DIR* root_dir = opendir(bundle_path);
    if (root_dir) {
        struct dirent* ent;
        while ((ent = readdir(root_dir)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            size_t nlen = strlen(ent->d_name);
            if (nlen > 6 && strcmp(ent->d_name + nlen - 6, ".dylib") == 0) {
                snprintf(out_exec_path, out_size, "%s/%s", bundle_path, ent->d_name);
                closedir(root_dir);
                return true;
            }
        }
        closedir(root_dir);
    }
    return false;
}

/// Helper to find and read filter plist inside or alongside a .bundle
static CFPropertyListRef tl_read_bundle_filter(const char* bundle_path, const char* tweak_name) {
    char path[1024];

    // 1. Contents/Resources/Filter.plist
    snprintf(path, sizeof(path), "%s/Contents/Resources/Filter.plist", bundle_path);
    if (access(path, F_OK) == 0) {
        CFPropertyListRef plist = tl_read_plist_file(path);
        if (plist) return plist;
    }

    // 2. Contents/Filter.plist
    snprintf(path, sizeof(path), "%s/Contents/Filter.plist", bundle_path);
    if (access(path, F_OK) == 0) {
        CFPropertyListRef plist = tl_read_plist_file(path);
        if (plist) return plist;
    }

    // 3. Contents/Resources/<TweakName>.plist
    snprintf(path, sizeof(path), "%s/Contents/Resources/%s.plist", bundle_path, tweak_name);
    if (access(path, F_OK) == 0) {
        CFPropertyListRef plist = tl_read_plist_file(path);
        if (plist) return plist;
    }

    // 4. Outside <TweakName>.plist
    snprintf(path, sizeof(path), "%s%s.plist", tl_bundles_path, tweak_name);
    if (access(path, F_OK) == 0) {
        CFPropertyListRef plist = tl_read_plist_file(path);
        if (plist) return plist;
    }

    // 5. Contents/Info.plist
    snprintf(path, sizeof(path), "%s/Contents/Info.plist", bundle_path);
    if (access(path, F_OK) == 0) {
        CFPropertyListRef plist = tl_read_plist_file(path);
        if (plist) return plist;
    }

    return NULL;
}

static int64_t (*_sandbox_extension_consume)(const char* token) = NULL;

// MARK: - TweakLoader Entrypoint (Constructor)

__attribute__((constructor)) static void tl_init_tweak_loader(void) {
    // Unset DYLD_INSERT_LIBRARIES so any child processes spawned do not unintentionally inherit injection
    unsetenv("DYLD_INSERT_LIBRARIES");

    // 1. Consume App Sandbox extensions FIRST so subsequent access() checks succeed in sandboxed apps (Notes, Mail, etc.)
    void* lib_sandbox_handle = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (lib_sandbox_handle) {
        _sandbox_extension_consume = dlsym(lib_sandbox_handle, "sandbox_extension_consume");
        if (_sandbox_extension_consume) {
            // TL_SANDBOX_TOKEN_0..N-1, one per entry in launchd_hooks' grant
            // tables. Consume until the first gap rather than a fixed pair, so
            // adding a grant there needs no change here.
            int consumed = 0;
            for (size_t i = 0; ; i++) {
                char name[64];
                snprintf(name, sizeof(name), "TL_SANDBOX_TOKEN_%zu", i);
                char *token = getenv(name);
                if (!token) break;
                if (_sandbox_extension_consume(token) > 0) consumed++;
            }

            if (consumed > 0) {
                TL_LOG("[TweakLoader] Consumed %d sandbox extension(s)", consumed);
            }
        }
    }

    // 2. Pre-flight check: if injection is suspended or essential dependency missing, abort
    if (access("/var/run/tweakinject.disabled", F_OK) == 0 ||
        access("/Library/TweakInject/.disabled", F_OK) == 0) {
        TL_LOG("[TweakLoader] Injection is suspended, skipping");
        return;
    }
    if (access("/Library/TweakInject/libellekit.dylib", F_OK) != 0) {
        TL_LOG("[TweakLoader] Essential dependency libellekit.dylib is missing, skipping");
        return;
    }

    // 3. Identify current process
    char process_name[256] = {0};
    proc_name(getpid(), process_name, sizeof(process_name));

    char exec_path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (proc_pidpath(getpid(), exec_path, sizeof(exec_path)) <= 0) {
        exec_path[0] = '\0';
    }

    CFBundleRef main_bundle = CFBundleGetMainBundle();
    CFStringRef main_bundle_id = main_bundle ? CFBundleGetIdentifier(main_bundle) : NULL;
    char bundle_path[1024] = {0};
    if (main_bundle) {
        CFURLRef bundle_url = CFBundleCopyBundleURL(main_bundle);
        if (bundle_url) {
            CFStringRef bundle_url_string = CFURLCopyPath(bundle_url);
            if (bundle_url_string) {
                CFStringGetCString(bundle_url_string, bundle_path, sizeof(bundle_path), kCFStringEncodingUTF8);
                CFRelease(bundle_url_string);
            }
            CFRelease(bundle_url);
        }
    }

    TL_LOG("[TweakLoader] Active in %s (pid %d)", process_name[0] ? process_name : "process", getpid());

    // 4. SafeMode check
    if (strcmp(process_name, "Dock") == 0 || strcmp(process_name, "WallpaperVideoExtension") == 0 ||
        strcmp(process_name, "WallpaperImageExtension") == 0 || strcmp(process_name, "Finder") == 0 ||
        strcmp(process_name, "WindowServer") == 0 || strcmp(process_name, "Spotlight") == 0) {
        dlopen(tl_safe_mode_dylib_path, RTLD_NOW);
    }

    if (tl_is_booted_in_safe_mode()) {
        TL_LOG("[TweakLoader] SafeBoot enabled, skipping injection");
        return;
    }

    // The root-owned marker, and only that. This used to also count any *.txt
    // in the Safe Mode directory, which is why that directory now holds the two
    // Safe Mode dylibs and nothing else.
    //
    // Reaching here in Safe Mode at all means this process is one of the
    // indicator hosts: the spawn hooks strip injection from everything else, so
    // the loader is not even mapped into the rest of the machine.
    if (access(tl_safe_mode_marker, F_OK) == 0) {
        // ControlCenter only, matching safe_mode_indicator_hosts[] in the spawn
        // hooks: these two must name the same process or the host gets the
        // loader and never the pill, or loads the pill and duplicates the item.
        if (strcmp(process_name, "ControlCenter") == 0) {
            dlopen(tl_safe_mode_pill_path, RTLD_NOW);
        }
        TL_LOG("[TweakLoader] SafeMode active, handled indicator for %s, skipping regular tweaks", process_name);
        return;
    }

    // 6. Scan and load tweaks in deterministic alphabetical order
    CFPropertyListRef per_proc_plist = tl_read_plist_file(tl_per_proc_tweaks_path);
    char processed_tweaks[256][256];
    int processed_count = 0;

    // Pass 1: Scan self-contained .bundle packages in tl_bundles_path
    struct dirent** bundle_list = NULL;
    int bundle_count = scandir(tl_bundles_path, &bundle_list, tl_filter_bundle_files, alphasort);
    if (bundle_count > 0) {
        for (int i = 0; i < bundle_count; i++) {
            const char* entry_name = bundle_list[i]->d_name;
            size_t name_len = strlen(entry_name);
            char tweak_base_name[256] = {0};

            if (name_len > 7 && strcmp(entry_name + name_len - 7, ".bundle") == 0) {
                memcpy(tweak_base_name, entry_name, name_len - 7);
                tweak_base_name[name_len - 7] = '\0';
            } else {
                snprintf(tweak_base_name, sizeof(tweak_base_name), "%s", entry_name);
            }

            if (processed_count < 256) {
                snprintf(processed_tweaks[processed_count++], sizeof(processed_tweaks[0]), "%s", tweak_base_name);
            }

            // Check per-process disable
            if (tl_is_tweak_disabled_for_process(tweak_base_name, process_name, exec_path, main_bundle_id, per_proc_plist)) {
                free(bundle_list[i]);
                continue;
            }

            char bundle_full_path[1024];
            snprintf(bundle_full_path, sizeof(bundle_full_path), "%s%s", tl_bundles_path, entry_name);

            char binary_full_path[1024] = {0};
            if (!tl_find_bundle_executable(bundle_full_path, binary_full_path, sizeof(binary_full_path))) {
                free(bundle_list[i]);
                continue;
            }

            CFPropertyListRef plist = tl_read_bundle_filter(bundle_full_path, tweak_base_name);
            if (!plist) {
                free(bundle_list[i]);
                continue;
            }

            if (CFGetTypeID(plist) == CFDictionaryGetTypeID()) {
                CFDictionaryRef root_dict = (CFDictionaryRef)plist;
                CFDictionaryRef filter_dict = (CFDictionaryRef)CFDictionaryGetValue(root_dict, CFSTR("Filter"));
                if (!filter_dict || CFGetTypeID(filter_dict) != CFDictionaryGetTypeID()) {
                    filter_dict = root_dict;
                }

                if (tl_is_injection_allowed_for_process_by_filter(filter_dict, process_name, exec_path, main_bundle, bundle_path, main_bundle_id)) {
                    TL_LOG("[TweakLoader] Injecting bundle %s into %s (pid %d)", binary_full_path, process_name, getpid());
                    void* handle = dlopen(binary_full_path, RTLD_NOW);
                    if (handle) {
                        TL_LOG("[TweakLoader] Injected %s successfully", binary_full_path);
                    } else {
                        const char* dl_err = dlerror();
                        TL_LOG("[TweakLoader] dlopen failed for %s: %s", binary_full_path, dl_err ? dl_err : "unknown");
                    }
                }
            }

            CFRelease(plist);
            free(bundle_list[i]);
        }
        free(bundle_list);
    }

    // Pass 2: Scan flat .dylib + .plist tweaks in tl_dylibs_path
    struct dirent** dylib_list = NULL;
    int dylib_count = scandir(tl_dylibs_path, &dylib_list, tl_filter_plist_files, alphasort);
    if (dylib_count > 0) {
        for (int i = 0; i < dylib_count; i++) {
            const char* entry_name = dylib_list[i]->d_name;
            size_t name_len = strlen(entry_name);
            char tweak_base_name[256] = {0};

            if (name_len > 6 && strcmp(entry_name + name_len - 6, ".plist") == 0) {
                memcpy(tweak_base_name, entry_name, name_len - 6);
                tweak_base_name[name_len - 6] = '\0';
            } else {
                snprintf(tweak_base_name, sizeof(tweak_base_name), "%s", entry_name);
            }

            // De-duplicate if already loaded via bundle
            bool already_processed = false;
            for (int p = 0; p < processed_count; p++) {
                if (strcasecmp(processed_tweaks[p], tweak_base_name) == 0) {
                    already_processed = true;
                    break;
                }
            }
            if (already_processed) {
                free(dylib_list[i]);
                continue;
            }
            if (processed_count < 256) {
                snprintf(processed_tweaks[processed_count++], sizeof(processed_tweaks[0]), "%s", tweak_base_name);
            }

            // Check per-process disable
            if (tl_is_tweak_disabled_for_process(tweak_base_name, process_name, exec_path, main_bundle_id, per_proc_plist)) {
                free(dylib_list[i]);
                continue;
            }

            char binary_full_path[1024];
            snprintf(binary_full_path, sizeof(binary_full_path), "%s%s.dylib", tl_dylibs_path, tweak_base_name);
            struct stat dylib_st;
            if (stat(binary_full_path, &dylib_st) != 0) {
                free(dylib_list[i]);
                continue;
            }

            char plist_full_path[1024];
            snprintf(plist_full_path, sizeof(plist_full_path), "%s%s.plist", tl_dylibs_path, tweak_base_name);
            CFPropertyListRef plist = tl_read_plist_file(plist_full_path);
            if (!plist) {
                free(dylib_list[i]);
                continue;
            }

            if (CFGetTypeID(plist) == CFDictionaryGetTypeID()) {
                CFDictionaryRef root_dict = (CFDictionaryRef)plist;
                CFDictionaryRef filter_dict = (CFDictionaryRef)CFDictionaryGetValue(root_dict, CFSTR("Filter"));
                if (!filter_dict || CFGetTypeID(filter_dict) != CFDictionaryGetTypeID()) {
                    filter_dict = root_dict;
                }

                if (tl_is_injection_allowed_for_process_by_filter(filter_dict, process_name, exec_path, main_bundle, bundle_path, main_bundle_id)) {
                    TL_LOG("[TweakLoader] Injecting dylib %s into %s (pid %d)", binary_full_path, process_name, getpid());
                    void* handle = dlopen(binary_full_path, RTLD_NOW);
                    if (handle) {
                        TL_LOG("[TweakLoader] Injected %s successfully", binary_full_path);
                    } else {
                        const char* dl_err = dlerror();
                        TL_LOG("[TweakLoader] dlopen failed for %s: %s", binary_full_path, dl_err ? dl_err : "unknown");
                    }
                }
            }

            CFRelease(plist);
            free(dylib_list[i]);
        }
        free(dylib_list);
    }

    if (per_proc_plist) {
        CFRelease(per_proc_plist);
    }
}
