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
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>

#define TWEAKINJECT_LOG_PATH     "/Library/TweakInject/tweakinject.log"
#define TWEAKINJECT_LOG_FALLBACK "/tmp/tweakinject.log"
#define TWEAKLOADER_ACTIVE_PATH  "/tmp/.tweakloader_active"

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
        write(fd, line, (size_t)lineLen);
        close(fd);
    }

    // Touch active marker
    int marker = open(TWEAKLOADER_ACTIVE_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK | O_CLOEXEC, 0666);
    if (marker >= 0) {
        char hb[64];
        int hbLen = snprintf(hb, sizeof(hb), "%ld %d\n", (long)now, getpid());
        if (hbLen > 0) write(marker, hb, (size_t)hbLen);
        close(marker);
    }
}

#define TL_LOG(fmt, ...) tl_safe_log(fmt, ##__VA_ARGS__)

#include <sys/sysctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

// MARK: - Paths & Constants
#define twkPath               "/Library/TweakInject/DynamicLibraries/"
#define safeModePath          "/Library/TweakInject/SafeMode/"
#define safeModeDylibPath     "/Library/TweakInject/libsafeMode.dylib"
#define denyListPath          "/Library/TweakInject/denyInjectionList.plist"
#define perProcessTweaksPath  "/Library/TweakInject/perProcessTweaks.plist"

// MARK: - Helper Functions

/// Checks if a CFArray of strings contains a given needle string.
static int string_array_contains(CFArrayRef array, const char* needle, int substring, int caseInsensitive) {
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
            if (caseInsensitive ? (strcasestr(needle, buf) != NULL) : (strstr(needle, buf) != NULL)) {
                return 1;
            }
        } else {
            if (caseInsensitive ? (strcasecmp(needle, buf) == 0) : (strcmp(needle, buf) == 0)) {
                return 1;
            }
        }
    }
    return 0;
}

/// Safely reads and parses a Property List (.plist) file from disk with a size sanity check.
static CFPropertyListRef read_plist_file(const char* path) {
    int fd = open(path, O_RDONLY);
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

/// Looks up process rules in perProcessTweaks.plist matching in priority: execPath, mainBundleId, procName.
static CFDictionaryRef find_process_rule_entry(CFDictionaryRef dict, const char* procName, const char* execPath, CFStringRef mainBundleId) {
    if (!dict || CFGetTypeID(dict) != CFDictionaryGetTypeID()) {
        return NULL;
    }

    // 1. Direct match with full executable path
    if (execPath && execPath[0] != '\0') {
        CFStringRef cfExec = CFStringCreateWithCString(kCFAllocatorDefault, execPath, kCFStringEncodingUTF8);
        if (cfExec) {
            CFTypeRef val = CFDictionaryGetValue(dict, cfExec);
            CFRelease(cfExec);
            if (val && CFGetTypeID(val) == CFDictionaryGetTypeID()) {
                return (CFDictionaryRef)val;
            }
        }
    }

    // 2. Direct match with main bundle identifier
    if (mainBundleId) {
        CFTypeRef val = CFDictionaryGetValue(dict, mainBundleId);
        if (val && CFGetTypeID(val) == CFDictionaryGetTypeID()) {
            return (CFDictionaryRef)val;
        }
    }

    // 3. Direct match with process base name
    if (procName && procName[0] != '\0') {
        CFStringRef cfProc = CFStringCreateWithCString(kCFAllocatorDefault, procName, kCFStringEncodingUTF8);
        if (cfProc) {
            CFTypeRef val = CFDictionaryGetValue(dict, cfProc);
            CFRelease(cfProc);
            if (val && CFGetTypeID(val) == CFDictionaryGetTypeID()) {
                return (CFDictionaryRef)val;
            }
        }
    }

    return NULL;
}

/// Checks if injection is prohibited for this process globally.
/// Two separate mechanisms answer "should this process be injected at all", and
/// they are deliberately not merged:
///
///   denyInjectionList.plist  ships with the loader and is a SAFETY list. logd is
///                            on it because logging from a constructor there wedges
///                            the machine. It is not a user preference and nothing
///                            in a UI should be able to clear it.
///   perProcessTweaks.plist   is USER state, written by whatever front-end manages
///                            tweaks, and says "I do not want injection in this
///                            process right now".
///
/// Same effect, different owner and lifetime — collapsing them would mean a user
/// action could remove a protection that exists to keep the system bootable.
static int is_injection_denied_for_process(const char* procName, const char* execPath, CFStringRef mainBundleId) {
    // 1. Safety list, shipped with the loader.
    CFPropertyListRef denyPlist = read_plist_file(denyListPath);
    if (denyPlist) {
        int denied = 0;
        CFTypeID type = CFGetTypeID(denyPlist);

        if (type == CFArrayGetTypeID()) {
            denied = string_array_contains((CFArrayRef)denyPlist, procName, 0, 0);
        } else if (type == CFDictionaryGetTypeID()) {
            CFDictionaryRef dict = (CFDictionaryRef)denyPlist;
            denied = string_array_contains((CFArrayRef)CFDictionaryGetValue(dict, CFSTR("Processes")), procName, 0, 0);
            if (!denied && execPath) {
                denied = string_array_contains((CFArrayRef)CFDictionaryGetValue(dict, CFSTR("PathContains")), execPath, 1, 0);
            }
        }
        CFRelease(denyPlist);
        if (denied) {
            return 1;
        }
    }

    // 2. User preference, per process.
    CFPropertyListRef perProcPlist = read_plist_file(perProcessTweaksPath);
    if (perProcPlist) {
        if (CFGetTypeID(perProcPlist) == CFDictionaryGetTypeID()) {
            CFDictionaryRef dict = (CFDictionaryRef)perProcPlist;
            CFDictionaryRef procEntry = find_process_rule_entry(dict, procName, execPath, mainBundleId);
            if (procEntry) {
                CFBooleanRef disabledVal = (CFBooleanRef)CFDictionaryGetValue(procEntry, CFSTR("TweakInjectionDisabled"));
                if (disabledVal && CFGetTypeID(disabledVal) == CFBooleanGetTypeID() && CFBooleanGetValue(disabledVal)) {
                    CFRelease(perProcPlist);
                    return 1;
                }
            }
        }
        CFRelease(perProcPlist);
    }

    return 0;
}

/// Checks if a specific tweak is disabled for this process in perProcessTweaks.plist.
static int is_tweak_disabled_for_process(const char* tweakBaseName, const char* procName, const char* execPath, CFStringRef mainBundleId, CFPropertyListRef perProcPlist) {
    if (!perProcPlist || !tweakBaseName || CFGetTypeID(perProcPlist) != CFDictionaryGetTypeID()) {
        return 0;
    }

    CFDictionaryRef dict = (CFDictionaryRef)perProcPlist;
    CFDictionaryRef procEntry = find_process_rule_entry(dict, procName, execPath, mainBundleId);

    if (procEntry) {
        CFArrayRef disabledTweaks = (CFArrayRef)CFDictionaryGetValue(procEntry, CFSTR("DisabledTweaks"));
        if (disabledTweaks && CFGetTypeID(disabledTweaks) == CFArrayGetTypeID()) {
            return string_array_contains(disabledTweaks, tweakBaseName, 0, 1);
        }
    }

    return 0;
}

// MARK: - Safe Boot Detection

/// Checks if macOS booted into Safe Mode via kern.bootargs.
int is_booted_in_safe_mode(void) {
    size_t size = 0;
    if (sysctlbyname("kern.bootargs", NULL, &size, NULL, 0) != 0 || size == 0)
        return 0;
    
    char* bootargs = malloc(size);
    if (!bootargs)
        return 0;
    
    if (sysctlbyname("kern.bootargs", bootargs, &size, NULL, 0) != 0) {
        free(bootargs);
        return 0;
    }
    
    int is_safe = (strstr(bootargs, "-x") != NULL);
    free(bootargs);
    return is_safe;
}

// MARK: - Filter Plist Evaluation

/// Evaluates a tweak's Filter dictionary against the current process.
static bool is_injection_allowed_for_process_by_filter(
    CFDictionaryRef filters,
    const char* procName,
    const char* execPath,
    CFBundleRef mainBundle,
    const char* bundlePath,
    CFStringRef mainBundleId
) {
    if (!filters || CFGetTypeID(filters) != CFDictionaryGetTypeID()) {
        return false;
    }

    // 1. ExcludeBundles (Hard veto: if matched, reject tweak immediately)
    CFArrayRef excludeBundles = (CFArrayRef)CFDictionaryGetValue(filters, CFSTR("ExcludeBundles"));
    if (excludeBundles && CFGetTypeID(excludeBundles) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(excludeBundles);
        for (CFIndex i = 0; i < count; i++) {
            CFTypeRef item = CFArrayGetValueAtIndex(excludeBundles, i);
            if (!item || CFGetTypeID(item) != CFStringGetTypeID()) continue;
            CFStringRef exclId = (CFStringRef)item;

            if (CFBundleGetBundleWithIdentifier(exclId) != NULL) {
                return false;
            }
            if (mainBundleId && CFStringCompare(mainBundleId, exclId, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                return false;
            }
        }
    }

    // 2. Type Gate ("All", "App", "Binary" - Hard veto on mismatch)
    CFStringRef typeFilter = (CFStringRef)CFDictionaryGetValue(filters, CFSTR("Type"));
    bool isAppProcess = false;
    if ((bundlePath[0] != '\0' && strstr(bundlePath, ".app") != NULL) ||
        (execPath && strstr(execPath, ".app/") != NULL)) {
        isAppProcess = true;
    }

    if (typeFilter && CFGetTypeID(typeFilter) == CFStringGetTypeID()) {
        if (CFStringCompare(typeFilter, CFSTR("App"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (!isAppProcess) return false;
        } else if (CFStringCompare(typeFilter, CFSTR("Binary"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (isAppProcess) return false;
        }
    }

    // 3. Privilege Gate ("Any" | "Root" | "User" - hard veto on mismatch)
    //
    // One of this loader's extensions to the iOS filter schema, alongside
    // ExcludeBundles and Type. Absent or "Any" is a no-op, so a filter written for
    // the original schema keeps its behaviour exactly.
    //
    // It is a containment control: a tweak that cannot load into a root process
    // cannot gain root, which bounds what a package can reach if it turns out to be
    // hostile or simply broken. euid is read here, at load time; a process that
    // drops privileges afterwards is not re-evaluated, matching the other gates.
    CFStringRef privFilter = (CFStringRef)CFDictionaryGetValue(filters, CFSTR("Privilege"));
    if (privFilter && CFGetTypeID(privFilter) == CFStringGetTypeID()) {
        uid_t euid = geteuid();
        if (CFStringCompare(privFilter, CFSTR("Root"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (euid != 0) return false;
        } else if (CFStringCompare(privFilter, CFSTR("User"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (euid == 0) return false;
        }
    }

    // 4. CoreFoundationVersion Gate ([min] or [min, max])
    CFArrayRef cfVersionFilter = (CFArrayRef)CFDictionaryGetValue(filters, CFSTR("CoreFoundationVersion"));
    if (cfVersionFilter && CFGetTypeID(cfVersionFilter) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(cfVersionFilter);
        if (count >= 1) {
            CFTypeRef minValRef = CFArrayGetValueAtIndex(cfVersionFilter, 0);
            if (minValRef && CFGetTypeID(minValRef) == CFNumberGetTypeID()) {
                double minVal = 0;
                CFNumberGetValue((CFNumberRef)minValRef, kCFNumberDoubleType, &minVal);
                if (kCFCoreFoundationVersionNumber < minVal) {
                    return false;
                }
            }
        }
        if (count >= 2) {
            CFTypeRef maxValRef = CFArrayGetValueAtIndex(cfVersionFilter, 1);
            if (maxValRef && CFGetTypeID(maxValRef) == CFNumberGetTypeID()) {
                double maxVal = 0;
                CFNumberGetValue((CFNumberRef)maxValRef, kCFNumberDoubleType, &maxVal);
                if (kCFCoreFoundationVersionNumber >= maxVal) {
                    return false;
                }
            }
        }
    }

    // 4. Criteria Matching: Bundles, Classes, Executables (OR semantics)
    CFArrayRef bundlesFilter = (CFArrayRef)CFDictionaryGetValue(filters, CFSTR("Bundles"));
    if (bundlesFilter && CFGetTypeID(bundlesFilter) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(bundlesFilter);
        for (CFIndex i = 0; i < count; i++) {
            CFTypeRef item = CFArrayGetValueAtIndex(bundlesFilter, i);
            if (!item || CFGetTypeID(item) != CFStringGetTypeID()) continue;
            CFStringRef reqId = (CFStringRef)item;

            if (CFBundleGetBundleWithIdentifier(reqId) != NULL) {
                return true;
            }
            if (mainBundleId && CFStringCompare(mainBundleId, reqId, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                return true;
            }
        }
    }

    CFArrayRef classesFilter = (CFArrayRef)CFDictionaryGetValue(filters, CFSTR("Classes"));
    if (classesFilter && CFGetTypeID(classesFilter) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(classesFilter);
        for (CFIndex i = 0; i < count; i++) {
            CFTypeRef item = CFArrayGetValueAtIndex(classesFilter, i);
            if (!item || CFGetTypeID(item) != CFStringGetTypeID()) continue;
            char classNameBuf[256];
            if (CFStringGetCString((CFStringRef)item, classNameBuf, sizeof(classNameBuf), kCFStringEncodingUTF8)) {
                if (objc_getClass(classNameBuf) != nil) {
                    return true;
                }
            }
        }
    }

    CFArrayRef executablesFilter = (CFArrayRef)CFDictionaryGetValue(filters, CFSTR("Executables"));
    if (executablesFilter && CFGetTypeID(executablesFilter) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(executablesFilter);
        const char* execBaseName = (execPath ? strrchr(execPath, '/') : NULL);
        execBaseName = execBaseName ? execBaseName + 1 : execPath;

        for (CFIndex i = 0; i < count; i++) {
            CFTypeRef item = CFArrayGetValueAtIndex(executablesFilter, i);
            if (!item || CFGetTypeID(item) != CFStringGetTypeID()) continue;
            char execNameBuf[256];
            if (CFStringGetCString((CFStringRef)item, execNameBuf, sizeof(execNameBuf), kCFStringEncodingUTF8)) {
                if (procName && strcasecmp(procName, execNameBuf) == 0) {
                    return true;
                }
                if (execBaseName && strcasecmp(execBaseName, execNameBuf) == 0) {
                    return true;
                }
            }
        }
    }

    // A filter with no criteria arrays matches every process that got past the gates
    // above -- but only if it actually declared a gate. This is a deliberate
    // divergence from the iOS loaders, where a criteria-less filter matches nothing
    // and "everywhere" is spelled by naming a universally linked bundle such as
    // com.apple.foundation. Here Type/Privilege say it directly.
    //
    // An empty filter still matches nothing: declaring no criteria AND no gate is
    // not a request to inject everywhere, it is an incomplete filter.
    bool has_any_criteria = (bundlesFilter && CFGetTypeID(bundlesFilter) == CFArrayGetTypeID() && CFArrayGetCount(bundlesFilter) > 0) ||
                            (classesFilter && CFGetTypeID(classesFilter) == CFArrayGetTypeID() && CFArrayGetCount(classesFilter) > 0) ||
                            (executablesFilter && CFGetTypeID(executablesFilter) == CFArrayGetTypeID() && CFArrayGetCount(executablesFilter) > 0);

    if (!has_any_criteria && (typeFilter != NULL || privFilter != NULL)) {
        return true;
    }

    return false;
}

static int filter_plist_files(const struct dirent* entry) {
    if (!entry || entry->d_name[0] == '.') {
        return 0;
    }
    size_t len = strlen(entry->d_name);
    return (len > 6 && strcmp(entry->d_name + len - 6, ".plist") == 0);
}

int64_t (*_sandbox_extension_consume)(const char* token);

// MARK: - TweakLoader Entrypoint (Constructor)

__attribute__((constructor)) static void init_tweak_loader(void) {

    // 1. Consume App Sandbox extension if provided
    void* libSystemSandboxHandle = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
    if (libSystemSandboxHandle) {
        _sandbox_extension_consume = dlsym(libSystemSandboxHandle, "sandbox_extension_consume");
        if (_sandbox_extension_consume) {
            char* sandbox_token = getenv("TL_SANDBOX_TOKEN"); if (!sandbox_token) sandbox_token = getenv("SANDBOX_TOKEN");
            if (sandbox_token) {
                int64_t handle = _sandbox_extension_consume(sandbox_token);
                if (handle > 0) {
                    TL_LOG("[TweakLoader] Sandbox extension consumed successfully");
                }
            }
        }
    }

    // 2. Identify current process
    char procName[256] = {0};
    proc_name(getpid(), procName, sizeof(procName));

    char execPath[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (proc_pidpath(getpid(), execPath, sizeof(execPath)) <= 0) {
        execPath[0] = '\0';
    }

    CFBundleRef mainBundle = CFBundleGetMainBundle();
    CFStringRef mainBundleId = mainBundle ? CFBundleGetIdentifier(mainBundle) : NULL;
    char bundlePath[1024] = {0};
    if (mainBundle) {
        CFURLRef bundleUrl = CFBundleCopyBundleURL(mainBundle);
        if (bundleUrl) {
            CFStringRef bundleUrlString = CFURLCopyPath(bundleUrl);
            if (bundleUrlString) {
                CFStringGetCString(bundleUrlString, bundlePath, sizeof(bundlePath), kCFStringEncodingUTF8);
                CFRelease(bundleUrlString);
            }
            CFRelease(bundleUrl);
        }
    }

    TL_LOG("[TweakLoader] Active in %s (pid %d)", procName[0] ? procName : "process", getpid());

    // 3. Denylist check
    if (is_injection_denied_for_process(procName, execPath, mainBundleId)) {
        TL_LOG("[TweakLoader] %s is denied, skipping injection", procName);
        return;
    }

    // 4. SafeMode check
    if (strcmp(procName, "Dock") == 0 || strcmp(procName, "WallpaperVideoExtension") == 0 ||
        strcmp(procName, "WallpaperImageExtension") == 0 || strcmp(procName, "Finder") == 0 ||
        strcmp(procName, "WindowServer") == 0 || strcmp(procName, "Spotlight") == 0) {
        dlopen(safeModeDylibPath, RTLD_NOW);
    }

    if (is_booted_in_safe_mode()) {
        TL_LOG("[TweakLoader] SafeBoot enabled, skipping injection");
        return;
    }

    DIR* smDir = opendir(safeModePath);
    if (smDir) {
        struct dirent* smEntry;
        while ((smEntry = readdir(smDir)) != NULL) {
            size_t nlen = strlen(smEntry->d_name);
            if (nlen > 4 && strcmp(smEntry->d_name + nlen - 4, ".txt") == 0) {
                closedir(smDir);
                TL_LOG("[TweakLoader] SafeMode active, skipping injection");
                return;
            }
        }
        closedir(smDir);
    }

    // 5. Scan and load tweaks in deterministic alphabetical order
    struct dirent** namelist = NULL;
    int count = scandir(twkPath, &namelist, filter_plist_files, alphasort);
    if (count < 0) {
        TL_LOG("[TweakLoader] Failed to scan %s", twkPath);
        return;
    }

    CFPropertyListRef perProcPlist = read_plist_file(perProcessTweaksPath);

    for (int i = 0; i < count; i++) {
        char plistFullPath[1024];
        snprintf(plistFullPath, sizeof(plistFullPath), "%s%s", twkPath, namelist[i]->d_name);

        size_t nameLen = strlen(namelist[i]->d_name);
        char tweakBaseName[512];
        if (nameLen > 6 && nameLen - 6 < sizeof(tweakBaseName)) {
            memcpy(tweakBaseName, namelist[i]->d_name, nameLen - 6);
            tweakBaseName[nameLen - 6] = '\0';
        } else {
            snprintf(tweakBaseName, sizeof(tweakBaseName), "%s", namelist[i]->d_name);
        }

        // Check per-process disable
        if (is_tweak_disabled_for_process(tweakBaseName, procName, execPath, mainBundleId, perProcPlist)) {
            free(namelist[i]);
            continue;
        }

        char dylibFullPath[1024];
        snprintf(dylibFullPath, sizeof(dylibFullPath), "%s%s.dylib", twkPath, tweakBaseName);

        struct stat dylibSt;
        if (stat(dylibFullPath, &dylibSt) != 0) {
            free(namelist[i]);
            continue;
        }

        CFPropertyListRef plist = read_plist_file(plistFullPath);
        if (!plist) {
            free(namelist[i]);
            continue;
        }

        if (CFGetTypeID(plist) == CFDictionaryGetTypeID()) {
            CFDictionaryRef rootDict = (CFDictionaryRef)plist;
            CFDictionaryRef filterDict = (CFDictionaryRef)CFDictionaryGetValue(rootDict, CFSTR("Filter"));
            if (!filterDict || CFGetTypeID(filterDict) != CFDictionaryGetTypeID()) {
                filterDict = rootDict;
            }

            if (is_injection_allowed_for_process_by_filter(filterDict, procName, execPath, mainBundle, bundlePath, mainBundleId)) {
                TL_LOG("[TweakLoader] Injecting %s into %s (pid %d)", dylibFullPath, procName, getpid());
                void* handle = dlopen(dylibFullPath, RTLD_NOW);
                if (handle) {
                    TL_LOG("[TweakLoader] Injected %s successfully", dylibFullPath);
                } else {
                    const char* dlErr = dlerror();
                    TL_LOG("[TweakLoader] dlopen failed for %s: %s", dylibFullPath, dlErr ? dlErr : "unknown");
                }
            }
        }

        CFRelease(plist);
        free(namelist[i]);
    }

    if (perProcPlist) {
        CFRelease(perProcPlist);
    }
    free(namelist);
}
