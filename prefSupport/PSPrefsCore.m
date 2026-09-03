//
//  PSPrefsCore.m
//  prefSupport
//

#import "PSPrefsCore.h"
#import <os/lock.h>
#import <sys/stat.h>
#import <grp.h>

static NSString *const kPSPrefsDir = @"/Library/TweakInject/Preferences/Defaults";

/// Cache and observation set, both guarded by one lock. Lifted from the
/// CFPreferences forwarding this library replaces -- the shape was right, only
/// the delivery mechanism was wrong.
static os_unfair_lock gPSLock = OS_UNFAIR_LOCK_INIT;
static NSMutableDictionary<NSString *, NSDictionary *> *gPSCache = nil;
static NSMutableDictionary<NSString *, NSNumber *> *gPSCacheMtime = nil;
static NSMutableSet<NSString *> *gPSObserved = nil;

/// mtime of the domain's plist, or 0 if it does not exist.
static time_t PSPrefsMtime(NSString *path) {
    struct stat st;
    return (path && stat(path.fileSystemRepresentation, &st) == 0) ? st.st_mtimespec.tv_sec : 0;
}

/// A domain must be ONE path component of ordinary identifier characters.
///
/// Without this the domain is concatenated straight into a path, and
/// "../../../../Users/me/Library/Preferences/com.apple.dock" walks out of the
/// store into the real preference tree -- a tweak could read or overwrite any
/// plist the process can reach. This library is only ever a door onto
/// /Library/TweakInject/Preferences/Defaults; anything that would leave it is
/// not a domain, and is refused rather than clamped, because a silently
/// rewritten domain would send a tweak's settings somewhere it never asked for.
static BOOL PSPrefsDomainIsValid(NSString *domain) {
    if (domain.length == 0 || domain.length > 255) return NO;
    if ([domain isEqualToString:@"."] || [domain isEqualToString:@".."]) return NO;

    static NSCharacterSet *illegal;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSMutableCharacterSet *ok = [NSMutableCharacterSet alphanumericCharacterSet];
        [ok addCharactersInString:@".-_"];
        illegal = [ok invertedSet];
    });
    // Catches '/', '\0', whitespace and every other separator in one test.
    return [domain rangeOfCharacterFromSet:illegal].location == NSNotFound;
}

NSString *PSPrefsPathForDomain(NSString *domain) {
    if (!PSPrefsDomainIsValid(domain)) return nil;
    return [NSString stringWithFormat:@"%@/%@.plist", kPSPrefsDir, domain];
}

static void PSPrefsInvalidate(CFNotificationCenterRef center, void *observer,
                              CFNotificationName name, const void *object,
                              CFDictionaryRef userInfo) {
    (void)center; (void)observer; (void)object; (void)userInfo;
    if (!name) return;
    // "com.foo.bar/prefsChanged" -> "com.foo.bar"
    NSString *notif = (__bridge NSString *)name;
    NSRange slash = [notif rangeOfString:@"/" options:NSBackwardsSearch];
    if (slash.location == NSNotFound) return;
    NSString *domain = [notif substringToIndex:slash.location];

    os_unfair_lock_lock(&gPSLock);
    [gPSCache removeObjectForKey:domain];
    [gPSCacheMtime removeObjectForKey:domain];
    os_unfair_lock_unlock(&gPSLock);
}

/// Register once per domain. Both spellings are observed because the
/// PostNotification key in a pane's Root.plist is author-written and the
/// casing is not consistent in the wild.
static void PSPrefsObserve(NSString *domain) {
    os_unfair_lock_lock(&gPSLock);
    if (!gPSObserved) gPSObserved = [NSMutableSet set];
    if ([gPSObserved containsObject:domain]) {
        os_unfair_lock_unlock(&gPSLock);
        return;
    }
    [gPSObserved addObject:domain];
    os_unfair_lock_unlock(&gPSLock);

    CFNotificationCenterRef center = CFNotificationCenterGetDarwinNotifyCenter();
    for (NSString *suffix in @[ @"/prefsChanged", @"/prefschanged" ]) {
        NSString *n = [domain stringByAppendingString:suffix];
        CFNotificationCenterAddObserver(center, NULL, PSPrefsInvalidate,
                                        (__bridge CFStringRef)n, NULL,
                                        CFNotificationSuspensionBehaviorCoalesce);
    }
}

static void PSPrefsPost(NSString *domain) {
    NSString *n = [domain stringByAppendingString:@"/prefsChanged"];
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         (__bridge CFStringRef)n, NULL, NULL, true);
}

NSDictionary<NSString *, id> *PSPrefsCopyDomain(NSString *domain) {
    if (!PSPrefsDomainIsValid(domain)) return nil;
    PSPrefsObserve(domain);

    NSString *path = PSPrefsPathForDomain(domain);
    time_t mtime = PSPrefsMtime(path);

    // Two independent freshness checks, because there is no cfprefsd here.
    //
    // The Darwin notification is the fast path and covers every writer that
    // goes through this library or the preference pane. The mtime comparison
    // covers everything else -- a plist edited by hand, restored from a backup,
    // or written by an older build that posts nothing. Without it a process
    // that has read a domain once would never see such a change for as long as
    // it lives. A stat is far cheaper than re-parsing the plist, and this sits
    // on every preference read.
    os_unfair_lock_lock(&gPSLock);
    NSDictionary *cached = gPSCache[domain];
    BOOL fresh = cached && gPSCacheMtime[domain].longLongValue == (long long)mtime;
    os_unfair_lock_unlock(&gPSLock);
    if (fresh) return cached;

    NSDictionary *onDisk = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!onDisk) return nil;   // never written; caller falls back to its defaults

    os_unfair_lock_lock(&gPSLock);
    if (!gPSCache) gPSCache = [NSMutableDictionary dictionary];
    if (!gPSCacheMtime) gPSCacheMtime = [NSMutableDictionary dictionary];
    gPSCache[domain] = onDisk;
    gPSCacheMtime[domain] = @((long long)mtime);
    os_unfair_lock_unlock(&gPSLock);
    return onDisk;
}

BOOL PSPrefsSetValue(NSString *domain, NSString *key, id value) {
    if (!PSPrefsDomainIsValid(domain) || key.length == 0) return NO;

    NSString *path = PSPrefsPathForDomain(domain);
    if (!path) return NO;
    NSMutableDictionary *dict =
        [([NSDictionary dictionaryWithContentsOfFile:path] ?: @{}) mutableCopy];
    if (value) {
        dict[key] = value;
    } else {
        [dict removeObjectForKey:key];
    }

    NSError *error = nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:dict
                                                              format:NSPropertyListXMLFormat_v1_0
                                                             options:0
                                                               error:&error];
    if (!data) return NO;
    // Atomic: a reader in another process never sees a half-written plist.
    if (![data writeToFile:path options:NSDataWritingAtomic error:&error]) return NO;

    // The store is root:staff 775 so both the tweak (as the user) and anything
    // running as root can write it. The FILE has to be group-writable for the
    // same reason: whichever of them creates it first must not lock the other
    // out. Best effort -- a failure here only costs the next writer.
    chmod(path.fileSystemRepresentation, 0664);
    struct group *staff = getgrnam("staff");
    if (staff) chown(path.fileSystemRepresentation, (uid_t)-1, staff->gr_gid);

    os_unfair_lock_lock(&gPSLock);
    if (!gPSCache) gPSCache = [NSMutableDictionary dictionary];
    if (!gPSCacheMtime) gPSCacheMtime = [NSMutableDictionary dictionary];
    gPSCache[domain] = [dict copy];
    gPSCacheMtime[domain] = @((long long)PSPrefsMtime(path));
    os_unfair_lock_unlock(&gPSLock);

    PSPrefsObserve(domain);
    PSPrefsPost(domain);
    return YES;
}

BOOL PSPrefsSynchronize(NSString *domain) {
    if (!PSPrefsDomainIsValid(domain)) return NO;
    PSPrefsPost(domain);
    return YES;
}
