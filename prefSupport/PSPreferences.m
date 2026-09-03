//
//  PSPreferences.m
//  prefSupport
//

#import "PSPreferences.h"
#import "PSPrefsCore.h"

CFPropertyListRef PSPreferencesCopyAppValue(CFStringRef key, CFStringRef domain) {
    if (!key || !domain) return NULL;
    NSDictionary *dict = PSPrefsCopyDomain((__bridge NSString *)domain);
    id value = dict[(__bridge NSString *)key];
    if (!value) return NULL;
    return (CFPropertyListRef)CFBridgingRetain(value);   // Copy: caller owns it
}

void PSPreferencesSetAppValue(CFStringRef key, CFPropertyListRef value, CFStringRef domain) {
    if (!key || !domain) return;
    PSPrefsSetValue((__bridge NSString *)domain,
                    (__bridge NSString *)key,
                    (__bridge id)value);
}

Boolean PSPreferencesGetAppBooleanValue(CFStringRef key, CFStringRef domain, Boolean *exists) {
    if (exists) *exists = false;
    if (!key || !domain) return false;

    NSDictionary *dict = PSPrefsCopyDomain((__bridge NSString *)domain);
    id value = dict[(__bridge NSString *)key];
    // CFPreferences reports existence only for a value it could actually use,
    // so a key holding the wrong type counts as absent rather than as false.
    if (![value respondsToSelector:@selector(boolValue)]) return false;
    if (![value isKindOfClass:NSNumber.class] && ![value isKindOfClass:NSString.class]) return false;

    if (exists) *exists = true;
    return [value boolValue];
}

CFIndex PSPreferencesGetAppIntegerValue(CFStringRef key, CFStringRef domain, Boolean *exists) {
    if (exists) *exists = false;
    if (!key || !domain) return 0;

    NSDictionary *dict = PSPrefsCopyDomain((__bridge NSString *)domain);
    id value = dict[(__bridge NSString *)key];
    if (![value isKindOfClass:NSNumber.class] && ![value isKindOfClass:NSString.class]) return 0;

    if (exists) *exists = true;
    return (CFIndex)[value integerValue];
}

Boolean PSPreferencesAppSynchronize(CFStringRef domain) {
    if (!domain) return false;
    return PSPrefsSynchronize((__bridge NSString *)domain) ? true : false;
}

CFArrayRef PSPreferencesCopyKeyList(CFStringRef domain) {
    if (!domain) return NULL;
    NSDictionary *dict = PSPrefsCopyDomain((__bridge NSString *)domain);
    if (!dict) return NULL;
    return (CFArrayRef)CFBridgingRetain(dict.allKeys);
}
