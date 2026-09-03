//
//  PSPreferences.h
//  prefSupport
//
//  CFPreferences, served from the TweakInject preference store instead of
//  cfprefsd. Every function mirrors its CoreFoundation counterpart, so porting a
//  tweak is a prefix change:
//
//      CFPreferencesCopyAppValue(k, d)   ->   PSPreferencesCopyAppValue(k, d)
//
//  Use this, not CFPreferences, for a tweak's OWN settings. The stock functions
//  are not hooked: called from inside a sandboxed app they resolve to that app's
//  container, which is why a tweak's settings would otherwise differ per host
//  process and stay invisible to its preference pane.
//
//  For anything that is NOT a tweak domain -- reading an app's or Apple's own
//  preferences -- keep using CFPreferences. That is the stock API's job and it
//  still does it correctly.
//

#import <CoreFoundation/CoreFoundation.h>

CF_ASSUME_NONNULL_BEGIN
#ifdef __cplusplus
extern "C" {
#endif

/// The value for `key` in `domain`, or NULL if unset. Caller owns the result.
CFPropertyListRef _Nullable PSPreferencesCopyAppValue(CFStringRef key, CFStringRef domain);

/// Set `key` in `domain`. A NULL `value` removes it. Creates the plist if it
/// does not exist yet, as stock CFPreferences does on a first write, and posts
/// `<domain>/prefsChanged` so other processes reload.
void PSPreferencesSetAppValue(CFStringRef key, CFPropertyListRef _Nullable value, CFStringRef domain);

/// `exists` reports whether the key was present AND of the expected type,
/// matching CFPreferencesGetAppBooleanValue.
Boolean PSPreferencesGetAppBooleanValue(CFStringRef key, CFStringRef domain, Boolean *_Nullable exists);
CFIndex PSPreferencesGetAppIntegerValue(CFStringRef key, CFStringRef domain, Boolean *_Nullable exists);

/// Writes land immediately, so this only re-posts the change notification.
/// Present so a ported tweak's call site does not have to be deleted.
Boolean PSPreferencesAppSynchronize(CFStringRef domain);

/// Every key in the domain, or NULL if it has never been written.
CFArrayRef _Nullable PSPreferencesCopyKeyList(CFStringRef domain);

#ifdef __cplusplus
}
#endif
CF_ASSUME_NONNULL_END
