//
//  PSPrefsCore.h
//  prefSupport
//
//  The store both public surfaces sit on. Not installed as a public header.
//
//  Tweak preferences live at a FIXED ABSOLUTE PATH rather than in the stock
//  location, and that is the whole reason this library exists: a tweak injected
//  into a sandboxed app that calls NSUserDefaults gets that app's container, so
//  its settings fragment per host process and the preference pane cannot see
//  what the tweak wrote. One absolute path gives every process the same store
//  regardless of container or uid.
//
//  This is the same trade Cephei's HBPreferences makes on iOS -- it reads plists
//  directly out of the mobile user's home directory instead of going through
//  cfprefsd, for exactly these two cases. What differs is how the sandbox is
//  satisfied: iOS jailbreaks relax filesystem confinement device-wide, while
//  here launchd_hooks issues a per-process sandbox extension over the store and
//  the loader consumes it.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// `/Library/TweakInject/Preferences/Defaults/<domain>.plist`, or nil if
/// `domain` is not a single safe path component. This library never addresses
/// anything outside that directory.
extern NSString *_Nullable PSPrefsPathForDomain(NSString *domain);

/// The domain's contents, or nil if it has never been written.
///
/// Cached, and the cache is dropped when another process posts the domain's
/// Darwin notification. Observation is registered on first read, so a tweak that
/// only ever reads still sees changes made by the pane.
extern NSDictionary<NSString *, id> *_Nullable PSPrefsCopyDomain(NSString *domain);

/// Set one key. A nil value removes it, matching CFPreferencesSetAppValue.
/// Creates the plist if absent, as stock CFPreferences does on a first write.
extern BOOL PSPrefsSetValue(NSString *domain, NSString *key, id _Nullable value);

/// Post the domain's change notification so other processes reload. Writes do
/// this already; this exists for the CFPreferencesAppSynchronize shape.
extern BOOL PSPrefsSynchronize(NSString *domain);

NS_ASSUME_NONNULL_END
