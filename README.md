# tweakLoader

A tweak loader and injection suite for macOS on Apple silicon, built to work like
its iOS counterparts while extending what a tweak can filter on.

> **Requires SIP to be disabled** (`csrutil disable` from recoveryOS). Nothing here
> works on a stock system, and that is by design — turning SIP off removes real
> protections from the whole machine. Use it on a machine you are willing to treat
> as untrusted.

## Components

| Component | What it is |
|---|---|
| `tweakLoader/` | The dylib injected into every process. Enumerates filter plists, decides what loads, and `dlopen`s the matching tweaks. |
| `launchd_hooks/` | Hooks `posix_spawn` inside launchd so newly spawned processes inherit the loader. Also where per-process disable and Safe Mode are enforced. |
| `xpcproxy_hooks/` | The same for `xpcproxy`, which is what actually execs most XPC services. |
| `prefSupport/` | `libprefSupport.dylib` — the preference API tweaks link against. See [Preferences](#preferences). |
| `safeMode/` | Crash tripwire loaded into critical processes, so a broken tweak cannot leave the machine unusable. |
| `safeModePill/` | The menu bar indicator shown while Safe Mode is active, and the way out of it. |

Disabling injection for a process, and Safe Mode itself, are enforced in the spawn
hooks rather than in the loader: a stripped process never receives
`libtweakLoader.dylib` at all, so there is nothing in it to go wrong.

## Filters

A tweak ships a plist next to its dylib describing where it should load. The format
follows the iOS tweak-filter convention — `Bundles`, `Classes`, `Executables`, combined
with OR — plus a few additions:

- `ExcludeBundles` — hard veto, evaluated before anything else.
- `Type` — `App`, `Binary` or `Any`.
- `Privilege` — `Any` (default), `Root`, or `User`. `User` keeps a tweak out of root
  processes entirely, which bounds what a package can reach. Absent means `Any`, so
  existing filters behave exactly as before.

A filter that declares no `Bundles`/`Classes`/`Executables` applies to every process
that passes its gates, as long as it sets at least one of `Type` or `Privilege`. A
filter that sets neither matches nothing — no criteria and no gate is an incomplete
filter, not a request to load everywhere. The iOS loaders differ here: there a
criteria-less filter matches nothing at all, and "everywhere" is spelled by naming a
universally linked bundle such as `com.apple.foundation`.

```xml
<dict>
  <key>Filter</key>
  <dict>
    <key>Bundles</key>
    <array><string>com.apple.dock</string></array>
    <key>Privilege</key>
    <string>User</string>
  </dict>
</dict>
```

## Preferences

A tweak injected into a sandboxed app cannot use the stock preferences API to reach a
shared store: `NSUserDefaults` hands it that app's container, so the tweak's settings
fragment per host process.

`libprefSupport.dylib` reads and writes `/Library/TweakInject/Preferences/Defaults`
directly, at a fixed absolute path, so every process sees the same store regardless of
container or uid. The store is `root:staff 775`, and `launchd_hooks` issues a sandbox
extension over it per injected process.

Two surfaces, mirroring the shapes they replace:

```objc
#import <PSUserDefaults.h>

PSUserDefaults *d = [[PSUserDefaults alloc] initWithSuiteName:@"com.you.tweakname"];
[d registerDefaults:@{ @"Enabled": @YES }];
BOOL on = [d boolForKey:@"Enabled"];
```

`PSPreferences` mirrors the CoreFoundation functions (`PSPreferencesCopyAppValue`,
`PSPreferencesSetAppValue`) for tweaks written against that style.

Link with `-L/Library/TweakInject -lprefSupport`. The install name is the absolute
`/Library/TweakInject/libprefSupport.dylib`, so dyld resolves it there at load time —
no search path, no `@rpath`.

There is deliberately no `standardUserDefaults` equivalent. A tweak is a guest in
someone else's process and has no "own" domain — the host's is not it. Naming the
domain is what makes a tweak's settings the same everywhere it loads. By convention
that name is the package identifier, as with Cephei's `HBPreferences`.

## Getting it running

Two steps, because a loader that only affects processes started *after* it is
installed is not much use:

1. **Inject the launchd hook.** [Dylinject](https://github.com/doraorak/Dylinject)
   loads `launchd_hooks.dylib` into launchd (pid 1). From then on every process
   launchd spawns inherits `libtweakLoader.dylib`.
2. **Catch what was already running.** Everything alive before step 1 has no loader
   in it. A userspace restart (`launchctl reboot userspace`) brings those processes
   back with it, without rebooting the kernel.

The hook has to be re-injected after each boot.

[TweakInject](https://github.com/doraorak/TweakInject) is the macOS app built on this
and drives all of it from a GUI — install, inject, userspace restart, per-process
rules, Safe Mode and tweak management — so none of it needs doing by hand. Its
package repository is
[TweakInject-Store](https://github.com/doraorak/TweakInject-Store).

This repository is the engine underneath: the app depends on the loader, the loader
does not depend on the app, and nothing here assumes a particular front-end.

## Layout on disk

```
/Library/TweakInject/
├── libtweakLoader.dylib
├── libprefSupport.dylib
├── libellekit.dylib
├── Tweaks/
│   ├── DynamicLibraries/      tweak dylibs + their filter plists
│   └── Bundles/               self-contained .bundle tweaks
├── DisabledTweaks/            the same two, for disabled tweaks
├── Preferences/
│   ├── Defaults/              the preference store (root:staff 775)
│   ├── PreferenceBundles/     settings UI shipped by tweaks
│   └── PreferencePanes/
├── Config/
│   ├── perProcessTweaks.plist per-process enable/disable
│   ├── denyInjectionList.plist
│   └── installed_packages.plist
├── SafeMode/                  the tripwire, the pill, and the marker
├── LaunchdHook/               launchd + xpcproxy hooks
└── logs/
```

Everything except `Preferences/Defaults` is `root:wheel`, directories `755` and files
`644`. All of it is loaded into other processes — including root ones — so a
world-writable directory is a local privilege escalation, not a convenience.
`Preferences/Defaults` is the one exception, and is group-writable on purpose:
tweaks write their own preferences as the user.

## Building

Open `tweakLoader.xcodeproj` and set your own development team (the shipped project
has it blank). Targets: `tweakLoader`, `launchd_hooks`, `xpcproxy_hooks`,
`prefSupport`, `safeMode`. `safeModePill` has no Xcode target — it is one file against
Cocoa, built directly.

Or build a component by hand:

```bash
clang -dynamiclib -arch arm64e -install_name /usr/local/lib/libtweakLoader.dylib \
  -framework CoreFoundation -lobjc -o libtweakLoader.dylib tweakLoader/tweakLoader.c
```

## Logging

Every injected component has `ENABLE_LOGS`, **off by default**, and logs through
one macro:

```c
TL_LOG("[TweakLoader] %{public}s denied", procName);
```

The switch itself:

```c
#define ENABLE_LOGS 0
```

Leave it off unless you are actively debugging. This code runs inside every process
that launches, `logd` included, and `os_log()` from a constructor there deadlocks
logd — after which the rest of the system follows and the machine usually needs a
reboot to recover.

## Notes

- The spawn hooks carry a blacklist of processes that must never be injected. It is
  not a convenience list; each entry is something that broke. `logd`, `syslogd` and
  `notifyd`, where logging from a constructor deadlocks the system. `cfprefsd` and
  `launchservicesd`, because nearly every launch goes through them and injecting
  them is circular. `amfid`, because injecting the validator that authorises
  injection is a loop, and a wedged amfid stalls every `exec` on the machine.
  `loginwindow` and the authentication stack, which deadlock a userspace restart.
  `MTLCompilerService`, where a hooked function in a shared XPC service stalls the
  GPU pipeline machine-wide rather than for the app that triggered the compile.
- `WindowServer` is deliberately **not** blacklisted.
- Both hook files carry the same gate, blacklist and plist parser, and those blocks
  are kept byte-identical between them. `xpcproxy` does not link CoreFoundation, so
  the parser in both is libc-only.
- Code signatures for every injectable dylib are registered with the kernel
  (`F_ADDFILESIGS_RETURN`) before a userspace restart. `launchctl reboot userspace`
  tears down `amfid` before PID 1 re-execs, so an uncached signature fails closed and
  killing a boot-critical process panics the kernel.
