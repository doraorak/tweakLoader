# tweakLoader

The injection core behind TweakInject: a Substrate-style tweak loader for macOS on
Apple Silicon.

It gets a dylib into every process that launches, decides per-process which tweaks
apply, and provides the pieces needed to make that happen at boot and to recover
when it goes wrong.

> **Requires SIP to be disabled** (`csrutil disable` from recoveryOS). Nothing here
> works on a stock system, and that is by design — turning SIP off removes real
> protections from the whole machine. Use it on a machine you are willing to treat
> as untrusted.

## Components

| Component | What it is |
|---|---|
| `tweakLoader/` | The dylib injected into every process. Enumerates filter plists, decides what loads, and `dlopen`s the matching tweaks. |
| `launchd_hooks/` | Hooks `posix_spawn` inside launchd so newly spawned processes inherit the loader. |
| `xpcproxy_hooks/` | The same for `xpcproxy`, which is what actually execs most XPC services. |
| `ldrestart/` | Restarts userspace so already-running processes pick up the loader, without killing the session. |
| `safeMode/` | Bypass loaded into critical processes so a broken tweak cannot leave the machine unusable. |

## Filters

A tweak ships a plist next to its dylib describing where it should load. The format
follows the iOS/Substrate convention — `Bundles`, `Classes`, `Executables`, combined
with OR — plus a few additions:

- `ExcludeBundles` — hard veto, evaluated before anything else.
- `Type` — `App`, `Binary` or `Any`. Not optional in practice: a filter with no
  `Bundles`/`Classes`/`Executables` matches nothing unless `Type` is present, so
  `Any` is what makes a criteria-less filter apply everywhere.
- `Privilege` — `Any` (default), `Root`, or `User`. `User` keeps a tweak out of root
  processes entirely, which bounds what a package can reach. Absent means `Any`, so
  existing filters behave exactly as before.

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

## Getting it running

Three steps, because a loader that only affects processes started *after* it is
installed is not much use:

1. **Inject the launchd hook.** [Dylinject](https://github.com/doraorak/Dylinject)
   loads `launchd_hooks.dylib` into launchd (pid 1). From then on every process
   launchd spawns inherits `libtweakLoader.dylib`.
2. **Catch what was already running.** Everything alive before step 1 has no loader
   in it. `ldrestart` restarts userspace so those processes come back with it,
   without killing the session.
3. **Reboot survival.** The hook has to be re-injected after each boot.

TweakInject, the macOS app built on this, drives all of it from a GUI — install,
inject, ldrestart, per-process rules and tweak management — so none of the above
needs doing by hand. Its package repository is
[TweakInject-Store](https://github.com/doraorak/TweakInject-Store).

This repository is the engine underneath: the app depends on the loader, the loader
does not depend on the app, and nothing here assumes a particular front-end.

## Layout on disk

```
/Library/TweakInject/
├── libtweakLoader.dylib
├── DynamicLibraries/          tweak dylibs + their filter plists
├── DisabledLibraries/         disabled tweaks
├── denyInjectionList.plist    processes never injected
├── perProcessTweaks.plist     per-process enable/disable
└── LaunchdHook/               launchd + xpcproxy hooks
```

These must be `root:wheel`, directories `755` and files `644`. Everything here is
loaded into other processes — including root ones — so a world-writable directory
is a local privilege escalation, not a convenience.

## Building

Open `tweakLoader.xcodeproj` and set your own development team (the shipped project
has it blank), or build a component directly:

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

- `ldrestart` deliberately spares WindowServer and loginwindow and signals
  WindowServer with `SIGHUP` rather than `SIGKILL`. Killing either strands the
  machine at the login screen.
- The spawn hooks carry a blacklist of processes that must never be injected —
  `logd` above all, where logging from a constructor deadlocks the whole system.
