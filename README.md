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
- `Type` — `App`, `Binary` or `All`.
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

## Notes

- `ldrestart` deliberately spares WindowServer and loginwindow and signals
  WindowServer with `SIGHUP` rather than `SIGKILL`. Killing either strands the
  machine at the login screen.
- The spawn hooks carry a blacklist of processes that must never be injected —
  `logd` above all, where logging from a constructor deadlocks the whole system.
