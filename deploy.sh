#!/bin/bash
#
# Installs the payload from the app bundle into /Library/TweakInject.
#
# Building is no longer this script's job. The app's own build now builds every
# component and refreshes its Payload/ (see scripts/build-payload.sh in the app
# project, wired in as a pre-build phase), so there is exactly one way to
# produce a payload and it cannot be skipped by forgetting a command. This is
# only the privileged copy onto this machine, for when you want it without
# opening the app.
#
# Prefer the app: the payload station installs the same files through the
# helper, and it also knows how to tell you when what is installed is older than
# what the app ships.
#
#   ./deploy.sh            install from the built app bundle (asks for your password)
#   ./deploy.sh --verify   verify what is currently installed, install nothing
#
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT="$PROJECT_DIR/tweakLoader.xcodeproj"
INSTALL_ROOT="/Library/TweakInject"
APP_PAYLOAD="/Users/doraorak/Desktop/programming/XCode-projects/APP/My apps/TweakInjectApp/Payload"

# A canary per component: a string the CURRENT source produces and an older
# build does not. Update these whenever the thing they prove changes.
CANARY_launchd_hooks="SecurityAgent"
CANARY_xpcproxy_hooks="SecurityAgent"
CANARY_libtweakLoader="/Library/TweakInject/logs/tweakinject.log"

products_dir() {
    xcodebuild -project "$PROJECT" -scheme "$1" -configuration Release \
        -showBuildSettings 2>/dev/null \
        | awk -F' = ' '/ BUILT_PRODUCTS_DIR = /{print $2; exit}'
}

verify() {
    local file="$1" canary="$2" label="$3"
    if [ ! -f "$file" ]; then
        echo "  ✗ $label: missing at $file"; return 1
    fi
    if ! strings -a "$file" 2>/dev/null | grep -qF "$canary"; then
        echo "  ✗ $label: does not contain \"$canary\" — this is a stale build"
        return 1
    fi
    echo "  ✓ $label  ($(stat -f%z "$file") bytes, built $(stat -f%Sm -t '%H:%M' "$file"))"
}

if [ "${1:-}" = "--verify" ]; then
    echo "Installed payload:"
    verify "$INSTALL_ROOT/LaunchdHook/launchd_hooks.dylib"  "$CANARY_launchd_hooks"  "launchd_hooks" || true
    verify "$INSTALL_ROOT/LaunchdHook/xpcproxy_hooks.dylib" "$CANARY_xpcproxy_hooks" "xpcproxy_hooks" || true
    verify "$INSTALL_ROOT/libtweakLoader.dylib"             "$CANARY_libtweakLoader" "libtweakLoader" || true
    exit 0
fi

APP="$(ls -d "$HOME/Library/Developer/Xcode/DerivedData/TweakInject-"*/Build/Products/Debug/TweakInject.app 2>/dev/null | head -1)"
[ -n "$APP" ] || { echo "No built TweakInject.app found. Build the app first."; exit 1; }
DD="$APP/Contents/Resources/Payload"
echo "Source: $DD"

echo "Verifying before install…"
verify "$DD/LaunchdHook/launchd_hooks.dylib"  "$CANARY_launchd_hooks"  "launchd_hooks"
verify "$DD/LaunchdHook/xpcproxy_hooks.dylib" "$CANARY_xpcproxy_hooks" "xpcproxy_hooks"
verify "$DD/libtweakLoader.dylib" "$CANARY_libtweakLoader" "libtweakLoader"

# PID 1 is arm64e. A slice-less or arm64-only build silently fails to inject.
for d in launchd_hooks xpcproxy_hooks; do
    lipo -archs "$DD/LaunchdHook/$d.dylib" | grep -q arm64e \
        || { echo "  ✗ $d.dylib has no arm64e slice — launchd will not load it"; exit 1; }
done
echo "  ✓ arm64e slices present"

echo "Installing (sudo)…"
sudo mkdir -p "$INSTALL_ROOT/LaunchdHook" "$INSTALL_ROOT/SafeMode"
sudo cp "$DD/LaunchdHook/launchd_hooks.dylib"  "$INSTALL_ROOT/LaunchdHook/launchd_hooks.dylib"
sudo cp "$DD/LaunchdHook/xpcproxy_hooks.dylib" "$INSTALL_ROOT/LaunchdHook/xpcproxy_hooks.dylib"
sudo cp "$DD/libtweakLoader.dylib" "$INSTALL_ROOT/libtweakLoader.dylib"
[ -f "$DD/ldrestart" ] && sudo cp "$DD/ldrestart" /usr/local/bin/ldrestart

# The pill lives beside the Safe Mode markers it advertises. Deploying the
# loader without it leaves the loader dlopen()ing a path that does not exist.
sudo cp "$DD/libsafeModePill.dylib" "$INSTALL_ROOT/SafeMode/libsafeModePill.dylib"
# It used to live in the payload root; nothing loads it from there any more.
sudo rm -f "$INSTALL_ROOT/libsafeModePill.dylib"
sudo chown -R root:wheel "$INSTALL_ROOT/SafeMode"
sudo chmod 755 "$INSTALL_ROOT/SafeMode"
[ -f "$INSTALL_ROOT/SafeMode/libsafeModePill.dylib" ] && sudo chmod 755 "$INSTALL_ROOT/SafeMode/libsafeModePill.dylib"

echo "Verifying what is now installed…"
verify "$INSTALL_ROOT/LaunchdHook/launchd_hooks.dylib"  "$CANARY_launchd_hooks"  "launchd_hooks"
verify "$INSTALL_ROOT/LaunchdHook/xpcproxy_hooks.dylib" "$CANARY_xpcproxy_hooks" "xpcproxy_hooks"
verify "$INSTALL_ROOT/libtweakLoader.dylib"             "$CANARY_libtweakLoader" "libtweakLoader"
echo "Done. Re-hook launchd for this to take effect."
