#!/bin/bash
#
# Build the payload and install it, refusing to install anything it cannot verify.
#
# This exists because of a specific failure. The documented build steps copied
# from ./build/Release, which Xcode stopped writing to at some point; the real
# products go to DerivedData. So every "rebuild and deploy" for an unknown number
# of sessions shipped a stale artifact, and the blacklist protecting the login
# and authentication stack — written, committed, believed to be live — was never
# in the running system. The symptom was a second `ldrestart` hanging at a blank
# login window, which looks nothing like a build problem.
#
# Copying from a path is therefore not enough. Every install below is checked for
# a string that only the current source can produce, and the script stops if it
# is missing.
#
#   ./deploy.sh            build, verify, install (asks for your password once)
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
CANARY_libtweakLoader="/Library/TweakInject/tweakinject.log"

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

echo "Building…"
for scheme in launchd_hooks xpcproxy_hooks tweakLoader ldrestart; do
    xcodebuild -project "$PROJECT" -scheme "$scheme" -configuration Release build \
        >/dev/null 2>&1 || { echo "  ✗ $scheme failed to build"; exit 1; }
    echo "  built $scheme"
done

DD="$(products_dir launchd_hooks)"
[ -n "$DD" ] || { echo "could not resolve BUILT_PRODUCTS_DIR"; exit 1; }
echo "Products: $DD"

echo "Verifying before install…"
verify "$DD/launchd_hooks.dylib"  "$CANARY_launchd_hooks"  "launchd_hooks"
verify "$DD/xpcproxy_hooks.dylib" "$CANARY_xpcproxy_hooks" "xpcproxy_hooks"
verify "$DD/libtweakLoader.dylib" "$CANARY_libtweakLoader" "libtweakLoader"

# PID 1 is arm64e. A slice-less or arm64-only build silently fails to inject.
for d in launchd_hooks xpcproxy_hooks; do
    lipo -archs "$DD/$d.dylib" | grep -q arm64e \
        || { echo "  ✗ $d.dylib has no arm64e slice — launchd will not load it"; exit 1; }
done
echo "  ✓ arm64e slices present"

echo "Installing (sudo)…"
sudo mkdir -p "$INSTALL_ROOT/LaunchdHook"
sudo cp "$DD/launchd_hooks.dylib"  "$INSTALL_ROOT/LaunchdHook/launchd_hooks.dylib"
sudo cp "$DD/xpcproxy_hooks.dylib" "$INSTALL_ROOT/LaunchdHook/xpcproxy_hooks.dylib"
sudo cp "$DD/libtweakLoader.dylib" "$INSTALL_ROOT/libtweakLoader.dylib"
[ -f "$DD/ldrestart" ] && sudo cp "$DD/ldrestart" /usr/local/bin/ldrestart

# The app bundle ships its own copy; leaving it stale reinstates the old payload
# the next time the app repairs itself.
if [ -d "$APP_PAYLOAD" ]; then
    cp "$DD/launchd_hooks.dylib"  "$APP_PAYLOAD/launchd_hooks.dylib"
    cp "$DD/xpcproxy_hooks.dylib" "$APP_PAYLOAD/xpcproxy_hooks.dylib"
    cp "$DD/libtweakLoader.dylib" "$APP_PAYLOAD/libtweakLoader.dylib"
    [ -f "$DD/ldrestart" ] && cp "$DD/ldrestart" "$APP_PAYLOAD/ldrestart"
    echo "  ✓ app Payload/ updated"
fi

echo "Verifying what is now installed…"
verify "$INSTALL_ROOT/LaunchdHook/launchd_hooks.dylib"  "$CANARY_launchd_hooks"  "launchd_hooks"
verify "$INSTALL_ROOT/LaunchdHook/xpcproxy_hooks.dylib" "$CANARY_xpcproxy_hooks" "xpcproxy_hooks"
verify "$INSTALL_ROOT/libtweakLoader.dylib"             "$CANARY_libtweakLoader" "libtweakLoader"
echo "Done. Re-hook launchd for this to take effect."
