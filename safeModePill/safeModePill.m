#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <unistd.h>
#import <stdio.h>
#import <string.h>

#define SAFE_MODE_MARKER "/Library/TweakInject/SafeMode/.safemode"
// Watched by the helper's LaunchDaemon. Dropping this file is how an
// unprivileged injected dylib asks for a privileged action: launchd starts the
// helper, which clears the marker and restarts userspace.
#define SAFE_MODE_EXIT_REQUEST "/tmp/.tweakinject-safemode-exit-request"

@interface SafeModeMenuHandler : NSObject
+ (instancetype)sharedHandler;
- (void)exitSafeMode:(id)sender;
- (void)openTweakInject:(id)sender;
@end

static NSStatusItem *gSafeModeStatusItem = nil;
static SafeModeMenuHandler *gMenuHandler = nil;

@implementation SafeModeMenuHandler

+ (instancetype)sharedHandler {
    static SafeModeMenuHandler *handler = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        handler = [[SafeModeMenuHandler alloc] init];
    });
    return handler;
}

- (void)exitSafeMode:(id)sender {
    // Unlinking the marker here cannot work: it is root:wheel and this runs as
    // the user inside a menu bar agent, so unlink() fails with EPERM. An earlier
    // version dropped the status item anyway, which made a failed exit look like
    // a successful one -- Safe Mode stayed on with nothing on screen saying so.
    //
    // Nor can this ask the helper directly: its XPC listener requires the caller
    // to be the app AND to carry no foreign image, and this host fails both.
    //
    // So it writes the request file the helper's LaunchDaemon watches. launchd
    // starts the helper, which clears the marker and restarts userspace -- the
    // reboot matters, because every process running now spawned under Safe Mode
    // with no tweaks in it. The pill removes itself on the next poll once the
    // marker is actually gone, so a failure still shows as "still in Safe Mode".
    const char *record = "exit requested from the menu bar pill\n";
    FILE *f = fopen(SAFE_MODE_EXIT_REQUEST, "w");
    if (f) {
        fwrite(record, 1, strlen(record), f);
        fclose(f);
    }
}

- (void)openTweakInject:(id)sender {
    system("open -a TweakInject 2>/dev/null || true");
}

@end

static void install_safe_mode_pill(void) {
    if (gSafeModeStatusItem) {
        return;
    }

    NSStatusBar *statusBar = [NSStatusBar systemStatusBar];
    if (!statusBar) return;

    gSafeModeStatusItem = [statusBar statusItemWithLength:NSVariableStatusItemLength];
    if (!gSafeModeStatusItem) return;

    // Retain persistently so it never deallocates in the host process
    CFRetain((__bridge CFTypeRef)gSafeModeStatusItem);

    // A stable autosave name, and visibility asserted rather than assumed.
    //
    // The host is ControlCenter, where menu bar visibility is USER-OWNED POLICY
    // persisted per autosave name -- the same mechanism System Settings uses to
    // let someone hide Wi-Fi or the clock. An item created there is born HIDDEN:
    // verified on the live process, a fresh statusItemWithLength: comes back with
    // flags 0xa0940 and isVisible == 0, where the identical call in Finder comes
    // back 0xa0950 and isVisible == 1. -[NSStatusItem isVisible] reads bit 0x10
    // in both (bit 0x20 selects it and is clear either way), so the whole
    // difference is one bit nobody sets. The class is the same NSSceneStatusItem
    // in both processes, so this was never about ControlCenter being exotic.
    //
    // Without an autosave name AppKit invents one, so every relaunch claimed a
    // fresh "Item-N" slot in com.apple.controlcenter and recorded it hidden.
    gSafeModeStatusItem.autosaveName = @"TweakInjectSafeMode";
    gSafeModeStatusItem.visible = YES;

    NSStatusBarButton *button = [gSafeModeStatusItem button];
    if (button) {
        button.toolTip = @"TweakInject Safe Mode Active — Tweaks Bypassed";

        // Drawn, not looked up. The old version set an emoji title plus an SF
        // Symbol tinted with a hierarchical colour, and rendered as an empty
        // slot: a pill occupying menu bar space with nothing in it. A
        // programmatic image cannot come back nil, cannot resolve to a missing
        // glyph, and cannot be flattened by a template/tint interaction.
        NSImage *dot = [NSImage imageWithSize:NSMakeSize(10, 10) flipped:NO
                               drawingHandler:^BOOL(NSRect rect) {
            [[NSColor systemRedColor] setFill];
            [[NSBezierPath bezierPathWithOvalInRect:NSInsetRect(rect, 1, 1)] fill];
            return YES;
        }];
        dot.template = NO;
        button.image = dot;
        button.imagePosition = NSImageLeading;

        // An explicit foreground colour, so it stays legible whatever the host
        // process does to the menu bar appearance.
        button.attributedTitle = [[NSAttributedString alloc]
            initWithString:@" SAFE MODE"
                attributes:@{ NSFontAttributeName: [NSFont systemFontOfSize:11 weight:NSFontWeightBold],
                              NSForegroundColorAttributeName: [NSColor systemRedColor] }];
    }

    gMenuHandler = [SafeModeMenuHandler sharedHandler];

    NSMenu *menu = [[NSMenu alloc] initWithTitle:@"Safe Mode Menu"];

    NSMenuItem *headerItem = [[NSMenuItem alloc] initWithTitle:@"⚠️ TweakInject Safe Mode Active" action:nil keyEquivalent:@""];
    [headerItem setEnabled:NO];
    [menu addItem:headerItem];

    NSMenuItem *statusDesc = [[NSMenuItem alloc] initWithTitle:@"All tweaks are currently stood down." action:nil keyEquivalent:@""];
    [statusDesc setEnabled:NO];
    [menu addItem:statusDesc];

    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *openAppItem = [[NSMenuItem alloc] initWithTitle:@"Open TweakInject App…" action:@selector(openTweakInject:) keyEquivalent:@""];
    [openAppItem setTarget:gMenuHandler];
    [openAppItem setEnabled:YES];
    [menu addItem:openAppItem];

    NSMenuItem *exitItem = [[NSMenuItem alloc] initWithTitle:@"Exit Safe Mode" action:@selector(exitSafeMode:) keyEquivalent:@""];
    [exitItem setTarget:gMenuHandler];
    [exitItem setEnabled:YES];
    [menu addItem:exitItem];

    [gSafeModeStatusItem setMenu:menu];
}

// One marker, matching the hooks, the loader and the app. The *.txt scan this
// replaces existed because the Safe Mode directory doubled as runtime state;
// it now holds the two Safe Mode dylibs and nothing else.
static BOOL safe_mode_is_active(void) {
    return access(SAFE_MODE_MARKER, F_OK) == 0;
}

static void remove_safe_mode_pill(void) {
    if (!gSafeModeStatusItem) return;
    [[NSStatusBar systemStatusBar] removeStatusItem:gSafeModeStatusItem];
    gSafeModeStatusItem = nil;
}

/// Reconcile what is on screen with what is on disk, forever.
///
/// The old code installed the pill once from the constructor and never looked
/// again. The loader only injects this dylib into processes that SPAWN while
/// Safe Mode is on, so the indicator was right at spawn and then frozen: leave
/// Safe Mode and the pill stayed in the running Dock claiming tweaks were stood
/// down, with an Exit item that could not clear the flag. Polling is cheap --
/// three access() calls -- and unlike a VNODE source it survives the marker
/// being deleted and recreated.
static void sync_safe_mode_pill(void) {
    if (!NSApp) return;
    if (safe_mode_is_active()) {
        install_safe_mode_pill();
        // Re-assert, because this is a safety indicator and not a preference. A
        // command-drag off the menu bar persists visible=NO under our autosave
        // name, which would otherwise silently retire the one thing on screen
        // saying tweaks are stood down. Guarded so it only writes when actually
        // off, rather than churning the pref every 1.5 seconds.
        if (gSafeModeStatusItem && !gSafeModeStatusItem.visible) {
            gSafeModeStatusItem.visible = YES;
        }
    } else {
        remove_safe_mode_pill();
    }
}

static void schedule_sync(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        sync_safe_mode_pill();
        schedule_sync();
    });
}

__attribute__((constructor))
static void init_safe_mode_pill(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        sync_safe_mode_pill();
        schedule_sync();
    });
}
