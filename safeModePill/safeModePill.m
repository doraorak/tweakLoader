#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <unistd.h>

#define SAFE_MODE_RUN  "/var/run/tweakinject.safemode"
#define SAFE_MODE_FILE "/Library/TweakInject/SafeMode/safemode.txt"
#define SAFE_MODE_TMP  "/tmp/.safemode"

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
    // This used to unlink the markers here and drop the status item. Both halves
    // were wrong: /var/run and /Library/TweakInject/SafeMode are root:wheel and
    // this runs as the user inside Dock, so every unlink() failed with EPERM --
    // and removing the item anyway made a failed exit look like a successful
    // one. Safe Mode stayed on with nothing on screen saying so.
    //
    // Clearing the flag needs the privileged helper, so it happens in the app.
    // The item disappears on its own once the flag is actually gone.
    system("open -a TweakInject 2>/dev/null || true");
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

    NSMenuItem *exitItem = [[NSMenuItem alloc] initWithTitle:@"Exit Safe Mode in TweakInject…" action:@selector(exitSafeMode:) keyEquivalent:@""];
    [exitItem setTarget:gMenuHandler];
    [exitItem setEnabled:YES];
    [menu addItem:exitItem];

    [gSafeModeStatusItem setMenu:menu];
}

static BOOL safe_mode_is_active(void) {
    if (access(SAFE_MODE_RUN, F_OK) == 0) return YES;
    if (access(SAFE_MODE_FILE, F_OK) == 0) return YES;
    if (access(SAFE_MODE_TMP, F_OK) == 0) return YES;
    // Any *.txt in the Safe Mode directory counts, matching the loader. The pill
    // dylib now lives in that directory too, which is why the suffix matters.
    NSArray<NSString *> *names = [[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:@"/Library/TweakInject/SafeMode" error:NULL];
    for (NSString *n in names) {
        if ([[n lowercaseString] hasSuffix:@".txt"]) return YES;
    }
    return NO;
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
