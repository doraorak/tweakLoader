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
    unlink(SAFE_MODE_RUN);
    unlink(SAFE_MODE_FILE);
    unlink(SAFE_MODE_TMP);

    if (gSafeModeStatusItem) {
        [[NSStatusBar systemStatusBar] removeStatusItem:gSafeModeStatusItem];
        gSafeModeStatusItem = nil;
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

    NSStatusBarButton *button = [gSafeModeStatusItem button];
    if (button) {
        button.title = @"🔴 SAFE MODE";
        button.toolTip = @"TweakInject Safe Mode Active — Tweaks Bypassed";

        NSImage *shieldImg = [NSImage imageWithSystemSymbolName:@"exclamationmark.shield.fill" accessibilityDescription:@"Safe Mode"];
        if (shieldImg) {
            NSImageSymbolConfiguration *config = [NSImageSymbolConfiguration configurationWithHierarchicalColor:[NSColor systemRedColor]];
            shieldImg = [shieldImg imageWithSymbolConfiguration:config];
            button.image = shieldImg;
            button.imagePosition = NSImageLeading;
        }
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

static void ensure_status_item_installed(int attempt) {
    if (gSafeModeStatusItem) {
        return;
    }
    if (NSApp) {
        install_safe_mode_pill();
        if (gSafeModeStatusItem) return;
    }
    if (attempt < 30) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            ensure_status_item_installed(attempt + 1);
        });
    }
}

__attribute__((constructor))
static void init_safe_mode_pill(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        ensure_status_item_installed(0);
    });
}
