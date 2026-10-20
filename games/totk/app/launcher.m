// The launcher inside the packaged app (build_app.py compiles it as Contents/MacOS/TOTK).
// The game itself is Contents/Resources/totk/build/totk-native; everything it writes goes to the player's own folders:
//   ~/Library/Application Support/MacNativeGames/TOTK/   profile (account, saves), shader cache, game slot, RomFS proof
//   ~/Library/Logs/MacNativeGames/totk.log             this run (totk.previous.log: the one before)
// If the game is already running, the launcher only brings it to the front.
#import <AppKit/AppKit.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <unistd.h>
#include "dmsh_chain.h"   // DMSH_CHAIN: the shader translation chain the cache folder is named after
#include "game_version.h"
#include "controller_map.h"
#include "include/totk_ui_lang.h"
#include "totk_shader_contrib.h"   // the shared shader list contribution and its reminder

static void show_error(NSString *detail) {
    NSAlert *alert = [NSAlert new];
    alert.messageText = @"The game could not start";
    alert.informativeText = detail;
    [alert runModal];
}

static NSDictionary<NSString *, NSString *> *kv_read(NSString *path) {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    NSString *text = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    for (NSString *line in [text componentsSeparatedByString:@"\n"]) {
        NSRange eq = [line rangeOfString:@"="];
        if (eq.location == NSNotFound) continue;
        NSString *key = [line substringToIndex:eq.location];
        if (!out[key]) out[key] = [line substringFromIndex:eq.location + 1];
    }
    return out;
}

static uint64_t pid_start(pid_t pid) {   // 0 if gone or a zombie; with the pid it names one process exactly
    struct proc_bsdinfo bi;
    if (pid <= 0 || proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) != (int)sizeof bi || bi.pbi_status == SZOMB) return 0;
    return bi.pbi_start_tvsec;
}

/* The game slot (runtime/game_slot.c): the running game holds an exclusive lock on <slot>/lock and names itself in
   <slot>/holder. Returns the running game's pid, or 0. */
static pid_t running_game(NSString *slot) {
    int fd = open([slot stringByAppendingPathComponent:@"lock"].fileSystemRepresentation, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    int held = flock(fd, LOCK_EX | LOCK_NB) != 0;
    close(fd);
    if (!held) return 0;
    NSDictionary *h = kv_read([slot stringByAppendingPathComponent:@"holder"]);
    /* A player launch must reach runtime/game_slot.c to preempt an agent's
       test. Only an existing player game (or another test for a test request)
       is brought forward here. */
    const char *requestOwner = getenv("TOTK_SLOT_OWNER");
    if (![h[@"owner"] isEqualToString:@"user"] &&
        (!requestOwner || !*requestOwner || !strcmp(requestOwner, "user"))) return 0;
    pid_t pid = [h[@"game_pid"] intValue];
    return pid > 0 && pid_start(pid) == (uint64_t)[h[@"game_start"] longLongValue] ? pid : 0;
}

/* Every TOTK_CONTRIB_STEP shaders the shared list does not have yet (totk_shader_contrib.h), before the game starts: ask
   the player to send the file in a GitHub issue. "Send" opens the issue form and shows the file in Finder to drag in. */
static void contrib_reminder(NSString *path) {
    NSUInteger rows = totk_contrib_due(path);
    if (!rows) return;
    totk_contrib_reminded(path, rows);   // "next time": TOTK_CONTRIB_STEP rows later; "don't remind me again": never
    [NSApplication sharedApplication]; [NSApp activateIgnoringOtherApps:YES];
    NSAlert *alert = [NSAlert new];
    alert.messageText = @(TOTK_UI("期待你的贡献", "We would love your contribution"));
    alert.informativeText = [NSString stringWithFormat:@(TOTK_UI("你有 %lu 个着色器可以贡献：玩的时候遇到的、公共着色器清单里还没有的。它们记在一个小文件里，只有着色器的标识，不含游戏内容、存档或个人信息。把它发到 GitHub 加进公共清单，以后大家打包的 App 都会带上它们，玩到那里不再卡顿。\n\n点“发送”会打开 GitHub 的提交页面，并在访达里显示这个文件，把它拖进页面即可。",
                                      "You have %lu shaders to contribute: ones your game met that the shared shader list does not have yet. They are kept in a small file with shader identifiers only: no game data, saves or personal information. Sent to GitHub and added to the shared list, they come with everyone's next build, and nobody stutters there again.\n\n\"Send\" opens the GitHub form and shows the file in Finder: drag it into the form.")), (unsigned long)rows];
    [alert addButtonWithTitle:@(TOTK_UI("发送", "Send"))];
    [alert addButtonWithTitle:@(TOTK_UI("下次提醒", "Remind me next time"))];
    [alert addButtonWithTitle:@(TOTK_UI("不要提醒了", "Don't remind me again"))];
    NSModalResponse choice = [alert runModal];
    if (choice == NSAlertThirdButtonReturn) totk_contrib_never(path);
    if (choice != NSAlertFirstButtonReturn) return;
    [NSWorkspace.sharedWorkspace openURL:[NSURL URLWithString:@TOTK_CONTRIB_ISSUE_URL]];
    [NSWorkspace.sharedWorkspace activateFileViewerSelectingURLs:@[[NSURL fileURLWithPath:path]]];
}

static BOOL make_dir(NSString *path) {
    return [NSFileManager.defaultManager createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:nil];
}

/* Settings window shown before the game starts. Every choice maps to environment variables the runtime already reads;
   the choices are kept in the app's user defaults. Hold Option while opening the app to see the window again after
   "Show this window at every launch" was turned off. Test runs (TOTK_SLOT_OWNER other than user, or TOTK_LAUNCHER=0)
   skip it, and a variable that is already set in the environment always wins over the window's choice. */
typedef struct { NSString *key, *title; NSArray<NSString *> *labels; NSInteger fallback; NSString *help; } Choice;
enum { C_DISPLAY, C_OUTPUT, C_SCENE, C_UPSCALE, C_ANISO, C_SHADOWS, C_DETAIL, C_INTERP, C_FPS, C_PAD, C_ICONS, NCHOICES };
static Choice choices[NCHOICES];
static void choices_init(void) {
    choices[C_DISPLAY] = (Choice){@"display", @"Display", @[@"Full screen", @"Window"], 0,
        @"Full screen uses the whole display. A 16:9 resolution keeps black bars on an ultrawide display; the ultrawide resolution fills it."};
    choices[C_OUTPUT] = (Choice){@"output", @"Resolution", @[@"1920 × 1080", @"2560 × 1440", @"3440 × 1440 (ultrawide 21:9)"], 1,
        @"The size the game composes its picture and menus at. Key 3 switches to 1080p while playing."};
    choices[C_SCENE] = (Choice){@"scene", @"3D resolution", @[@"Native (900 lines)", @"1080 lines", @"1440 lines"], 0,
        @"How many lines the 3D world is rendered with before upscaling (1600 × 900 is the Switch\u2019s docked size; on the ultrawide canvas the width follows 21:9). Higher is sharper and needs more GPU time."};
    choices[C_UPSCALE] = (Choice){@"upscale", @"Upscaling", @[@"MetalFX", @"Built-in (FSR 1)"], 0,
        @"How the 3D scene is scaled up to the chosen resolution and to the screen."};
    choices[C_ANISO] = (Choice){@"aniso", @"Texture filtering", @[@"Game default", @"4x anisotropic", @"8x anisotropic", @"16x anisotropic"], 3,
        @"Sharper ground, roads and walls seen at a shallow angle. Almost free on a Mac GPU."};
    choices[C_SHADOWS] = (Choice){@"shadows", @"Shadows", @[@"Game default", @"Sharp (2048)", @"Sharpest (4096)"], 1,
        @"Shadow map size, through UltraCam. The game draws shadows 800 pixels wide; 2048 costs under a millisecond per frame, 4096 about one and a half."};
    choices[C_DETAIL] = (Choice){@"detail", @"Level of detail", @[@"Game default", @"Higher"], 1,
        @"Through UltraCam: trees and objects keep their full models further away (its draw distance setting 25000 \u2192 50000)."};
    choices[C_INTERP] = (Choice){@"interp", @"Frame generation", @[@"Off", @"30 + 30", @"Half the refresh rate", @"Unlimited"], 3,
        @"MetalFX frame interpolation: a generated frame between every two game frames. Key 2 cycles it while playing."};
    choices[C_FPS] = (Choice){@"fps", @"Frame rate", @[@"Up to 60 FPS", @"Original 30 FPS"], 0,
        @"Up to 60 FPS lets the game run faster than the Switch's 30 FPS where the Mac keeps up."};
    choices[C_PAD] = (Choice){@"pad", @"Controller", @[@"Switch layout (by position)", @"As labeled on the controller"], 0,
        @"Switch layout: the right face button is A and the bottom one is B, as the on-screen prompts show."};
    choices[C_ICONS] = (Choice){@"icons", @"Button icons", @[@"Xbox (A B X Y as on the controller)", @"Nintendo"], 0,
        @"With the Switch layout, the prompts show the letter printed on an Xbox controller's button: the right one is B, the bottom one A."};
}
static NSString *const kShowFps = @"showOverlay", *const kShowWindow = @"showLauncher", *const kDynres = @"fixedResolution";

static void put(const char *name, const char *value) { if (value) setenv(name, value, 0); }
/* UltraCam (MaxLastBreath's exlaunch plugin), rewritten into the app by build_app.py --ultracam: its rows only show then. */
static NSString *ultracam_dir(void) {
    NSString *dir = [NSBundle.mainBundle.resourcePath stringByAppendingPathComponent:@"totk/rewritten/plugins/ultracam"];
    return [NSFileManager.defaultManager fileExistsAtPath:[dir stringByAppendingPathComponent:@"subsdk3.patched.bin"]] ? dir : nil;
}
static void apply_settings(NSUserDefaults *d) {
    NSInteger v[NCHOICES];
    for (int i = 0; i < NCHOICES; i++) {
        id o = [d objectForKey:choices[i].key];
        v[i] = o ? [o integerValue] : choices[i].fallback;
        if (v[i] < 0 || v[i] >= (NSInteger)choices[i].labels.count) v[i] = choices[i].fallback;
    }
    put("TOTK_FULLSCREEN", v[C_DISPLAY] == 0 ? "1" : "0");
    static const char *outputs[] = {"0", "2560x1440", "3440x1440"};
    put("TOTK_OUTPUT_RES", outputs[v[C_OUTPUT]]);
    /* The game's own RomFS fixes come in variants (scripts/make_romfs_patches.py): -3440x1440 lays the UI out for a true
       21:9 canvas, -xbox gives the prompts Xbox face-button letters (only with the by-position mapping: by label the
       Nintendo letters already match the Xbox controller's). */
    int wide = v[C_OUTPUT] == 2, xbox = v[C_ICONS] == 0 && v[C_PAD] == 0;
    if (wide) {   // a true 21:9 canvas: the camera's aspect follows it (runtime/aspect_patch.h), the UI is not squeezed at draw time
        put("TOTK_ASPECT", "3440x1440");
        put("TOTK_UI_SQUEEZE", "0");
    }
    if (wide || xbox) {
        char patches[128];
        snprintf(patches, sizeof patches, "extracted/" TOTK_GAME_DIR "/romfs-patches%s%s", wide ? "-3440x1440" : "", xbox ? "-xbox" : "");
        put("TOTK_ROMFS_PATCHES", patches);
    }
    /* The 3D size follows the canvas's shape: the same 900 / 1080 / 1440 lines, 21:9 wide on the ultrawide canvas. Native
       is given explicitly too: left to itself the game scales its 1600 x 900 with the canvas width. */
    static const char *scenes[] = {"1600x900", "1920x1080", "2560x1440"}, *wide_scenes[] = {"2150x900", "2580x1080", "3440x1440"};
    put("TOTK_RENDER_RES", (v[C_OUTPUT] == 2 ? wide_scenes : scenes)[v[C_SCENE]]);
    put("TOTK_MFX_UPSCALE", v[C_UPSCALE] == 0 ? "1" : "0");
    put("TOTK_MFX_OUTPUT", v[C_UPSCALE] == 0 ? "1" : "0");
    static const char *aniso[] = {"0", "4", "8", "16"};
    put("TOTK_ANISO", aniso[v[C_ANISO]]);
    NSString *ultracam = ultracam_dir();
    if (ultracam && (v[C_SHADOWS] || v[C_DETAIL])) {
        static const char *sizes[] = {"0", "2048", "4096"};
        put("TOTK_PLUGIN", ultracam.fileSystemRepresentation);
        put("TOTK_ULTRACAM_SHADOWS", sizes[v[C_SHADOWS]]);
        put("TOTK_ULTRACAM_LOD", v[C_DETAIL] ? "5" : "1");
    }
    put("TOTK_DYNRES", [d objectForKey:kDynres] == nil || [d boolForKey:kDynres] ? "0" : "1");
    static const char *interp[] = {"0", "interp30", "interp", "interpmax"};
    put("TOTK_MFX", interp[v[C_INTERP]]);
    put("TOTK_FPS60", v[C_FPS] == 0 ? "1" : "0");
    if (v[C_PAD] == 1) put("TOTK_FACE_BUTTONS", "label");   // unset: by position, a real Switch pad unchanged (runtime/gamepad_layout.h)
    const char *overlay = [d objectForKey:kShowFps] && [d boolForKey:kShowFps] ? "1" : "0";
    put("TOTK_HINTS", overlay); put("TOTK_FPS_OVERLAY", overlay); put("TOTK_SHADER_OVERLAY", overlay); put("TOTK_LOAD_OVERLAY", overlay);
}

@interface TOTKLauncherWindow : NSObject <NSWindowDelegate>
@property(strong) NSWindow *window;
@property(strong) NSMutableArray<NSPopUpButton *> *popups;
@property(strong) NSButton *overlay, *showAgain, *dynres;
@end
@implementation TOTKLauncherWindow
static NSTextField *label(NSString *text, CGFloat size, NSFontWeight weight, NSColor *color) {
    NSTextField *l = [NSTextField labelWithString:text];
    l.font = [NSFont systemFontOfSize:size weight:weight]; l.textColor = color;
    return l;
}
- (instancetype)init {
    if (!(self = [super init])) return nil;
    NSUserDefaults *d = NSUserDefaults.standardUserDefaults;
    self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 560, 100)
                                              styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskFullSizeContentView
                                                backing:NSBackingStoreBuffered defer:NO];
    self.window.titlebarAppearsTransparent = YES; self.window.titleVisibility = NSWindowTitleHidden;
    self.window.movableByWindowBackground = YES; self.window.delegate = self; self.window.releasedWhenClosed = NO;
    NSVisualEffectView *bg = [NSVisualEffectView new];
    bg.material = NSVisualEffectMaterialUnderWindowBackground; bg.blendingMode = NSVisualEffectBlendingModeBehindWindow;
    bg.state = NSVisualEffectStateActive; self.window.contentView = bg;

    NSImageView *icon = [NSImageView imageViewWithImage:NSApp.applicationIconImage];
    icon.imageScaling = NSImageScaleProportionallyUpOrDown;
    [icon.widthAnchor constraintEqualToConstant:72].active = YES; [icon.heightAnchor constraintEqualToConstant:72].active = YES;
    NSTextField *title = label(@"Tears of the Kingdom", 24, NSFontWeightBold, NSColor.labelColor);
    NSTextField *subtitle = label([NSString stringWithFormat:@"The Legend of Zelda  ·  Version %s  ·  Native Mac port", TOTK_GAME_VERSION],
                                  12, NSFontWeightRegular, NSColor.secondaryLabelColor);
    NSStackView *names = [NSStackView stackViewWithViews:@[title, subtitle]];
    names.orientation = NSUserInterfaceLayoutOrientationVertical; names.alignment = NSLayoutAttributeLeading; names.spacing = 2;
    NSStackView *header = [NSStackView stackViewWithViews:@[icon, names]];
    header.spacing = 16; header.alignment = NSLayoutAttributeCenterY;

    self.popups = [NSMutableArray array];
    NSMutableArray *rows = [NSMutableArray array];
    for (int i = 0; i < NCHOICES; i++) {
        NSPopUpButton *p = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
        [p addItemsWithTitles:choices[i].labels];
        id o = [d objectForKey:choices[i].key]; NSInteger v = o ? [o integerValue] : choices[i].fallback;
        [p selectItemAtIndex:v >= 0 && v < (NSInteger)choices[i].labels.count ? v : choices[i].fallback];
        p.toolTip = choices[i].help;
        [p.widthAnchor constraintEqualToConstant:260].active = YES;
        [self.popups addObject:p];
        if ((i == C_SHADOWS || i == C_DETAIL) && !ultracam_dir()) continue;
        [rows addObject:@[label([choices[i].title stringByAppendingString:@":"], 13, NSFontWeightRegular, NSColor.labelColor), p]];
    }
    self.dynres = [NSButton checkboxWithTitle:@"Keep the 3D resolution fixed" target:nil action:nil];
    self.dynres.state = [d objectForKey:kDynres] == nil || [d boolForKey:kDynres] ? NSControlStateValueOn : NSControlStateValueOff;
    self.dynres.toolTip = @"The Switch lowers the 3D resolution in busy scenes; on a Mac it can stay at full size all the time.";
    [rows addObject:@[label(@"Sharpness:", 13, NSFontWeightRegular, NSColor.labelColor), self.dynres]];
    self.overlay = [NSButton checkboxWithTitle:@"Show FPS counter and shortcut panel" target:nil action:nil];
    self.overlay.state = [d boolForKey:kShowFps] ? NSControlStateValueOn : NSControlStateValueOff;
    [rows addObject:@[label(@"On screen:", 13, NSFontWeightRegular, NSColor.labelColor), self.overlay]];
    NSGridView *grid = [NSGridView gridViewWithViews:rows];
    grid.rowSpacing = 12; grid.columnSpacing = 12;
    [grid columnAtIndex:0].xPlacement = NSGridCellPlacementTrailing;
    for (NSInteger r = 0; r < grid.numberOfRows; r++) [grid rowAtIndex:r].yPlacement = NSGridCellPlacementCenter;

    NSTextField *keys = label(@"While playing:  1  on-screen info    2  frame generation    3  resolution    4  21:9 view    5  edge smoothing", 11, NSFontWeightRegular, NSColor.tertiaryLabelColor);
    self.showAgain = [NSButton checkboxWithTitle:@"Show this window at every launch" target:nil action:nil];
    self.showAgain.state = [d objectForKey:kShowWindow] == nil || [d boolForKey:kShowWindow] ? NSControlStateValueOn : NSControlStateValueOff;
    self.showAgain.toolTip = @"When it is off, hold Option while opening the game to see this window.";
    self.showAgain.controlSize = NSControlSizeSmall; self.showAgain.font = [NSFont systemFontOfSize:11];
    NSButton *quit = [NSButton buttonWithTitle:@"Quit" target:self action:@selector(quit:)];
    quit.keyEquivalent = @"\033";
    NSButton *play = [NSButton buttonWithTitle:@"Play" target:self action:@selector(play:)];
    play.keyEquivalent = @"\r"; play.bezelColor = NSColor.controlAccentColor;
    [play.widthAnchor constraintGreaterThanOrEqualToConstant:96].active = YES;
    NSView *spacer = [NSView new]; [spacer setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    NSStackView *footer = [NSStackView stackViewWithViews:@[self.showAgain, spacer, quit, play]];
    footer.spacing = 10; footer.alignment = NSLayoutAttributeCenterY;

    NSBox *line = [NSBox new]; line.boxType = NSBoxSeparator;
    NSStackView *main = [NSStackView stackViewWithViews:@[header, line, grid, keys, footer]];
    main.orientation = NSUserInterfaceLayoutOrientationVertical; main.alignment = NSLayoutAttributeCenterX; main.spacing = 18;
    [main setCustomSpacing:22 afterView:header]; [main setCustomSpacing:14 afterView:grid]; [main setCustomSpacing:24 afterView:keys];
    main.edgeInsets = NSEdgeInsetsMake(40, 32, 26, 32); main.translatesAutoresizingMaskIntoConstraints = NO;
    [bg addSubview:main];
    [NSLayoutConstraint activateConstraints:@[
        [main.leadingAnchor constraintEqualToAnchor:bg.leadingAnchor], [main.trailingAnchor constraintEqualToAnchor:bg.trailingAnchor],
        [main.topAnchor constraintEqualToAnchor:bg.topAnchor], [main.bottomAnchor constraintEqualToAnchor:bg.bottomAnchor],
        [main.widthAnchor constraintEqualToConstant:560],
        [header.widthAnchor constraintEqualToAnchor:main.widthAnchor constant:-64], [line.widthAnchor constraintEqualToAnchor:main.widthAnchor constant:-64],
        [footer.widthAnchor constraintEqualToAnchor:main.widthAnchor constant:-64]]];
    [bg layoutSubtreeIfNeeded];
    [self.window setContentSize:main.fittingSize];
    [self.window center];
    self.window.initialFirstResponder = play;
    return self;
}
- (void)play:(id)sender {
    (void)sender;
    NSUserDefaults *d = NSUserDefaults.standardUserDefaults;
    for (int i = 0; i < NCHOICES; i++) [d setInteger:self.popups[i].indexOfSelectedItem forKey:choices[i].key];
    [d setBool:self.overlay.state == NSControlStateValueOn forKey:kShowFps];
    [d setBool:self.dynres.state == NSControlStateValueOn forKey:kDynres];
    [d setBool:self.showAgain.state == NSControlStateValueOn forKey:kShowWindow];
    [d synchronize];
    [NSApp stopModalWithCode:NSModalResponseOK];
}
- (void)quit:(id)sender { (void)sender; [NSApp stopModalWithCode:NSModalResponseCancel]; }
- (void)windowWillClose:(NSNotification *)n { (void)n; [NSApp stopModalWithCode:NSModalResponseCancel]; }
@end

/* Returns NO when the player closed the window or chose Quit. */
static BOOL choose_settings(void) {
    choices_init();
    NSUserDefaults *d = NSUserDefaults.standardUserDefaults;
    const char *owner = getenv("TOTK_SLOT_OWNER"), *ui = getenv("TOTK_LAUNCHER");
    BOOL test = (owner && *owner && strcmp(owner, "user")) || (ui && !strcmp(ui, "0"));
    BOOL option = (NSEvent.modifierFlags & NSEventModifierFlagOption) != 0;
    BOOL show = !test && (option || [d objectForKey:kShowWindow] == nil || [d boolForKey:kShowWindow]);
    if (show) {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        TOTKLauncherWindow *w = [TOTKLauncherWindow new];
        [NSApp activateIgnoringOtherApps:YES];
        [w.window makeKeyAndOrderFront:nil];
        NSModalResponse r = [NSApp runModalForWindow:w.window];
        w.window.delegate = nil; [w.window orderOut:nil];
        if (r != NSModalResponseOK) return NO;
    }
    if (!test) apply_settings(d);
    return YES;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        NSString *root = [NSBundle.mainBundle.resourcePath stringByAppendingPathComponent:@"totk"];
        NSString *binary = [root stringByAppendingPathComponent:@"build/totk-native"];
        /* --check (build_app.py, once after packaging): only look that the game is there and exit. The first run of a new
           app is when macOS scans the whole bundle (minutes for 16 GB, with nothing on screen); doing it during the build
           makes the player's first start immediate. */
        if (argc > 1 && !strcmp(argv[1], "--check")) {
            int ok = access(binary.fileSystemRepresentation, X_OK) == 0;
            NSString *declared = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
            ok = ok && [declared isEqualToString:@TOTK_GAME_VERSION];
            printf("%s: game version %s\n", ok ? "ok" : "missing binary or version mismatch", TOTK_GAME_VERSION);
            return ok ? 0 : 1;
        }
        if (access(binary.fileSystemRepresentation, X_OK) != 0) {
            show_error(@"The game files are missing from this app. Build it again with build_app.py.");
            return 1;
        }
        NSString *home = NSHomeDirectory();
        NSString *data = [home stringByAppendingPathComponent:@"Library/Application Support/MacNativeGames/TOTK"];
        NSString *logs = [home stringByAppendingPathComponent:@"Library/Logs/MacNativeGames"];
        /* Folders the environment already names are kept (open --env TOTK_PROFILE_DIR=... runs a test on a save copy,
           TOTK_GAME_SLOT_DIR shares one game slot with another build of the game: one game at a time on the Mac). */
        NSString *(^env_or)(const char *, NSString *) = ^NSString *(const char *name, NSString *fallback) {
            const char *v = getenv(name); return v && *v ? @(v) : fallback; };
        NSString *profile = env_or("TOTK_PROFILE_DIR", [data stringByAppendingPathComponent:@"profile"]);
        NSString *slot = env_or("TOTK_GAME_SLOT_DIR", [data stringByAppendingPathComponent:@"game-slot"]);
        NSString *cache = env_or("TOTK_SHADER_CACHE", [data stringByAppendingPathComponent:[NSString stringWithFormat:@"shader-cache/rt-%s", DMSH_CHAIN]]);
        if (!make_dir(profile) || !make_dir(slot) || !make_dir(cache) || !make_dir(logs)) {
            show_error([NSString stringWithFormat:@"Cannot create %@.", data]);
            return 1;
        }
        pid_t running = running_game(slot);
        if (running) {
            [[NSRunningApplication runningApplicationWithProcessIdentifier:running] activateWithOptions:NSApplicationActivateAllWindows];
            return 0;
        }
        if (!choose_settings()) return 0;
#if defined(TOTK_GAME_V112) || defined(TOTK_GAME_V121) || defined(TOTK_GAME_V143)
        NSString *backup = [profile stringByAppendingFormat:@"-before-%s", TOTK_GAME_VERSION];
        NSFileManager *fm = NSFileManager.defaultManager;
        if (![fm fileExistsAtPath:backup]) {
            NSString *temporary = [backup stringByAppendingFormat:@".copy-%d", getpid()];
            NSError *error = nil;
            if (![fm copyItemAtPath:profile toPath:temporary error:&error] ||
                ![fm moveItemAtPath:temporary toPath:backup error:&error]) {
                [fm removeItemAtPath:temporary error:nil];
                show_error([@"Cannot back up saves before upgrading: " stringByAppendingString:error.localizedDescription ?: @"unknown error"]);
                return 1;
            }
        }
#endif
        if (chdir(root.fileSystemRepresentation) != 0) {   // the game reads its data relative to this folder
            show_error(@"Cannot open the game folder inside the app.");
            return 1;
        }
        /* The player's controller layout (runtime/controller_map.h), checked here: a bad line shows this alert instead of
           the game closing at start. */
        NSString *controls = env_or("TOTK_CONTROLS", [data stringByAppendingPathComponent:@"controls.txt"]);
        NSData *layout = [NSData dataWithContentsOfFile:controls];
        if (layout) {
            NSString *text = layout.length < 16384 ? [[NSString alloc] initWithData:layout encoding:NSUTF8StringEncoding] : nil;
            uint16_t map[CONTROLLER_BUTTONS]; uint8_t modes[CONTROLLER_BUTTONS]; controller_map_default(map, modes);
            const char *problem = layout.length < 16384 ? "not UTF-8 text" : "larger than 16 KB";
            int line = text ? controller_map_parse(text.UTF8String, map, modes, &problem) : 1;
            if (line) { show_error([NSString stringWithFormat:@"%@, line %d: %s", controls, line, problem]); return 1; }
        }
        setenv("TOTK_CONTROLS", controls.fileSystemRepresentation, 1);
        setenv("TOTK_PROFILE_DIR", profile.fileSystemRepresentation, 1);
        setenv("TOTK_SHADER_CACHE", cache.fileSystemRepresentation, 1);
        setenv("TOTK_GAME_SLOT_DIR", slot.fileSystemRepresentation, 1);
        setenv("TOTK_ROMFS_PROOF_DIR", data.fileSystemRepresentation, 1);   // the app bundle stays read-only
        setenv("TOTK_SHARED_FONTS", "extracted/firmware/shared-fonts", 1);
        /* Player mods (runtime/romfs.c): <data>/mods/<version>/manifest.tsv, when present. */
        setenv("TOTK_ROMFS_MODS", [data stringByAppendingPathComponent:@"mods/" TOTK_GAME_DIR].fileSystemRepresentation, 0);
        /* The game's language (runtime/services.c): the app's first preferred language, which also follows a per-app
           language (defaults write org.macnativegames.totk AppleLanguages -array pt-BR). TOTK_LANG still overrides it. */
        NSString *preferred = NSLocale.preferredLanguages.firstObject;
        if (preferred) setenv("TOTK_LOCALE", preferred.UTF8String, 1);
        setenv("TOTK_GPU_ALLOW_SUBMIT", "1", 1);
        setenv("TOTK_GPU_WIDEN", "1", 1);
        setenv("TOTK_GPU_BLOCKRT", "1", 1);
        setenv("TOTK_GPU_MIDCLEAR", "1", 1);
        /* 5000 MB was enough for the game's own sizes; a bigger scene or canvas needs more. The kernel panics seen during
           development came at about 15 GB resident, so 7000 MB keeps a wide margin. */
        setenv("TOTK_GPU_BUDGET_MB", "7000", 1);
        setenv("TOTK_SLOT_OWNER", "user", 0);
        setenv("TOTK_SLOT_PURPOSE", "player", 0);
        NSString *contrib = env_or("TOTK_SHADER_CONTRIB", [data stringByAppendingPathComponent:@"shader-list-contribution.txt"]);
        setenv("TOTK_SHADER_CONTRIB", contrib.fileSystemRepresentation, 1);
        contrib_reminder(contrib);
        unsetenv("TOTK_AUTOLOAD");   // the game starts at its title screen, as on the console
        /* runtime command channel (runtime/input.c): echo "shot ~/Desktop/shot.png" >> "<data>/input.txt" */
        { NSString *cmds = env_or("TOTK_INPUT_FILE", [data stringByAppendingPathComponent:@"input.txt"]);
          FILE *cf = fopen(cmds.fileSystemRepresentation, "w"); if (cf) fclose(cf);
          setenv("TOTK_INPUT_FILE", cmds.fileSystemRepresentation, 1); }

        NSString *log = [logs stringByAppendingPathComponent:@"totk.log"];
        [NSFileManager.defaultManager removeItemAtPath:[logs stringByAppendingPathComponent:@"totk.previous.log"] error:nil];
        [NSFileManager.defaultManager moveItemAtPath:log toPath:[logs stringByAppendingPathComponent:@"totk.previous.log"] error:nil];
        FILE *lf = fopen(log.fileSystemRepresentation, "w");
        if (lf) {
            dup2(fileno(lf), STDOUT_FILENO);
            dup2(fileno(lf), STDERR_FILENO);
            fclose(lf);
        }
        char *const arguments[] = {(char *)binary.fileSystemRepresentation, "rewritten/" TOTK_GAME_DIR, "boot", NULL};
        execv(arguments[0], arguments);
        fprintf(stderr, "[launcher] execv failed: %s\n", strerror(errno));
        show_error([NSString stringWithFormat:@"Starting the game failed. See %@.", log]);
        return 1;
    }
}
