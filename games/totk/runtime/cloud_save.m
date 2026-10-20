/* Save data shared through iCloud between the Mac and the iPad build: the player's game only (TOTK_SLOT_OWNER=user,
   TOTK_SLOT_PURPOSE=player), never a test run; TOTK_CLOUD_SAVE=0 turns it off.

   Where: the iPad build's iCloud container (its entitlements name it; TOTK_CLOUD_CONTAINER on the Mac, which reaches the
   same container under ~/Library/Mobile Documents), folder Documents/Saves. TOTK_CLOUD_SAVE_DIR names another folder.

   What: a unit is one top-level entry of the save data (slot_00 ... slot_05, option.sav, album, storage), taken whole
   because the game writes a slot as several files and only the set is consistent. A unit's version is the newest
   modification time of its files. A send copies the unit's files into the cloud folder, then writes its manifest
   (manifests/<unit>.json: version and a SHA-256 for each file) last. At start, a unit whose manifest is newer than the
   local copy is taken only when every file it lists has arrived with that hash; the local copy it replaces is kept in
   <profile>/cloud-backup/<time>/. Playing on both devices at the same moment is not supported: the later save wins. */
#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <TargetConditionals.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "cloud_save.h"

static NSString *save_dir, *profile_dir, *cloud_dir;
static dispatch_queue_t queue;
static _Atomic int push_queued;

static int wanted(void) {
    const char *off = getenv("TOTK_CLOUD_SAVE"), *owner = getenv("TOTK_SLOT_OWNER"), *purpose = getenv("TOTK_SLOT_PURPOSE");
    return !(off && !strcmp(off, "0")) && owner && !strcmp(owner, "user") && purpose && !strcmp(purpose, "player");
}
static NSString *find_cloud_dir(void) {
    const char *dir = getenv("TOTK_CLOUD_SAVE_DIR");
    if (dir && *dir) return @(dir);
#if TARGET_OS_IPHONE
    NSURL *c = [NSFileManager.defaultManager URLForUbiquityContainerIdentifier:nil];   // the first one the app is entitled to
    if (!c) { fprintf(stderr, "[totk] cloud save: off (no iCloud container: signed in to iCloud, app entitled?)\n"); return nil; }
    return [c.path stringByAppendingPathComponent:@"Documents/Saves"];
#else
    const char *id = getenv("TOTK_CLOUD_CONTAINER");
    if (!id || !*id) return nil;
    NSString *c = [NSHomeDirectory() stringByAppendingPathComponent:[@"Library/Mobile Documents" stringByAppendingPathComponent:
        [@(id) stringByReplacingOccurrencesOfString:@"." withString:@"~"]]];
    BOOL isDir = NO;
    if (![NSFileManager.defaultManager fileExistsAtPath:c isDirectory:&isDir] || !isDir) {
        fprintf(stderr, "[totk] cloud save: off (%s not here yet: the iPad build has not used it, or iCloud Drive is off)\n", c.fileSystemRepresentation);
        return nil;
    }
    return [c stringByAppendingPathComponent:@"Documents/Saves"];
#endif
}

/* ---------- files ---------- */
static NSString *sha256(NSString *path) {
    FILE *f = fopen(path.fileSystemRepresentation, "rb"); if (!f) return nil;
    CC_SHA256_CTX c; CC_SHA256_Init(&c); unsigned char buf[65536], md[CC_SHA256_DIGEST_LENGTH]; size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) CC_SHA256_Update(&c, buf, (CC_LONG)n);
    int bad = ferror(f); fclose(f); if (bad) return nil;
    CC_SHA256_Final(md, &c);
    NSMutableString *s = [NSMutableString stringWithCapacity:64]; for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [s appendFormat:@"%02x", md[i]];
    return s;
}
/* The unit's regular files, relative to root ("slot_05/progress.sav", or "option.sav" for a single-file unit). */
static NSArray<NSString *> *unit_files(NSString *root, NSString *unit) {
    NSFileManager *fm = NSFileManager.defaultManager; NSString *top = [root stringByAppendingPathComponent:unit]; BOOL isDir = NO;
    if (![fm fileExistsAtPath:top isDirectory:&isDir]) return @[];
    if (!isDir) return @[unit];
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *rel in [fm enumeratorAtPath:top]) {
        if ([rel.lastPathComponent hasPrefix:@"."]) continue;
        NSDictionary *a = [fm attributesOfItemAtPath:[top stringByAppendingPathComponent:rel] error:nil];
        if ([a.fileType isEqual:NSFileTypeRegular]) [out addObject:[unit stringByAppendingPathComponent:rel]];
    }
    return out;
}
static uint64_t mtime_ns(NSString *path) {
    struct stat st; if (stat(path.fileSystemRepresentation, &st)) return 0;
    return (uint64_t)st.st_mtimespec.tv_sec * 1000000000ull + (uint64_t)st.st_mtimespec.tv_nsec;
}
static uint64_t unit_version(NSString *root, NSString *unit) {
    uint64_t v = 0; for (NSString *rel in unit_files(root, unit)) { uint64_t t = mtime_ns([root stringByAppendingPathComponent:rel]); if (t > v) v = t; }
    return v;
}
static NSArray<NSString *> *units_in(NSString *root) {
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *name in [NSFileManager.defaultManager contentsOfDirectoryAtPath:root error:nil]) if (![name hasPrefix:@"."]) [out addObject:name];
    return out;
}
static NSString *manifest_path(NSString *unit) { return [cloud_dir stringByAppendingPathComponent:[NSString stringWithFormat:@"manifests/%@.json", unit]]; }
static NSDictionary *read_manifest(NSString *unit) {
    NSData *d = [NSData dataWithContentsOfFile:manifest_path(unit)]; if (!d) return nil;
    id m = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    return [m isKindOfClass:NSDictionary.class] && [m[@"version"] isKindOfClass:NSNumber.class] && [m[@"files"] isKindOfClass:NSDictionary.class] ? m : nil;
}
/* Copy through a coordinated replace, so iCloud sees one finished file and never a half-written one. */
static BOOL put_file(NSString *from, NSString *to) {
    NSFileManager *fm = NSFileManager.defaultManager;
    [fm createDirectoryAtPath:to.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil];
    __block BOOL ok = NO; NSError *err = nil;
    [[[NSFileCoordinator alloc] initWithFilePresenter:nil] coordinateWritingItemAtURL:[NSURL fileURLWithPath:to]
        options:NSFileCoordinatorWritingForReplacing error:&err byAccessor:^(NSURL *url) {
        NSString *tmp = [url.path stringByAppendingFormat:@".part-%d", getpid()];
        [fm removeItemAtPath:tmp error:nil];
        ok = [fm copyItemAtPath:from toPath:tmp error:nil] && rename(tmp.fileSystemRepresentation, url.fileSystemRepresentation) == 0;
        if (!ok) [fm removeItemAtPath:tmp error:nil];
    }];
    return ok && !err;
}
static BOOL put_data(NSData *data, NSString *to) {
    [NSFileManager.defaultManager createDirectoryAtPath:to.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil];
    __block BOOL ok = NO; NSError *err = nil;
    [[[NSFileCoordinator alloc] initWithFilePresenter:nil] coordinateWritingItemAtURL:[NSURL fileURLWithPath:to]
        options:NSFileCoordinatorWritingForReplacing error:&err byAccessor:^(NSURL *url) { ok = [data writeToURL:url atomically:YES]; }];
    return ok && !err;
}

/* ---------- send ---------- */
static void push_now(void) {
    for (NSString *unit in units_in(save_dir)) {
        uint64_t v = unit_version(save_dir, unit); NSDictionary *m = read_manifest(unit);
        if (!v || (m && [m[@"version"] unsignedLongLongValue] >= v)) continue;
        NSMutableDictionary *files = [NSMutableDictionary dictionary]; BOOL ok = YES;
        for (NSString *rel in unit_files(save_dir, unit)) {
            NSString *from = [save_dir stringByAppendingPathComponent:rel], *h = sha256(from);
            if (!h || !put_file(from, [cloud_dir stringByAppendingPathComponent:rel])) { ok = NO; break; }
            files[rel] = h;
        }
        /* A file the game wrote while this copy ran makes the unit newer than v: the next commit sends it again. */
        NSData *json = ok ? [NSJSONSerialization dataWithJSONObject:@{@"version": @(v), @"files": files, @"device": TARGET_OS_IPHONE ? @"iOS" : @"Mac"}
                                                            options:NSJSONWritingSortedKeys error:nil] : nil;
        if (json && put_data(json, manifest_path(unit))) fprintf(stderr, "[totk] cloud save: sent %s (%lu files)\n", unit.UTF8String, (unsigned long)files.count);
        else fprintf(stderr, "[totk] cloud save: could not send %s\n", unit.UTF8String);
    }
}
void runtime_cloud_save_push(void) {
    if (!cloud_dir || atomic_exchange(&push_queued, 1)) return;
    /* A second later, so the several commits of one save make one send. */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), queue, ^{ atomic_store(&push_queued, 0); @autoreleasepool { push_now(); } });
}
void runtime_cloud_save_flush(int timeout_ms) {
    if (!cloud_dir) return;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    dispatch_async(queue, ^{ @autoreleasepool { push_now(); } dispatch_semaphore_signal(done); });
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ms * NSEC_PER_MSEC)))
        fprintf(stderr, "[totk] cloud save: still sending after %d ms; it ends with the process\n", timeout_ms);
}

/* ---------- receive ---------- */
static void ask_download(NSString *path) {
    [NSFileManager.defaultManager startDownloadingUbiquitousItemAtURL:[NSURL fileURLWithPath:path] error:nil];
}
/* Every file of the manifest present with its hash; asks iCloud for the missing ones and waits until the deadline. */
static BOOL arrived(NSDictionary *files, uint64_t deadline) {
    for (;;) {
        BOOL all = YES;
        for (NSString *rel in files) {
            NSString *p = [cloud_dir stringByAppendingPathComponent:rel];
            if (![sha256(p) isEqual:files[rel]]) { all = NO; ask_download(p); }
        }
        if (all) return YES;
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC) > deadline) return NO;
        usleep(250000);
    }
}
static BOOL take_unit(NSString *unit, NSDictionary *m) {
    NSFileManager *fm = NSFileManager.defaultManager; NSDictionary *files = m[@"files"];
    uint64_t v = [m[@"version"] unsignedLongLongValue];
    NSString *incoming = [save_dir stringByAppendingPathComponent:@".cloud-incoming"];
    [fm removeItemAtPath:incoming error:nil];
    for (NSString *rel in files) {
        if ([rel hasPrefix:@"/"] || [rel.pathComponents containsObject:@".."] || ![rel.pathComponents.firstObject isEqual:unit]) return NO;
        NSString *to = [incoming stringByAppendingPathComponent:rel];
        [fm createDirectoryAtPath:to.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil];
        if (![fm copyItemAtPath:[cloud_dir stringByAppendingPathComponent:rel] toPath:to error:nil] || ![sha256(to) isEqual:files[rel]]) return NO;
        /* The version it had there, so this copy is not sent back as a newer one. */
        struct timespec t[2] = {{(time_t)(v / 1000000000ull), (long)(v % 1000000000ull)}, {(time_t)(v / 1000000000ull), (long)(v % 1000000000ull)}};
        utimensat(AT_FDCWD, to.fileSystemRepresentation, t, 0);
    }
    NSString *mine = [save_dir stringByAppendingPathComponent:unit];
    if ([fm fileExistsAtPath:mine]) {
        NSDateFormatter *f = [NSDateFormatter new]; f.dateFormat = @"yyyyMMdd-HHmmss"; f.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        NSString *keep = [profile_dir stringByAppendingPathComponent:[NSString stringWithFormat:@"cloud-backup/%@/%@", [f stringFromDate:NSDate.date], unit]];
        [fm createDirectoryAtPath:keep.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil];
        if (![fm moveItemAtPath:mine toPath:keep error:nil]) return NO;
    }
    BOOL ok = [fm moveItemAtPath:[incoming stringByAppendingPathComponent:unit] toPath:mine error:nil];
    [fm removeItemAtPath:incoming error:nil];
    return ok;
}
void runtime_cloud_save_pull(const char *profile, const char *save_root) {
    if (!wanted()) return;
    @autoreleasepool {
        cloud_dir = find_cloud_dir(); if (!cloud_dir) return;
        save_dir = @(save_root); profile_dir = @(profile);
        queue = dispatch_queue_create("totk.cloud-save", DISPATCH_QUEUE_SERIAL);
        [NSFileManager.defaultManager createDirectoryAtPath:[cloud_dir stringByAppendingPathComponent:@"manifests"] withIntermediateDirectories:YES attributes:nil error:nil];
        fprintf(stderr, "[totk] cloud save: %s\n", cloud_dir.fileSystemRepresentation);
        uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC) + 20000000000ull;   // at most 20 s of waiting at start
        NSString *mdir = [cloud_dir stringByAppendingPathComponent:@"manifests"];
        for (NSString *name in [NSFileManager.defaultManager contentsOfDirectoryAtPath:mdir error:nil])   // ".x.json.icloud": not here yet
            if ([name hasPrefix:@"."] && [name hasSuffix:@".icloud"]) ask_download([mdir stringByAppendingPathComponent:[name substringWithRange:NSMakeRange(1, name.length - 8)]]);
        for (NSString *name in [NSFileManager.defaultManager contentsOfDirectoryAtPath:mdir error:nil]) {
            if (![name hasSuffix:@".json"] || [name hasPrefix:@"."]) continue;
            NSString *unit = name.stringByDeletingPathExtension; NSDictionary *m = read_manifest(unit);
            if (!m || [m[@"version"] unsignedLongLongValue] <= unit_version(save_dir, unit)) continue;
            if (!arrived(m[@"files"], deadline)) { fprintf(stderr, "[totk] cloud save: %s from %s is not fully here yet; kept this device's copy\n", unit.UTF8String, [m[@"device"] description].UTF8String); continue; }
            if (take_unit(unit, m)) fprintf(stderr, "[totk] cloud save: took %s from %s\n", unit.UTF8String, [m[@"device"] description].UTF8String);
            else fprintf(stderr, "[totk] cloud save: could not take %s; kept this device's copy\n", unit.UTF8String);
        }
    }
    runtime_cloud_save_push();   // what this device has that the cloud lacks (first use, or saves made while offline)
}
