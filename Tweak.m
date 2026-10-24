@import UIKit;
#import <objc/runtime.h>
#import <objc/message.h>
#import <xpc/xpc.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "kexploit/kexploit_opa334.h"
#include "kexploit/kutils.h"
#include "sandbox_escape.h"
#include "apfs_own.h"

static const char *kCarrierBundlesPath = "/var/mobile/Library/Carrier Bundles";
static const NSInteger kCarrierBundlesLockButtonTag = 0x43424C4B;

static UIWindow *carrierBundlesKeyWindow(void) {
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (scene.activationState != UISceneActivationStateForegroundActive ||
            ![scene isKindOfClass:[UIWindowScene class]]) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window.isKeyWindow) return window;
        }
    }
    return nil;
}

static void showCarrierBundlesLockedAlert(mode_t mode) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = carrierBundlesKeyWindow();
        UIViewController *presenter = keyWindow.rootViewController;
        while (presenter.presentedViewController) presenter = presenter.presentedViewController;
        if (!presenter) {
            NSLog(@"[CarrierBundles] 0555 verified, but no presenter was available");
            return;
        }

        NSString *message = [NSString stringWithFormat:
            @"/var/mobile/Library/Carrier Bundles\n权限已改为 0%o，现在不可写入。\n\n点“完成并退出”结束本次运行。",
            mode & 0777];
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"Carrier Bundles 已锁定"
            message:message
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction
            actionWithTitle:@"完成并退出"
            style:UIAlertActionStyleDefault
            handler:^(__unused UIAlertAction *action) { _exit(0); }]];
        [presenter presentViewController:alert animated:YES completion:nil];
    });
}

static void showCarrierBundlesWritableAlert(mode_t mode) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = carrierBundlesKeyWindow();
        UIViewController *presenter = keyWindow.rootViewController;
        while (presenter.presentedViewController) presenter = presenter.presentedViewController;
        if (!presenter) {
            NSLog(@"[CarrierBundles] 0777 verified, but no presenter was available");
            return;
        }

        NSString *message = [NSString stringWithFormat:
            @"/var/mobile/Library/Carrier Bundles\n当前权限为 0%o，可以开始写入。\n\n全部完成后，请点右下角红色锁定按钮。",
            mode & 0777];
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"Carrier Bundles 已可写"
            message:message
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"开始操作"
            style:UIAlertActionStyleDefault handler:nil]];
        [presenter presentViewController:alert animated:YES completion:nil];
    });
}

static int setCarrierBundlesDirectoryPermissions(mode_t permissions) {
    struct stat before;
    if (stat(kCarrierBundlesPath, &before) != 0) {
        NSLog(@"[CarrierBundles] stat before failed: %s", strerror(errno));
        return -1;
    }
    if (!S_ISDIR(before.st_mode)) {
        NSLog(@"[CarrierBundles] target is not a directory (mode=0%o)", before.st_mode & 0xFFFF);
        return -1;
    }

    mode_t requested = (before.st_mode & S_IFMT) | (permissions & 0777);
    NSLog(@"[CarrierBundles] mode before=0%o requested=0%o",
          before.st_mode & 0xFFFF, requested & 0xFFFF);
    if (apfs_mod(kCarrierBundlesPath, requested) != 0) {
        NSLog(@"[CarrierBundles] apfs_mod failed");
        return -1;
    }

    struct stat after;
    if (stat(kCarrierBundlesPath, &after) != 0) {
        NSLog(@"[CarrierBundles] stat after failed: %s", strerror(errno));
        return -1;
    }
    if (!S_ISDIR(after.st_mode) || (after.st_mode & 0777) != (permissions & 0777)) {
        NSLog(@"[CarrierBundles] verification failed (mode=0%o)", after.st_mode & 0xFFFF);
        return -1;
    }

    NSLog(@"[CarrierBundles] directory mode changed successfully: 0%o -> 0%o",
          before.st_mode & 0xFFFF, after.st_mode & 0xFFFF);
    return 0;
}

int prepareCarrierBundlesDirectoryForWrite(void) {
    return setCarrierBundlesDirectoryPermissions(0777);
}

int lockCarrierBundlesDirectoryReadOnly(void) {
    int result = setCarrierBundlesDirectoryPermissions(0555);
    if (result == 0) {
        struct stat after;
        if (stat(kCarrierBundlesPath, &after) == 0) showCarrierBundlesLockedAlert(after.st_mode);
    }
    return result;
}

static void installCarrierBundlesLockButton(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = carrierBundlesKeyWindow();
        if (!window || [window viewWithTag:kCarrierBundlesLockButtonTag]) return;

        UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
        button.tag = kCarrierBundlesLockButtonTag;
        button.translatesAutoresizingMaskIntoConstraints = NO;
        button.backgroundColor = [UIColor colorWithRed:0.78 green:0.10 blue:0.12 alpha:0.94];
        button.tintColor = UIColor.whiteColor;
        button.contentEdgeInsets = UIEdgeInsetsMake(10, 14, 10, 14);
        [button setTitle:@"锁定 Carrier Bundles" forState:UIControlStateNormal];

        UIAction *action = [UIAction actionWithHandler:^(__unused UIAction *action) {
            button.enabled = NO;
            [button setTitle:@"正在锁定…" forState:UIControlStateNormal];
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                if (lockCarrierBundlesDirectoryReadOnly() != 0) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        button.enabled = YES;
                        [button setTitle:@"锁定失败，点此重试" forState:UIControlStateNormal];
                    });
                }
            });
        }];
        [button addAction:action forControlEvents:UIControlEventTouchUpInside];
        [window addSubview:button];
        UILayoutGuide *safe = window.safeAreaLayoutGuide;
        [NSLayoutConstraint activateConstraints:@[
            [button.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
            [button.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-12]
        ]];
        NSLog(@"[CarrierBundles] lock button installed");
    });
}

#pragma mark - Root Helper Hooks

static BOOL hook_isRootHelperAvailable(id self, SEL _cmd) {
    return NO;
}

static int hook_spawnRootHelper(id self, SEL _cmd) { return 0; }
static int hook_spawnRootHelperIfNeeds(id self, SEL _cmd) { return 0; }
static int hook_respawnRootHelper(id self, SEL _cmd) { return 0; }
static void hook_tryLoadFilzaHelper(id self, SEL _cmd) {}
static void hook_createHelperConnectionIfNeeds(id self, SEL _cmd) {}

static int hook_spawnRoot_args_pid(id self, SEL _cmd, id path, id args, int *pid) {
    if (pid) *pid = 0;
    return -1;
}

static id hook_sendObjectWithReplySync(id self, SEL _cmd, id msg) {
    return (id)xpc_null_create();
}

static id hook_sendObjectWithReplySync_fd(id self, SEL _cmd, id msg, int *fd) {
    if (fd) *fd = -1;
    return (id)xpc_null_create();
}

static id hook_sendObjectWithReplySync_fd_logintty(id self, SEL _cmd, id msg, int *fd, BOOL logintty) {
    if (fd) *fd = -1;
    return (id)xpc_null_create();
}

static void hook_sendObjectNoReply(id self, SEL _cmd, id msg) {}

static void hook_sendObjectWithReplyAsync(id self, SEL _cmd, id msg, id queue, id completion) {
    if (completion) { void (^block)(id) = completion; block(nil); }
}

#pragma mark - Zip/Unzip via minizip C API (linked in Filza binary)

// minizip C functions — statically linked in Filza, resolve via dlsym at runtime
#include <dlfcn.h>
typedef void* zipFile64;
typedef void* unzFile64;

// Function pointer types
static zipFile64 (*p_zipOpen64)(const char*, int);
static int (*p_zipOpenNewFileInZip64)(zipFile64, const char*, const void*, const void*, unsigned, const void*, unsigned, const char*, int, int, int);
static int (*p_zipWriteInFileInZip)(zipFile64, const void*, unsigned);
static int (*p_zipCloseFileInZip)(zipFile64);
static int (*p_zipClose)(zipFile64, const char*);
static unzFile64 (*p_unzOpen64)(const char*);
static int (*p_unzGoToFirstFile)(unzFile64);
static int (*p_unzGoToNextFile)(unzFile64);
static int (*p_unzGetCurrentFileInfo64)(unzFile64, void*, char*, unsigned long, void*, unsigned long, char*, unsigned long);
static int (*p_unzOpenCurrentFilePassword)(unzFile64, const char*);
static int (*p_unzReadCurrentFile)(unzFile64, void*, unsigned);
static int (*p_unzCloseCurrentFile)(unzFile64);
static int (*p_unzClose)(unzFile64);

static bool g_minizipLoaded = false;
static void loadMinizip(void) {
    if (g_minizipLoaded) return;
    // RTLD_DEFAULT searches all loaded images including Filza's statically linked minizip
    p_zipOpen64 = dlsym(RTLD_DEFAULT, "zipOpen64");
    p_zipOpenNewFileInZip64 = dlsym(RTLD_DEFAULT, "zipOpenNewFileInZip64");
    p_zipWriteInFileInZip = dlsym(RTLD_DEFAULT, "zipWriteInFileInZip");
    p_zipCloseFileInZip = dlsym(RTLD_DEFAULT, "zipCloseFileInZip");
    p_zipClose = dlsym(RTLD_DEFAULT, "zipClose");
    p_unzOpen64 = dlsym(RTLD_DEFAULT, "unzOpen64");
    p_unzGoToFirstFile = dlsym(RTLD_DEFAULT, "unzGoToFirstFile");
    p_unzGoToNextFile = dlsym(RTLD_DEFAULT, "unzGoToNextFile");
    p_unzGetCurrentFileInfo64 = dlsym(RTLD_DEFAULT, "unzGetCurrentFileInfo64");
    p_unzOpenCurrentFilePassword = dlsym(RTLD_DEFAULT, "unzOpenCurrentFilePassword");
    p_unzReadCurrentFile = dlsym(RTLD_DEFAULT, "unzReadCurrentFile");
    p_unzCloseCurrentFile = dlsym(RTLD_DEFAULT, "unzCloseCurrentFile");
    p_unzClose = dlsym(RTLD_DEFAULT, "unzClose");
    g_minizipLoaded = (p_zipOpen64 && p_unzOpen64);
    NSLog(@"[Tweak] minizip loaded: %d (zip=%p unz=%p)", g_minizipLoaded, p_zipOpen64, p_unzOpen64);
}

static IMP orig_ZipFiles = NULL, orig_unZipFile = NULL, orig_unZipFilePassword = NULL;

// Recursively add files to a zip archive using minizip C API
static void addFileToZip(zipFile64 zf, NSString *basePath, NSString *relativePath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *fullPath = [basePath stringByAppendingPathComponent:relativePath];
    BOOL isDir = NO;
    [fm fileExistsAtPath:fullPath isDirectory:&isDir];
    if (isDir) {
        // Add directory entry
        NSString *dirEntry = [relativePath stringByAppendingString:@"/"];
        p_zipOpenNewFileInZip64(zf, dirEntry.UTF8String, NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0);
        p_zipCloseFileInZip(zf);
        for (NSString *item in [fm contentsOfDirectoryAtPath:fullPath error:nil])
            addFileToZip(zf, basePath, [relativePath stringByAppendingPathComponent:item]);
    } else {
        NSData *data = [NSData dataWithContentsOfFile:fullPath];
        if (!data) return;
        // Z_DEFLATED=8, Z_DEFAULT_COMPRESSION=-1
        p_zipOpenNewFileInZip64(zf, relativePath.UTF8String, NULL, NULL, 0, NULL, 0, NULL, 8, -1, data.length > 0xFFFFFFFF);
        p_zipWriteInFileInZip(zf, data.bytes, (unsigned int)data.length);
        p_zipCloseFileInZip(zf);
    }
}

// Hook: -[Zipper ZipFiles:toFilePath:currentDirectory:]
static id hook_ZipFiles(id self, SEL _cmd, id files, id toFilePath, id currentDirectory) {
    @try {
        loadMinizip();
        if (!g_minizipLoaded) return orig_ZipFiles ? ((id(*)(id,SEL,id,id,id))orig_ZipFiles)(self, _cmd, files, toFilePath, currentDirectory) : nil;
        zipFile64 zf = p_zipOpen64(((NSString *)toFilePath).UTF8String, 0); // APPEND_STATUS_CREATE=0
        if (!zf) { NSLog(@"[Tweak] zipOpen64 failed"); return nil; }

        for (id fi in files) {
            NSString *fn = [fi performSelector:NSSelectorFromString(@"fileName")];
            if (fn) addFileToZip(zf, currentDirectory, fn);
        }
        p_zipClose(zf, NULL);

        // Return FileItem if zip was created (matching original behavior)
        if ([[NSFileManager defaultManager] fileExistsAtPath:toFilePath]) {
            Class FI = NSClassFromString(@"FileItem");
            if (FI) {
                id item = [[FI alloc] init];
                ((void(*)(id,SEL,id,id))objc_msgSend)(item, NSSelectorFromString(@"setFilePath:attribute:"), toFilePath, nil);
                return item;
            }
        }
        return nil;
    } @catch (NSException *e) { NSLog(@"[Tweak] Zip error: %@", e); return nil; }
}

// Hook: -[Zipper unZipFile:toPath:currentDirectory:outMessage:]
static id hook_unZipFile(id self, SEL _cmd, id zipPath, id toPath, id currentDir, id *outMsg) {
    @try {
        loadMinizip();
        if (!g_minizipLoaded) return orig_unZipFile ? ((id(*)(id,SEL,id,id,id,id*))orig_unZipFile)(self, _cmd, zipPath, toPath, currentDir, outMsg) : nil;
        // zipPath is a FileItem, get the actual path string
        NSString *zipPathStr = zipPath;
        if ([zipPath respondsToSelector:NSSelectorFromString(@"filePath")])
            zipPathStr = [zipPath performSelector:NSSelectorFromString(@"filePath")];

        unzFile64 uf = p_unzOpen64(((NSString *)zipPathStr).UTF8String);
        if (!uf) { if (outMsg) *outMsg = @"Failed to open zip"; return nil; }

        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *destPath = toPath;
        [fm createDirectoryAtPath:destPath withIntermediateDirectories:YES attributes:nil error:nil];

        char filename[512];
        uint8_t buf[32768];
        int ret = p_unzGoToFirstFile(uf);
        while (ret == 0) {
            p_unzGetCurrentFileInfo64(uf, NULL, filename, sizeof(filename), NULL, 0, NULL, 0);
            NSString *name = [NSString stringWithUTF8String:filename];
            NSString *fullPath = [destPath stringByAppendingPathComponent:name];

            if ([name hasSuffix:@"/"]) {
                [fm createDirectoryAtPath:fullPath withIntermediateDirectories:YES attributes:nil error:nil];
            } else {
                [fm createDirectoryAtPath:[fullPath stringByDeletingLastPathComponent]
                  withIntermediateDirectories:YES attributes:nil error:nil];

                if (p_unzOpenCurrentFilePassword(uf, NULL) == 0) {
                    NSMutableData *fileData = [NSMutableData data];
                    int bytesRead;
                    while ((bytesRead = p_unzReadCurrentFile(uf, buf, sizeof(buf))) > 0)
                        [fileData appendBytes:buf length:bytesRead];
                    p_unzCloseCurrentFile(uf);
                    [fileData writeToFile:fullPath atomically:YES];
                }
            }
            ret = p_unzGoToNextFile(uf);
        }
        p_unzClose(uf);

        if (outMsg) *outMsg = @"OK";

        // Return array of extracted FileItems (matching original behavior)
        NSArray *contents = [fm contentsOfDirectoryAtPath:destPath error:nil];
        if (contents.count > 0) {
            Class FI = NSClassFromString(@"FileItem");
            if (FI) {
                id item = [[FI alloc] init];
                ((void(*)(id,SEL,id,id))objc_msgSend)(item, NSSelectorFromString(@"setFilePath:attribute:"), destPath, nil);
                return @[item];
            }
        }
        return nil;
    } @catch (NSException *e) { NSLog(@"[Tweak] Unzip error: %@", e); if (outMsg) *outMsg = [e reason]; return nil; }
}

// Hook: -[Zipper unZipFile:toPath:currentDirectory:withPassword:outMessage:]
static id hook_unZipFilePassword(id self, SEL _cmd, id zipPath, id toPath, id currentDir, id password, id *outMsg) {
    return hook_unZipFile(self, @selector(unZipFile:toPath:currentDirectory:outMessage:), zipPath, toPath, currentDir, outMsg);
}

#pragma mark - Apps Manager Fix

// Full Apps Manager fix for sandbox-escaped devices.
// LSApplicationProxy properties (localizedName, iconsDictionary, dataContainerURL,
// staticDiskUsage, etc.) return nil without entitlements.
// Fix: Hook setAppProxy: to populate from Info.plist + filesystem directly.
// Hook calculateDiskUsage to walk bundle dirs. Hook tap to use bundle path fallback.

@interface LSApplicationProxy : NSObject
+ (id)applicationProxyForIdentifier:(NSString *)bundleId;
- (NSString *)applicationIdentifier;
- (NSURL *)bundleURL;
- (NSURL *)dataContainerURL;
- (NSString *)localizedName;
- (NSString *)bundleVersion;
- (NSString *)shortVersionString;
- (NSString *)applicationType;
- (NSDictionary *)iconsDictionary;
- (NSNumber *)staticDiskUsage;
- (NSNumber *)dynamicDiskUsage;
@end

@interface LSApplicationWorkspace : NSObject
+ (id)defaultWorkspace;
- (NSArray *)allApplications;
@end

// --- Helper: find app bundle path from bundleId ---
static NSString *findBundlePath(NSString *bundleId) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *appsDir = @"/var/containers/Bundle/Application";
    for (NSString *uuid in [fm contentsOfDirectoryAtPath:appsDir error:nil]) {
        NSString *uuidPath = [appsDir stringByAppendingPathComponent:uuid];
        for (NSString *item in [fm contentsOfDirectoryAtPath:uuidPath error:nil]) {
            if (![item hasSuffix:@".app"]) continue;
            NSString *appPath = [uuidPath stringByAppendingPathComponent:item];
            NSString *plist = [appPath stringByAppendingPathComponent:@"Info.plist"];
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
            if ([info[@"CFBundleIdentifier"] isEqualToString:bundleId]) return appPath;
        }
    }
    // System apps
    for (NSString *item in [fm contentsOfDirectoryAtPath:@"/Applications" error:nil]) {
        if (![item hasSuffix:@".app"]) continue;
        NSString *appPath = [@"/Applications" stringByAppendingPathComponent:item];
        NSString *plist = [appPath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        if ([info[@"CFBundleIdentifier"] isEqualToString:bundleId]) return appPath;
    }
    return nil;
}

// --- Helper: find data container path ---
static NSString *findDataContainer(NSString *bundleId) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dataDir = @"/var/mobile/Containers/Data/Application";
    for (NSString *uuid in [fm contentsOfDirectoryAtPath:dataDir error:nil]) {
        NSString *uuidPath = [dataDir stringByAppendingPathComponent:uuid];
        NSString *metaPlist = [uuidPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPlist];
        if ([meta[@"MCMMetadataIdentifier"] isEqualToString:bundleId]) return uuidPath;
    }
    return nil;
}

// --- Helper: find best icon in bundle ---
static NSString *findIconPath(NSString *bundlePath, NSDictionary *infoPlist) {
    NSFileManager *fm = [NSFileManager defaultManager];
    // Try CFBundleIcons -> CFBundlePrimaryIcon -> CFBundleIconFiles
    NSDictionary *icons = infoPlist[@"CFBundleIcons"];
    NSDictionary *primary = icons[@"CFBundlePrimaryIcon"];
    NSArray *iconFiles = primary[@"CFBundleIconFiles"];
    if (!iconFiles) iconFiles = infoPlist[@"CFBundleIconFiles"];

    NSString *bestIcon = nil;
    unsigned long long bestSize = 0;
    if (iconFiles.count > 0) {
        for (NSString *iconName in iconFiles) {
            // Try exact name and @2x/@3x variants
            NSArray *variants = @[
                iconName,
                [iconName stringByAppendingString:@"@2x.png"],
                [iconName stringByAppendingString:@"@3x.png"],
                [iconName stringByAppendingString:@"@2x~iphone.png"],
                [iconName stringByAppendingString:@"@3x~iphone.png"],
                [NSString stringWithFormat:@"%@.png", iconName],
            ];
            for (NSString *v in variants) {
                NSString *full = [bundlePath stringByAppendingPathComponent:v];
                NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
                unsigned long long sz = [attrs fileSize];
                if (sz > bestSize) { bestSize = sz; bestIcon = full; }
            }
        }
    }

    // Fallback: scan for Icon*.png / AppIcon*.png
    if (!bestIcon) {
        for (NSString *file in [fm contentsOfDirectoryAtPath:bundlePath error:nil]) {
            if (([file hasPrefix:@"Icon"] || [file hasPrefix:@"icon"] || [file hasPrefix:@"AppIcon"])
                && [file hasSuffix:@".png"]) {
                NSString *full = [bundlePath stringByAppendingPathComponent:file];
                NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
                unsigned long long sz = [attrs fileSize];
                if (sz > bestSize) { bestSize = sz; bestIcon = full; }
            }
        }
    }
    return bestIcon;
}

// --- Hook: allApplications fallback ---
static IMP orig_allApplications = NULL;
static id hook_allApplications(id self, SEL _cmd) {
    NSArray *origResult = ((id(*)(id,SEL))orig_allApplications)(self, _cmd);
    if (origResult && origResult.count > 0) return origResult;

    NSMutableArray *apps = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    void (^scanDir)(NSString *) = ^(NSString *dir) {
        for (NSString *uuid in [fm contentsOfDirectoryAtPath:dir error:nil]) {
            NSString *uuidPath = [dir stringByAppendingPathComponent:uuid];
            for (NSString *item in [fm contentsOfDirectoryAtPath:uuidPath error:nil]) {
                if (![item hasSuffix:@".app"]) continue;
                NSString *plist = [[uuidPath stringByAppendingPathComponent:item] stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
                NSString *bid = info[@"CFBundleIdentifier"];
                if (bid) {
                    id proxy = [NSClassFromString(@"LSApplicationProxy") applicationProxyForIdentifier:bid];
                    if (proxy) [apps addObject:proxy];
                }
            }
        }
    };
    scanDir(@"/var/containers/Bundle/Application");
    // System apps (flat structure)
    for (NSString *item in [fm contentsOfDirectoryAtPath:@"/Applications" error:nil]) {
        if (![item hasSuffix:@".app"]) continue;
        NSString *plist = [[@"/Applications" stringByAppendingPathComponent:item] stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *bid = info[@"CFBundleIdentifier"];
        if (bid) {
            id proxy = [NSClassFromString(@"LSApplicationProxy") applicationProxyForIdentifier:bid];
            if (proxy) [apps addObject:proxy];
        }
    }
    NSLog(@"[Tweak] Apps Manager: found %lu apps via filesystem", (unsigned long)apps.count);
    return apps;
}

// --- Hook: setAppProxy: — populate name, icon, paths from filesystem ---
static IMP orig_setAppProxy = NULL;
static void hook_setAppProxy(id self, SEL _cmd, id proxy) {
    // Call original first
    ((void(*)(id,SEL,id))orig_setAppProxy)(self, _cmd, proxy);

    NSString *bundleId = [self performSelector:NSSelectorFromString(@"bundleId")];
    if (!bundleId) return;

    NSString *bundlePath = nil;
    NSString *currentFilePath = [self performSelector:NSSelectorFromString(@"filePath")];

    // Fix filePath if missing or inaccessible
    if (!currentFilePath || currentFilePath.length == 0) {
        NSURL *bundleURL = [proxy bundleURL];
        if (bundleURL) bundlePath = [bundleURL path];
        if (!bundlePath) bundlePath = findBundlePath(bundleId);
        if (bundlePath) {
            ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setFilePath:"), bundlePath);
        }
    } else {
        bundlePath = currentFilePath;
    }

    // Fix display name — always prefer Info.plist name over proxy
    if (bundlePath) {
        NSString *plist = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *name = info[@"CFBundleDisplayName"];
        if (!name) name = info[@"CFBundleName"];
        if (!name) name = [proxy localizedName];
        if (!name) name = bundleId;
        ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setAFileName:"), name);
    }

    // Fix icon path
    NSString *iconPath = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"iconPath"));
    if (!iconPath && bundlePath) {
        NSString *plist = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *found = findIconPath(bundlePath, info);
        if (found) {
            ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setIconPath:"), found);
        }
    }

    // Fix document path
    NSString *docPath = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"documentPath"));
    if (!docPath) {
        NSURL *dataURL = [proxy dataContainerURL];
        if (dataURL) docPath = [dataURL path];
        if (!docPath) docPath = findDataContainer(bundleId);
        if (docPath) {
            ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setDocumentPath:"), docPath);
        }
    }

    // Fix version
    NSString *ver = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"version"));
    if (!ver || ver.length == 0) {
        ver = [proxy bundleVersion];
        if (!ver && bundlePath) {
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
            ver = info[@"CFBundleShortVersionString"];
            if (!ver) ver = info[@"CFBundleVersion"];
        }
        if (ver) ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setVersion:"), ver);
    }
}


// --- Hook: browserView:didSelectItemAtIndexPath: — fallback to bundle path ---
static IMP orig_didSelectItem = NULL;
static void hook_didSelectItem(id self, SEL _cmd, id browserView, id indexPath) {
    // Get the selected item
    id fileList = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"fileList"));
    NSUInteger row = ((NSUInteger(*)(id,SEL))objc_msgSend)(indexPath, @selector(row));
    id item = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(fileList, NSSelectorFromString(@"objectAtIndex:"), row);

    NSString *docPath = ((id(*)(id,SEL))objc_msgSend)(item, NSSelectorFromString(@"documentPath"));
    NSString *bundlePath = [item performSelector:NSSelectorFromString(@"filePath")];

    // If documentPath is nil but bundlePath exists, set documentPath to bundlePath
    // so the original handler can navigate there instead of showing error
    if (!docPath && bundlePath) {
        ((void(*)(id,SEL,id))objc_msgSend)(item, NSSelectorFromString(@"setDocumentPath:"), bundlePath);
    }

    // Call original
    ((void(*)(id,SEL,id,id))orig_didSelectItem)(self, _cmd, browserView, indexPath);
}

#pragma mark - License / Integrity Bypass

// Suppress "Main binary was modified" and "Not activated" alerts.
// +[TGAlertController showAlertWithTitle:text:cancelButton:otherButtons:completion:]
// checks the text parameter; if it's the integrity/activation alert, swallow it.
static IMP orig_showAlert = NULL;
static id hook_showAlertWithTitle(id self, SEL _cmd, id title, id text, id cancelButton, id otherButtons, id completion) {
    NSString *textStr = text;
    if ([textStr isKindOfClass:[NSString class]]) {
        if ([textStr containsString:@"binary was modified"] ||
            [textStr containsString:@"reinstall Filza"]) {
            NSLog(@"[Tweak] Suppressed integrity alert");
            return nil;
        }
    }
    // Pass through all other alerts
    return ((id(*)(id,SEL,id,id,id,id,id))orig_showAlert)(self, _cmd, title, text, cancelButton, otherButtons, completion);
}

// Suppress activation nag: -[NewActivationViewController viewDidLoad]
// Just dismiss the VC immediately so the user never sees it.
static IMP orig_activationViewDidLoad = NULL;
static void hook_activationViewDidLoad(id self, SEL _cmd) {
    // Call original to set up the VC, then immediately dismiss
    ((void(*)(id,SEL))orig_activationViewDidLoad)(self, _cmd);
    dispatch_async(dispatch_get_main_queue(), ^{
        ((void(*)(id,SEL,BOOL,id))objc_msgSend)(self,
            NSSelectorFromString(@"dismissViewControllerAnimated:completion:"), NO, nil);
    });
    NSLog(@"[Tweak] Suppressed activation nag");
}

#pragma mark - Auto-repair protected roots on navigate

// App bundles keep the original lazy ownership repair. Carrier Bundles is
// handled separately: navigation may start the delayed exploit, but it never
// recursively changes ownership or permissions.

static NSString * const kCarrierBundlesRoot = @"/var/mobile/Library/Carrier Bundles";

static NSMutableSet<NSString *> *g_chowned_roots = nil;
static dispatch_queue_t g_chown_queue = NULL;
static volatile BOOL g_sandbox_escaped = NO;
static volatile BOOL g_exploit_started = NO;

static void scheduleExploitOnce(void);

static NSString *normalized_path(NSString *path) {
    NSString *normalized = [path stringByStandardizingPath];
    while (normalized.length > 1 && [normalized hasSuffix:@"/"]) {
        normalized = [normalized substringToIndex:normalized.length - 1];
    }
    return normalized;
}

static BOOL path_is_at_or_inside_root(NSString *path, NSString *root) {
    if ([path isEqualToString:root]) return YES;
    return [path hasPrefix:[root stringByAppendingString:@"/"]];
}

// Returns the .app root path for any path inside a Bundle/Application/<UUID>/<Name>.app,
// or nil if the path isn't inside one.
static NSString *app_root_for_path(NSString *path) {
    if (![path hasPrefix:@"/var/containers/Bundle/Application/"]) return nil;
    NSArray<NSString *> *comps = [path pathComponents];
    for (NSUInteger i = 0; i < comps.count; i++) {
        if ([comps[i] hasSuffix:@".app"]) {
            return [NSString pathWithComponents:
                [comps subarrayWithRange:NSMakeRange(0, i + 1)]];
        }
    }
    return nil;
}

static NSString *protected_root_for_path(NSString *path) {
    NSString *normalized = normalized_path(path);
    if (path_is_at_or_inside_root(normalized, kCarrierBundlesRoot)) {
        return kCarrierBundlesRoot;
    }
    return app_root_for_path(normalized);
}

static void ensure_protected_root_repaired_async(NSString *path) {
    NSString *root = protected_root_for_path(path);
    if (!root) return;
    if ([root isEqualToString:kCarrierBundlesRoot]) {
        if (!g_sandbox_escaped) scheduleExploitOnce();
        return;
    }
    if (!g_sandbox_escaped) {
        NSLog(@"[Tweak] auto-repair skipped before sandbox escape: %@", root);
        return;
    }

    @synchronized(g_chowned_roots) {
        if ([g_chowned_roots containsObject:root]) return;
        [g_chowned_roots addObject:root];
    }

    dispatch_async(g_chown_queue, ^{
        NSLog(@"[Tweak] auto-chown: %@", root);
        apfs_own_tree([root UTF8String], 501, 501);
    });
}

static IMP orig_contentsOfDirectory = NULL;
static id hook_contentsOfDirectory(id self, SEL _cmd, id path, NSError **error) {
    if ([path isKindOfClass:[NSString class]]) {
        ensure_protected_root_repaired_async((NSString *)path);
    }
    return ((id(*)(id,SEL,id,NSError**))orig_contentsOfDirectory)(self, _cmd, path, error);
}

#pragma mark - Hook Installation

static void installHooks(void) {
    if (!g_chowned_roots) g_chowned_roots = [NSMutableSet new];
    if (!g_chown_queue) g_chown_queue = dispatch_queue_create("com.filza.autochown", DISPATCH_QUEUE_SERIAL);

    Class rfm = NSClassFromString(@"TGRootFileManager");
    if (rfm) {
        Class meta = object_getClass(rfm);
        class_replaceMethod(meta, NSSelectorFromString(@"isRootHelperAvailable"), (IMP)hook_isRootHelperAvailable, "B@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"spawnRootHelper"), (IMP)hook_spawnRootHelper, "i@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"spawnRootHelperIfNeeds"), (IMP)hook_spawnRootHelperIfNeeds, "i@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"respawnRootHelper"), (IMP)hook_respawnRootHelper, "i@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"tryLoadFilzaHelper"), (IMP)hook_tryLoadFilzaHelper, "v@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"createHelperConnectionIfNeeds"), (IMP)hook_createHelperConnectionIfNeeds, "v@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"spawnRoot:args:pid:"), (IMP)hook_spawnRoot_args_pid, "i@:@@^i");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplySync:"), (IMP)hook_sendObjectWithReplySync, "@@:@");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplySync:fileDescriptor:"), (IMP)hook_sendObjectWithReplySync_fd, "@@:@^i");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplySync:fileDescriptor:logintty:"), (IMP)hook_sendObjectWithReplySync_fd_logintty, "@@:@^iB");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectNoReply:"), (IMP)hook_sendObjectNoReply, "v@:@");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplyAsync:queue:completion:"), (IMP)hook_sendObjectWithReplyAsync, "v@:@@?");

        // Auto-repair protected roots on first listing of anything inside them.
        Method cod = class_getInstanceMethod(rfm, NSSelectorFromString(@"contentsOfDirectoryAtPath:error:"));
        if (cod) {
            orig_contentsOfDirectory = method_getImplementation(cod);
            method_setImplementation(cod, (IMP)hook_contentsOfDirectory);
        }
    }
    Class zipper = NSClassFromString(@"Zipper");
    if (zipper) {
        Method m;
        m = class_getInstanceMethod(zipper, NSSelectorFromString(@"ZipFiles:toFilePath:currentDirectory:"));
        if (m) { orig_ZipFiles = method_getImplementation(m); method_setImplementation(m, (IMP)hook_ZipFiles); }
        m = class_getInstanceMethod(zipper, NSSelectorFromString(@"unZipFile:toPath:currentDirectory:outMessage:"));
        if (m) { orig_unZipFile = method_getImplementation(m); method_setImplementation(m, (IMP)hook_unZipFile); }
        m = class_getInstanceMethod(zipper, NSSelectorFromString(@"unZipFile:toPath:currentDirectory:withPassword:outMessage:"));
        if (m) { orig_unZipFilePassword = method_getImplementation(m); method_setImplementation(m, (IMP)hook_unZipFilePassword); }
    }

    // License/integrity bypass
    Class alertCtrl = NSClassFromString(@"TGAlertController");
    if (alertCtrl) {
        Class alertMeta = object_getClass(alertCtrl);
        Method m = class_getClassMethod(alertCtrl, NSSelectorFromString(@"showAlertWithTitle:text:cancelButton:otherButtons:completion:"));
        if (m) {
            orig_showAlert = method_getImplementation(m);
            class_replaceMethod(alertMeta, NSSelectorFromString(@"showAlertWithTitle:text:cancelButton:otherButtons:completion:"),
                (IMP)hook_showAlertWithTitle, "@@:@@@@@");
        }
    }
    Class activationVC = NSClassFromString(@"NewActivationViewController");
    if (activationVC) {
        Method m = class_getInstanceMethod(activationVC, @selector(viewDidLoad));
        if (m) {
            orig_activationViewDidLoad = method_getImplementation(m);
            method_setImplementation(m, (IMP)hook_activationViewDidLoad);
        }
    }

    // Apps Manager fixes
    Class lsWorkspace = NSClassFromString(@"LSApplicationWorkspace");
    if (lsWorkspace) {
        Method m = class_getInstanceMethod(lsWorkspace, NSSelectorFromString(@"allApplications"));
        if (m) { orig_allApplications = method_getImplementation(m); method_setImplementation(m, (IMP)hook_allApplications); }
    }
    Class appItem = NSClassFromString(@"ApplicationItem");
    if (appItem) {
        Method m;
        m = class_getInstanceMethod(appItem, NSSelectorFromString(@"setAppProxy:"));
        if (m) { orig_setAppProxy = method_getImplementation(m); method_setImplementation(m, (IMP)hook_setAppProxy); }
    }
    Class appsVC = NSClassFromString(@"TGApplicationsViewController");
    if (appsVC) {
        Method m = class_getInstanceMethod(appsVC, NSSelectorFromString(@"browserView:didSelectItemAtIndexPath:"));
        if (m) { orig_didSelectItem = method_getImplementation(m); method_setImplementation(m, (IMP)hook_didSelectItem); }
    }

    NSLog(@"[Tweak] All hooks installed");
}

#pragma mark - Exploit (silent, background)

static void runExploit(void) {
    NSLog(@"[Tweak] Running kexploit...");
    int kret = kexploit_opa334();
    if (kret != 0) {
        NSLog(@"[Tweak] kexploit failed: %d", kret);
        return;
    }

    NSLog(@"[Tweak] kexploit succeeded, escaping sandbox...");
    uint64_t self_proc_addr = proc_self();
    int sret = sandbox_escape(self_proc_addr);
    NSLog(@"[Tweak] sandbox_escape returned %d", sret);
    if (sret != 0) {
        NSLog(@"[CarrierBundles] skipped because sandbox escape failed");
        return;
    }
    g_sandbox_escaped = YES;

    // Keep the original Carrier Bundles repair. Changing only the directory
    // mode leaves existing root-owned children inaccessible to mobile.
    long repaired = apfs_mobile_rw_tree(kCarrierBundlesPath, 501, 501);
    NSLog(@"[CarrierBundles] original tree repair processed %ld entries", repaired);
    if (repaired <= 0) {
        NSLog(@"[CarrierBundles] tree repair failed; lock control was not installed");
        return;
    }

    if (prepareCarrierBundlesDirectoryForWrite() != 0) {
        NSLog(@"[CarrierBundles] could not prepare 0777; lock control was not installed");
        return;
    }

    struct stat writableState;
    if (stat(kCarrierBundlesPath, &writableState) == 0) {
        installCarrierBundlesLockButton();
        showCarrierBundlesWritableAlert(writableState.st_mode);
    }

    // For root-owned paths that fail DAC, use apfs_own(path, 501, 501) to
    // flip on-disk ownership to mobile before opening. Example:
    //     if (apfs_own("/var/root/.somefile", 501, 501) == 0) { ... }

    // App bundle ownership repair still runs lazily. Carrier Bundles was
    // repaired once above before the verified 0777/0555 operations.
}

static void scheduleExploitOnce(void) {
    @synchronized([NSProcessInfo processInfo]) {
        if (g_exploit_started) return;
        g_exploit_started = YES;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        runExploit();
    });
}

static BOOL systemVersionAtLeast(NSString *minimum) {
    NSString *version = [[UIDevice currentDevice] systemVersion];
    return [version compare:minimum options:NSNumericSearch] != NSOrderedAscending;
}

#pragma mark - Entry Point

__attribute__((constructor)) void TweakInit(void) {
    installHooks();

    // This probe is informational. apfs_mod still needs kernel read/write.
    int fd = open("/var/mobile/.sbx_check", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        close(fd); unlink("/var/mobile/.sbx_check");
        NSLog(@"[Tweak] /var/mobile is writable; kernel access is still required for apfs_mod");
    }

    // Run exploit AFTER app finishes launching (UIKit must be ready for offsets_init
    // which uses UIDevice.currentDevice.systemVersion)
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:nil usingBlock:^(NSNotification *note) {
        if (systemVersionAtLeast(@"18.6")) {
            NSLog(@"[Tweak] iOS 18.6+ detected; delaying kexploit until Carrier Bundles access");
            return;
        }
        scheduleExploitOnce();
    }];
}

