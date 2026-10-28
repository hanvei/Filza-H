@import UIKit;
#import <objc/runtime.h>
#import <objc/message.h>
#import <xpc/xpc.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "kexploit/kexploit_opa334.h"
#include "kexploit/kutils.h"
#include "sandbox_escape.h"
#include "apfs_own.h"
#include "TaskRop/RemoteCall.h"

static const char *kCarrierBundlesPath = "/var/mobile/Library/Carrier Bundles";

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

        mode_t permissions = mode & 0777;
        NSString *state = permissions == 0555 ? @"现在不可写入。" :
            (permissions == 0777 ? @"现在可以写入。" : @"权限修改已经生效。");
        NSString *message = [NSString stringWithFormat:
            @"/var/mobile/Library/Carrier Bundles\n权限已保存为 0%o，%@",
            permissions, state];
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"Carrier Bundles 保存成功"
            message:message
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction
            actionWithTitle:@"确定"
            style:UIAlertActionStyleDefault
            handler:nil]];
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
            @"/var/mobile/Library/Carrier Bundles\n当前权限为 0%o，可以开始写入。\n\n完成后，请在 Filza 的权限编辑界面手动保存为 0555。",
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

static IMP orig_setAttributesOfItem = NULL;

// LockIPCC stages the path in launchd and asks launchd to perform chmod.
//
// Experiment switch: 0 = never hijack launchd in this build. The launchd
// RemoteCall is what kills launchd (and reboots the device) on iOS 18.6/A18,
// so we apply the permission change ourselves instead: first a real chmod()
// syscall (Filza is root and unsandboxed after the escape), then a direct
// apfs_fsnode.mode write through the kernel RW primitive.
#define RC_ENABLE_LAUNCHD_CHMOD 0

static BOOL g_launchd_remote_call_ready = NO;

static BOOL remote_chmod_via_launchd(const char *path, mode_t mode);

static BOOL initialize_launchd_remote_call(void) {
#if !RC_ENABLE_LAUNCHD_CHMOD
    NSLog(@"[CarrierBundles] launchd RemoteCall disabled in this build (direct chmod mode)");
    return NO;
#endif
    @synchronized([NSProcessInfo processInfo]) {
        if (g_launchd_remote_call_ready && g_RC_trojanMem && g_RC_trojanMem != UINT64_MAX) {
            return YES;
        }
        if (!g_sandbox_escaped) {
            NSLog(@"[CarrierBundles] RemoteCall initialization skipped before sandbox escape");
            return NO;
        }

        NSLog(@"[CarrierBundles] initializing launchd RemoteCall after exploit setup");
        int result = init_remote_call("launchd", false);
        if (result != 0 || !g_RC_trojanMem || g_RC_trojanMem == UINT64_MAX) {
            NSLog(@"[CarrierBundles] launchd RemoteCall initialization failed safely: result=%d memory=0x%llx",
                  result, (unsigned long long)g_RC_trojanMem);
            return NO;
        }

        g_launchd_remote_call_ready = YES;
        NSLog(@"[CarrierBundles] launchd RemoteCall ready");
        return YES;
    }
}

static BOOL remote_chmod_via_launchd(const char *path, mode_t mode) {
    if (!path || !path[0]) return NO;

    @synchronized([NSProcessInfo processInfo]) {
        if (!g_launchd_remote_call_ready || !g_RC_trojanMem || g_RC_trojanMem == UINT64_MAX) {
            NSLog(@"[CarrierBundles] chmod refused: launchd RemoteCall is not ready");
            return NO;
        }

        size_t length = strlen(path) + 1;
        if (length > 0x1000 || !remote_write(g_RC_trojanMem, path, length)) {
            NSLog(@"[CarrierBundles] could not stage path in launchd");
            return NO;
        }

        uint64_t result = do_remote_call_stable(1000, "chmod",
            g_RC_trojanMem, (uint64_t)(mode & 07777),
            0, 0, 0, 0, 0, 0);
        if ((int64_t)result != 0) {
            NSLog(@"[CarrierBundles] launchd chmod failed for %s: result=%lld",
                  path, (long long)result);
            return NO;
        }
        return YES;
    }
}

// Apply a permission change without touching launchd.
// Step 1: plain chmod() syscall. After sandbox_escape Filza runs as root with
//         the sandbox torn down, so this may simply work (this is what makes
//         the change persist through a reboot).
// Step 2: fall back to writing apfs_fsnode.mode directly via the kernel RW
//         primitive (works even when the VFS refuses, but is memory-only).
static BOOL carrier_apply_permissions(const char *cpath, mode_t mode) {
    errno = 0;
    int rc = chmod(cpath, mode & 07777);
    int chmodErrno = errno;
    NSLog(@"[CarrierBundles] direct chmod: %s -> 0%o rc=%d errno=%d",
          cpath, mode & 07777, rc, chmodErrno);
    if (rc == 0) return YES;

    errno = 0;
    int arc = apfs_mod(cpath, mode & 07777);
    int apfsErrno = errno;
    NSLog(@"[CarrierBundles] apfs_mod fallback: %s -> 0%o rc=%d errno=%d",
          cpath, mode & 07777, arc, apfsErrno);
    if (arc == 0) return YES;

#if RC_ENABLE_LAUNCHD_CHMOD
    return remote_chmod_via_launchd(cpath, mode);
#else
    return NO;
#endif
}

static void reportCarrierPermissionIfSaved(NSString *path, mode_t requestedMode) {
    if (![normalized_path(path) isEqualToString:kCarrierBundlesRoot]) return;

    struct stat after;
    if (stat(kCarrierBundlesPath, &after) == 0 &&
        S_ISDIR(after.st_mode) &&
        (after.st_mode & 07777) == (requestedMode & 07777)) {
        NSLog(@"[CarrierBundles] manual permission save verified: 0%o", after.st_mode & 07777);
        showCarrierBundlesLockedAlert(after.st_mode);
    } else {
        NSLog(@"[CarrierBundles] manual permission save verification failed");
    }
}

static BOOL hook_setAttributesOfItem(id self, SEL _cmd, id attributes, id path, NSError **error) {
    NSNumber *permission = nil;
    BOOL isCarrierPermissionChange = NO;
    if ([path isKindOfClass:[NSString class]] &&
        [attributes isKindOfClass:[NSDictionary class]]) {
        permission = [(NSDictionary *)attributes objectForKey:NSFilePosixPermissions];
        isCarrierPermissionChange = permission &&
            path_is_at_or_inside_root(normalized_path((NSString *)path), kCarrierBundlesRoot);
    }

    // For Carrier Bundles permission saves we take ownership of the call.
    // Calling the original implementation first is what made Filza surface
    // "no permission": its chmod failed, it recorded the error, and only then
    // did we patch the mode through the kernel, leaving the UI convinced the
    // save had failed even though stat already reported the new mode.
    if (isCarrierPermissionChange && g_sandbox_escaped &&
        [path isKindOfClass:[NSString class]]) {
        const char *cpath = [(NSString *)path fileSystemRepresentation];
        struct stat before;
        if (lstat(cpath, &before) == 0 && !S_ISLNK(before.st_mode)) {
            mode_t targetPermissions = [permission unsignedShortValue] & 07777;
            NSLog(@"[CarrierBundles] permission save intercepted: %@ 0%o -> 0%o",
                  path, (unsigned)(before.st_mode & 07777), (unsigned)targetPermissions);

            if (carrier_apply_permissions(cpath, targetPermissions)) {
                struct stat after;
                if (stat(cpath, &after) == 0 &&
                    (after.st_mode & 07777) == targetPermissions) {
                    if (error) *error = nil;
                    NSLog(@"[CarrierBundles] saved permissions: %@ -> 0%o",
                          path, (unsigned)(after.st_mode & 07777));
                    reportCarrierPermissionIfSaved((NSString *)path, [permission unsignedShortValue]);
                    return YES;
                }
                NSLog(@"[CarrierBundles] verify failed after apply: %@ got 0%o want 0%o",
                      path, (unsigned)(after.st_mode & 07777), (unsigned)targetPermissions);
            } else {
                NSLog(@"[CarrierBundles] apply failed for %@; deferring to original implementation",
                      path);
            }
        } else {
            NSLog(@"[CarrierBundles] intercepted save but lstat failed for %@ (errno=%d), deferring",
                  path, errno);
        }
    }

    BOOL ok = orig_setAttributesOfItem ?
        ((BOOL(*)(id,SEL,id,id,NSError**))orig_setAttributesOfItem)(self, _cmd, attributes, path, error) : NO;
    if (isCarrierPermissionChange) {
        NSLog(@"[CarrierBundles] fell back to original setAttributes for %@ -> %d", path, ok);
    }
    return ok;
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
    Class nsfm = [NSFileManager class];
    if (nsfm) {
        Method m = class_getInstanceMethod(nsfm, @selector(setAttributes:ofItemAtPath:error:));
        if (m) {
            orig_setAttributesOfItem = method_getImplementation(m);
            method_setImplementation(m, (IMP)hook_setAttributesOfItem);
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

// Diagnostic probe. Runs the exact operations the user needs (create / delete /
// chmod inside Carrier Bundles) and logs rc+errno for each, so one device run
// tells us which kernel layer is refusing:
//   EACCES(13) -> plain DAC (mode bits)      => need uid 0
//   EPERM(1)   -> sandbox / data vault MACF  => need uid 0 + label
//   EROFS(30)  -> read-only mount
// Everything it creates is removed again, and the directory mode is never
// changed (chmod is re-issued with the *current* mode).
static void cw_probe_matrix(const char *tag);

static void cw_probe(const char *tag) {
    const char *dir = kCarrierBundlesPath;
    NSLog(@"[PROBE][%s] uid=%u euid=%u gid=%u egid=%u",
          tag, getuid(), geteuid(), getgid(), getegid());

    struct stat st;
    if (lstat(dir, &st) == 0) {
        NSLog(@"[PROBE][%s] lstat dir mode=0%o uid=%u gid=%u flags=0x%x",
              tag, (unsigned)(st.st_mode & 07777), st.st_uid, st.st_gid,
              (unsigned)st.st_flags);
    } else {
        NSLog(@"[PROBE][%s] lstat dir failed errno=%d(%s)", tag, errno, strerror(errno));
    }

    const char *targets[2] = { "/var/mobile/Library", dir };
    const char *names[2] = { "Library", "CarrierBundles" };

    // Baseline check: this is what "能访问系统文件" actually means. If opendir
    // stops working here, the exploit itself regressed, not the permission code.
    for (int i = 0; i < 2; i++) {
        DIR *d = opendir(targets[i]);
        int cnt = -1, dErr = 0;
        if (d) {
            cnt = 0;
            while (readdir(d) != NULL) cnt++;
            closedir(d);
        } else {
            dErr = errno;
        }
        NSLog(@"[PROBE][%s] opendir(%s) entries=%d errno=%d",
              tag, names[i], cnt, dErr);
    }

    for (int i = 0; i < 2; i++) {
        errno = 0;
        int aw = access(targets[i], W_OK);
        int awErr = errno;

        char probePath[1200];
        snprintf(probePath, sizeof(probePath), "%s/.cwp_%d", targets[i], (int)getpid());
        errno = 0;
        int fd = open(probePath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        int crErr = errno;
        int ur = -1, ulErr = 0;
        if (fd >= 0) {
            close(fd);
            errno = 0;
            ur = unlink(probePath);
            ulErr = errno;
        }
        NSLog(@"[PROBE][%s] %s accessW=%d/errno%d create=%d/errno%d unlink=%d/errno%d",
              tag, names[i], aw, awErr, fd, crErr, ur, ulErr);
    }

    // chmod with the current mode: exercises the VFS write path without
    // actually changing the stored permission bits.
    if (lstat(dir, &st) == 0) {
        errno = 0;
        int cr = chmod(dir, st.st_mode & 07777);
        NSLog(@"[PROBE][%s] chmod(dir, 0%o)=%d errno=%d(%s)",
              tag, (unsigned)(st.st_mode & 07777), cr, errno, strerror(errno));
    }

    cw_probe_matrix(tag);
}

// One path alone cannot distinguish "the sandbox is still closed" from "this
// particular directory is protected by something else". After the earlier run
// showed create() succeeding in /var/mobile/Library but failing in
// /var/mobile/Library/Carrier Bundles, the matrix below writes and removes one
// file in each of several directories and prints dev / mount flags / rootless
// xattr / errno per attempt, so the refusing layer is identified by comparison:
//   every child of Library fails  -> the extension is not inherited by children
//   only Carrier Bundles fails    -> path-level protection (data vault, special
//                                    inode, or a separate mount)
//   st_dev differs from siblings  -> it is a separate mount / firmlink
static void cw_probe_matrix(const char *tag) {
    static const struct { const char *name; const char *path; } items[] = {
        { "Library",         "/private/var/mobile/Library" },
        { "Lib/Caches",      "/private/var/mobile/Library/Caches" },
        { "Lib/Preferences", "/private/var/mobile/Library/Preferences" },
        { "Lib/SMS",         "/private/var/mobile/Library/SMS" },
        { "Lib/Keyboard",    "/private/var/mobile/Library/Keyboard" },
        { "CarrierBundles",  "/private/var/mobile/Library/Carrier Bundles" },
        { "Media",           "/private/var/mobile/Media" },
        { "Documents",       "/private/var/mobile/Documents" },
    };

    for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
        struct stat st;
        if (lstat(items[i].path, &st) != 0) {
            NSLog(@"[PROBE][%s] MATRIX %-15s lstat failed errno=%d(%s)",
                  tag, items[i].name, errno, strerror(errno));
            continue;
        }

        char rootless[64];
        memset(rootless, 0, sizeof(rootless));
        errno = 0;
        ssize_t xlen = getxattr(items[i].path, "com.apple.rootless",
                                rootless, sizeof(rootless) - 1, 0, 0);
        int xerr = errno;

        struct statfs sf;
        memset(&sf, 0, sizeof(sf));
        int haveFs = (statfs(items[i].path, &sf) == 0);

        char probe[1200];
        snprintf(probe, sizeof(probe), "%s/.cwp_%d", items[i].path, (int)getpid());
        errno = 0;
        int fd = open(probe, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        int cerr = errno;
        int ur = -1, uerr = 0;
        if (fd >= 0) {
            close(fd);
            errno = 0;
            ur = unlink(probe);
            uerr = errno;
        }

        NSLog(@"[PROBE][%s] MATRIX %-15s mode=0%o uid=%u gid=%u dev=0x%llx flags=0x%x "
              "xattr=%ld/%d create=%d/%d unlink=%d/%d fs=%s mnt=0x%x",
              tag, items[i].name, (unsigned)(st.st_mode & 07777),
              st.st_uid, st.st_gid, (unsigned long long)st.st_dev,
              (unsigned)st.st_flags, (long)xlen, xerr, fd, cerr, ur, uerr,
              haveFs ? sf.f_fstypename : "?", haveFs ? (unsigned)sf.f_flags : 0);
    }
}

static void runExploit(void) {
    NSLog(@"[Tweak] Running kexploit...");
    int kret = kexploit_opa334();
    if (kret != 0) {
        NSLog(@"[Tweak] kexploit failed: %d", kret);
        return;
    }

    NSLog(@"[Tweak] kexploit succeeded, escaping sandbox...");
    cw_probe("before-escape");

    uint64_t self_proc_addr = proc_self();

    // The extension offsets inherited from another iOS build were never
    // verified here, and the old "SANDBOX ESCAPED" proof point was a false
    // positive (it tested a path the container already allows). Dump the real
    // objects so the layout can be read off this device.
#define RC_DUMP_SANDBOX 1
#if RC_DUMP_SANDBOX
    sbx_dump_state(self_proc_addr, "before");
#endif

    int sret = sandbox_escape(self_proc_addr);
    NSLog(@"[Tweak] sandbox_escape returned %d", sret);
    if (sret != 0) {
        NSLog(@"[CarrierBundles] skipped because sandbox escape failed");
        return;
    }
    g_sandbox_escaped = YES;

#if RC_DUMP_SANDBOX
    sbx_dump_state(self_proc_addr, "after");
#endif
    cw_probe("after-escape");

    // Experience switch: elevating the whole process to uid 0 breaks Filza's
    // own baseline (it stops browsing system paths and loses the sandbox
    // escape it just performed), so it is OFF by default. Keep the code around
    // for the "locked to 0555 but still writable" mode, but never enable it
    // without also proving that baseline browsing still works afterwards.
#define RC_ENABLE_ROOT_ELEVATION 0
#if RC_ENABLE_ROOT_ELEVATION
    int eret = sbx_elevate_self_uid0(self_proc_addr);
    NSLog(@"[Tweak] root elevation returned %d (uid=%u)", eret, getuid());
    cw_probe("after-root");
#else
    NSLog(@"[Tweak] root elevation disabled in this build (baseline-safe mode); uid=%u",
          getuid());
#endif

    // Establish and validate the reusable launchd context while the exploit
    // setup is still in its controlled startup phase. Permission saves only
    // reuse this context; they never initialize kernel-facing state.
    initialize_launchd_remote_call();

    struct stat initialState;
    if (stat(kCarrierBundlesPath, &initialState) == 0 && S_ISDIR(initialState.st_mode)) {
        NSLog(@"[CarrierBundles] initial dir mode=0%o uid=%u gid=%u",
              (unsigned)(initialState.st_mode & 07777),
              initialState.st_uid, initialState.st_gid);
    }
    // NOTE: no early return for a "persisted 0555" any more. That shortcut is
    // what left the folder permanently read-only for our own uid=501 process:
    // the first 0555 save skipped the repair on every later launch, so the
    // folder could never be written to again.

    // Keep the original Carrier Bundles repair. Changing only the directory
    // mode leaves existing root-owned children inaccessible to mobile.
    long repaired = apfs_mobile_rw_tree(kCarrierBundlesPath, 501, 501);
    NSLog(@"[CarrierBundles] original tree repair processed %ld entries", repaired);
    if (repaired <= 0) {
        NSLog(@"[CarrierBundles] tree repair failed; manual permission saving is unavailable");
        return;
    }

    struct stat writableState;
    if (stat(kCarrierBundlesPath, &writableState) == 0) {
        showCarrierBundlesWritableAlert(writableState.st_mode);
    }

    // For root-owned paths that fail DAC, use apfs_own(path, 501, 501) to
    // flip on-disk ownership to mobile before opening. Example:
    //     if (apfs_own("/var/root/.somefile", 501, 501) == 0) { ... }

    // App bundle ownership repair still runs lazily. Carrier Bundles is
    // repaired only while writable; a persisted 0555 directory is preserved.
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
        NSLog(@"[Tweak] app launched; starting original exploit flow");
        scheduleExploitOnce();
    }];
}

