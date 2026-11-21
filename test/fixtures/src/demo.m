// Objective-C fixture for REA-iPhone class-dump tests. Compiled for
// arm64-apple-ios without Foundation, so NSObject is declared as an external
// root class: subclasses then bind to _OBJC_CLASS_$_NSObject at load time,
// exercising external-superclass resolution through bind/chained fixups.

__attribute__((objc_root_class))
@interface NSObject
+ (id)alloc;
- (id)init;
@end

@class NSString;

@protocol Greeter
- (const char *)greet;
@optional
- (void)wave:(int)times;
@property (nonatomic, readonly) int mood;
@end

@interface Wallet : NSObject <Greeter> {
  long _balance;
  NSString *_owner;
  unsigned char _flags[4];
  struct GeoPoint { double lat; double lon; } _location;
}
@property (nonatomic) long balance;
@property (nonatomic, copy) NSString *owner;
@property (nonatomic, readonly) int mood;
@property (class, nonatomic, readonly) int instanceCount;
+ (id)sharedWallet;
- (void)deposit:(long)amount;
- (_Bool)transferTo:(NSString *)recipient amount:(double)amount error:(id *)error;
- (const char *)greet;
@end

@implementation Wallet
@synthesize balance = _balance;
@synthesize owner = _owner;
+ (int)instanceCount { return 1; }
+ (id)sharedWallet { return 0; }
- (int)mood { return 1; }
- (void)deposit:(long)amount { _balance += amount; }
- (_Bool)transferTo:(NSString *)recipient amount:(double)amount error:(id *)error { return 0; }
- (const char *)greet { return "Hello from Wallet"; }
@end

@interface Wallet (Audit)
- (void)audit;
+ (void)resetAuditLog;
@end
@implementation Wallet (Audit)
- (void)audit {}
+ (void)resetAuditLog {}
@end

// A class whose runtime name is a Swift-style mangled name.
__attribute__((objc_runtime_name("_TtC9WalletKit15TransferService")))
@interface SwiftLikeService : NSObject
- (void)send;
@end
@implementation SwiftLikeService
- (void)send {}
@end

// Category on an external class: its cls pointer is a bind, not a rebase.
@interface NSObject (Telemetry)
- (void)rea_trackEvent:(NSString *)name;
@end
@implementation NSObject (Telemetry)
- (void)rea_trackEvent:(NSString *)name {}
@end

NSString *TelemetryURL(void) { return @"https://telemetry.example.com/collect"; }

const char *kSecretEndpoint = "https://api.example.com/v2/transfer";
const char *kStripeKey = "sk_live_51HxExampleExampleExampleExample00";
const char *kJailbreakPath = "/Applications/Cydia.app";
const char *kSupport = "support@example.com";
int main(void) { return 0; }
