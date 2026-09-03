//
//  PSUserDefaults.h
//  prefSupport
//
//  NSUserDefaults, served from the TweakInject preference store instead of
//  cfprefsd. The method set mirrors Foundation's, so porting a tweak is usually
//  a class swap:
//
//      NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
//      PSUserDefaults *d = [[PSUserDefaults alloc] initWithSuiteName:@"com.you.tweak"];
//
//  There is no `standardUserDefaults` equivalent, deliberately. A tweak has no
//  "own" domain the way an app does -- it is a guest in someone else's process,
//  and the stock standardUserDefaults there is the HOST's. Naming the domain is
//  the point: it is what makes a tweak's settings the same in every process it
//  loads into.
//
//  Conventionally the domain is the tweak's package identifier
//  (`com.author.tweakname`), the same convention HBPreferences documents for
//  `initWithIdentifier:`, but nothing enforces that and a tweak may use several.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PSUserDefaults : NSObject

/// `domain` is the preference identifier, e.g. `com.author.tweakname`.
///
/// Returns nil if the domain is not a single safe path component -- it names a
/// file inside the tweak preference store, so anything that could address a
/// path outside it is refused. Never raises: a tweak's bad input must not take
/// down the app it is loaded into.
- (nullable instancetype)initWithSuiteName:(NSString *)domain NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@property (nonatomic, readonly, copy) NSString *suiteName;

/// Values returned when a key has never been written. Layered UNDER the store,
/// so registering a default never overwrites what the user chose -- same
/// contract as -[NSUserDefaults registerDefaults:].
- (void)registerDefaults:(NSDictionary<NSString *, id> *)defaults;

- (nullable id)objectForKey:(NSString *)key;
- (void)setObject:(nullable id)value forKey:(NSString *)key;
- (void)removeObjectForKey:(NSString *)key;

- (BOOL)boolForKey:(NSString *)key;
- (NSInteger)integerForKey:(NSString *)key;
- (double)doubleForKey:(NSString *)key;
- (float)floatForKey:(NSString *)key;
- (nullable NSString *)stringForKey:(NSString *)key;
- (nullable NSArray *)arrayForKey:(NSString *)key;
- (nullable NSDictionary *)dictionaryForKey:(NSString *)key;
- (nullable NSData *)dataForKey:(NSString *)key;

- (void)setBool:(BOOL)value forKey:(NSString *)key;
- (void)setInteger:(NSInteger)value forKey:(NSString *)key;
- (void)setDouble:(double)value forKey:(NSString *)key;
- (void)setFloat:(float)value forKey:(NSString *)key;

/// Every key in the domain, defaults included.
- (NSDictionary<NSString *, id> *)dictionaryRepresentation;

/// Writes are already on disk when they return; this re-posts the change
/// notification and always succeeds.
- (BOOL)synchronize;

/// defaults[@"Key"] = @YES;
- (nullable id)objectForKeyedSubscript:(NSString *)key;
- (void)setObject:(nullable id)value forKeyedSubscript:(NSString *)key;

@end

NS_ASSUME_NONNULL_END
