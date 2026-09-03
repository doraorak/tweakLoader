//
//  PSUserDefaults.m
//  prefSupport
//

#import "PSUserDefaults.h"
#import "PSPrefsCore.h"
#import <os/lock.h>

@implementation PSUserDefaults {
    NSMutableDictionary<NSString *, id> *_registeredDefaults;
    os_unfair_lock _lock;
}

- (nullable instancetype)initWithSuiteName:(NSString *)domain {
    // Returns nil rather than raising. This library is loaded into other
    // people's processes -- Dock, ControlCenter, whatever a filter matches --
    // and an NSParameterAssert here would turn a tweak's bad domain string into
    // a crash of its host. Refusing to construct is the loudest thing that is
    // still safe; every accessor on a nil object is then a harmless no-op.
    if (!PSPrefsPathForDomain(domain)) return nil;
    self = [super init];
    if (self) {
        _suiteName = [domain copy];
        _registeredDefaults = [NSMutableDictionary dictionary];
        _lock = OS_UNFAIR_LOCK_INIT;
    }
    return self;
}

#pragma mark - Defaults

- (void)registerDefaults:(NSDictionary<NSString *, id> *)defaults {
    if (defaults.count == 0) return;
    os_unfair_lock_lock(&_lock);
    [_registeredDefaults addEntriesFromDictionary:defaults];
    os_unfair_lock_unlock(&_lock);
}

- (nullable id)registeredDefaultForKey:(NSString *)key {
    os_unfair_lock_lock(&_lock);
    id v = _registeredDefaults[key];
    os_unfair_lock_unlock(&_lock);
    return v;
}

#pragma mark - Reading

- (nullable id)objectForKey:(NSString *)key {
    if (key.length == 0) return nil;
    id stored = PSPrefsCopyDomain(self.suiteName)[key];
    return stored ?: [self registeredDefaultForKey:key];
}

// Typed accessors coerce the way NSUserDefaults does: a number or a string is
// acceptable for the scalar getters, anything else reads as absent.
- (BOOL)boolForKey:(NSString *)key {
    id v = [self objectForKey:key];
    return [v isKindOfClass:NSNumber.class] || [v isKindOfClass:NSString.class] ? [v boolValue] : NO;
}

- (NSInteger)integerForKey:(NSString *)key {
    id v = [self objectForKey:key];
    return [v isKindOfClass:NSNumber.class] || [v isKindOfClass:NSString.class] ? [v integerValue] : 0;
}

- (double)doubleForKey:(NSString *)key {
    id v = [self objectForKey:key];
    return [v isKindOfClass:NSNumber.class] || [v isKindOfClass:NSString.class] ? [v doubleValue] : 0.0;
}

- (float)floatForKey:(NSString *)key {
    id v = [self objectForKey:key];
    return [v isKindOfClass:NSNumber.class] || [v isKindOfClass:NSString.class] ? [v floatValue] : 0.0f;
}

- (nullable NSString *)stringForKey:(NSString *)key {
    id v = [self objectForKey:key];
    if ([v isKindOfClass:NSString.class]) return v;
    if ([v isKindOfClass:NSNumber.class]) return [v stringValue];
    return nil;
}

- (nullable NSArray *)arrayForKey:(NSString *)key {
    id v = [self objectForKey:key];
    return [v isKindOfClass:NSArray.class] ? v : nil;
}

- (nullable NSDictionary *)dictionaryForKey:(NSString *)key {
    id v = [self objectForKey:key];
    return [v isKindOfClass:NSDictionary.class] ? v : nil;
}

- (nullable NSData *)dataForKey:(NSString *)key {
    id v = [self objectForKey:key];
    return [v isKindOfClass:NSData.class] ? v : nil;
}

- (NSDictionary<NSString *, id> *)dictionaryRepresentation {
    os_unfair_lock_lock(&_lock);
    NSMutableDictionary *out = [_registeredDefaults mutableCopy];
    os_unfair_lock_unlock(&_lock);
    [out addEntriesFromDictionary:PSPrefsCopyDomain(self.suiteName) ?: @{}];
    return out;
}

#pragma mark - Writing

- (void)setObject:(nullable id)value forKey:(NSString *)key {
    if (key.length == 0) return;
    PSPrefsSetValue(self.suiteName, key, value);
}

- (void)removeObjectForKey:(NSString *)key {
    [self setObject:nil forKey:key];
}

- (void)setBool:(BOOL)value forKey:(NSString *)key      { [self setObject:@(value) forKey:key]; }
- (void)setInteger:(NSInteger)value forKey:(NSString *)key { [self setObject:@(value) forKey:key]; }
- (void)setDouble:(double)value forKey:(NSString *)key  { [self setObject:@(value) forKey:key]; }
- (void)setFloat:(float)value forKey:(NSString *)key    { [self setObject:@(value) forKey:key]; }

- (BOOL)synchronize {
    return PSPrefsSynchronize(self.suiteName);
}

#pragma mark - Subscripting

- (nullable id)objectForKeyedSubscript:(NSString *)key {
    return [self objectForKey:key];
}

- (void)setObject:(nullable id)value forKeyedSubscript:(NSString *)key {
    [self setObject:value forKey:key];
}

@end
