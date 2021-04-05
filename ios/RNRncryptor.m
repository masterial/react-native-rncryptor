#import "RNRncryptor.h"

@implementation RNRncryptor

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(encrypt:(NSString *)text 
                  password:(NSString *)password
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error;
    NSData *encryptedData = [RNEncryptor encryptData:data
                                        withSettings:kRNCryptorAES256Settings
                                            password:password
                                               error:&error];
    NSString *b64 = [encryptedData base64EncodedStringWithOptions:0];
    
    if(error){
        reject(@"Error", @"Decrypt failed", error);
    } else {
        resolve(b64);
    }
}

RCT_EXPORT_METHOD(encryptFromBase64:(NSString *)base64
                  password:(NSString *)password
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:base64 options:0];
    
    NSError *error;
    NSData *encryptedData = [RNEncryptor encryptData:data
                                        withSettings:kRNCryptorAES256Settings
                                            password:password
                                               error:&error];
    NSString *b64 = [encryptedData base64EncodedStringWithOptions:0];
    
    if(error){
        reject(@"Error", @"Decrypt failed", error);
    } else {
        resolve(b64);
    }
}

RCT_EXPORT_METHOD(encryptFile:(NSString *)filepath
                  password:(NSString *)password
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    BOOL fileExists = [[NSFileManager defaultManager] fileExistsAtPath:filepath];

    if (!fileExists) {
        return reject(@"ENOENT", [NSString stringWithFormat:@"ENOENT: no such file or directory, open '%@'", filepath], nil);
    }

    NSError *error = nil;

    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:filepath error:&error];

    if (error) {
        reject(@"Error", @"Encrypt file", error);
    }

    if ([attributes objectForKey:NSFileType] == NSFileTypeDirectory) {
        return reject(@"EISDIR", @"EISDIR: illegal operation on a directory, read", nil);
    }

    NSData *content = [[NSFileManager defaultManager] contentsAtPath:filepath];
    
    NSData *encryptedData = [RNEncryptor encryptData:content
                                        withSettings:kRNCryptorAES256Settings
                                            password:password
                                               error:&error];
    NSString *b64 = [encryptedData base64EncodedStringWithOptions:0];
    
    if(error){
        reject(@"Error", @"Encrypt file failed", error);
    } else {
        resolve(b64);
    }
}

RCT_EXPORT_METHOD(decrypt:(NSString *)base64 
                  password:(NSString *)password
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:base64 options:0];
    NSError *error;
    NSData *decryptedData = [RNDecryptor decryptData:data
                                        withPassword:password
                                               error:&error];
    NSString *string = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    
    if(error){
        reject(@"Error", @"Decrypt failed", error);
    } else {
        resolve(string);
    }
}

RCT_EXPORT_METHOD(decryptToBase64:(NSString *)encrypted
                  password:(NSString *)password
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:encrypted options:0];
    NSError *error;
    NSData *decryptedData = [RNDecryptor decryptData:data
                                        withPassword:password
                                               error:&error];
    
    NSString *b64 = [decryptedData base64EncodedStringWithOptions:0];
    
    if(error){
        reject(@"Error", @"Decrypt failed", error);
    } else {
        resolve(b64);
    }
}

RCT_EXPORT_METHOD(readEncryptedFile:(NSString *)filepath
                  password:(NSString *)password
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    BOOL fileExists = [[NSFileManager defaultManager] fileExistsAtPath:filepath];

    if (!fileExists) {
        return reject(@"ENOENT", [NSString stringWithFormat:@"ENOENT: no such file or directory, open '%@'", filepath], nil);
    }

    NSError *error = nil;

    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:filepath error:&error];

    if (error) {
        reject(@"Error", @"Decrypt failed", error);
    }

    if ([attributes objectForKey:NSFileType] == NSFileTypeDirectory) {
        return reject(@"EISDIR", @"EISDIR: illegal operation on a directory, read", nil);
    }

    NSData *content = [[NSFileManager defaultManager] contentsAtPath:filepath];
    NSData *decryptedData = [RNDecryptor decryptData:content
                                        withPassword:password
                                               error:&error];
    
    NSString *b64 = [decryptedData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];

    resolve(b64);
}

RCT_EXPORT_METHOD(readFile:(NSString *)filepath
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    BOOL fileExists = [[NSFileManager defaultManager] fileExistsAtPath:filepath];

    if (!fileExists) {
        return reject(@"ENOENT", [NSString stringWithFormat:@"ENOENT: no such file or directory, open '%@'", filepath], nil);
    }

    NSError *error = nil;

    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:filepath error:&error];

    if (error) {
        reject(@"Error", @"Decrypt failed", error);
    }

    if ([attributes objectForKey:NSFileType] == NSFileTypeDirectory) {
        return reject(@"EISDIR", @"EISDIR: illegal operation on a directory, read", nil);
    }

    NSData *content = [[NSFileManager defaultManager] contentsAtPath:filepath];
    NSString *b64 = [content base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];

    resolve(b64);
}

@end
  
