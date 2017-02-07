//
//  ENCRYPT.m
//  encrypt
//
//  Created by Jun on 17/2/7.
//  Copyright © 2017年 Jun. All rights reserved.
//

#import "ENCRYPT.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

//base64编码
static const char encodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define LocalNoneStr @""
//AES128偏移量 16位
#define VIkey @"1234567890123456"

// 填充模式 kSecPaddingNone 每次加密结果是固定的，kSecPaddingPKCS1是随机变化的
#define kTypeOfWrapPadding		kSecPaddingNone

// 公钥/私钥标签
#define kPublicKeyTag			"com.litao.publickey"
#define kPrivateKeyTag			"com.litao.privatekey"
static const uint8_t publicKeyIdentifier[]		= kPublicKeyTag;
static const uint8_t privateKeyIdentifier[]		= kPrivateKeyTag;

@interface ENCRYPT()
{
    SecKeyRef publicKeyRef;         //公钥
    SecKeyRef privateKeyRef;        //私钥
}

@property (nonatomic , strong)NSData *publicTag;

@property (nonatomic , strong)NSData *privateTag;

@end

@implementation ENCRYPT

+ (instancetype)sharedRSACryptor {
    static id instance;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        // 查询密钥的标签
        _privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
        _publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
    }
    return self;
}


+ (NSString *)md5:(NSString *)input{
    const char *cStr = [input UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5( cStr, (CC_LONG)strlen(cStr), digest ); // This is the md5 call
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    return  output;
}

//SHA1
+ (NSString *)SHA1String:(NSString *)str{
    const char *strchar = str.UTF8String;
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1(strchar, (CC_LONG)strlen(strchar), digest);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH *2];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }
    return output;
}

//SHA256
+ (NSString *)SHA256String:(NSString *)str{
    const char *strchar = str.UTF8String;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    
    CC_SHA256(strchar, (CC_LONG)strlen(strchar), digest);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH *2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }
    return output;
}

//SHA512
+ (NSString *)SHA512String:(NSString *)str{
    const char *strchar = str.UTF8String;
    unsigned char digest[CC_SHA512_DIGEST_LENGTH];
    
    CC_SHA512(strchar, (CC_LONG)strlen(strchar), digest);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA512_DIGEST_LENGTH *2];
    for (int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }
    return output;
}


//BASE64加密
+ (NSString *)base64EncodeString:(NSString *)str{
    if ([str isEqualToString:LocalNoneStr] && str == nil){
        return LocalNoneStr;
    }
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    //以bundleid为key的加密
    NSString *key = [[NSBundle mainBundle] bundleIdentifier];
    data = [self DESEncrypt:data WithKey:key];
    NSString *encryptStr = [self base64DncodedStringFrom:data];
    return encryptStr;
}

//BASE64解密
+ (NSString *)base64DecodeString:(NSString *)str{
    if (str == nil && [str isEqualToString:LocalNoneStr]){
        return LocalNoneStr;
    }
    NSData *data = [self dataWithBase64EncodedString:str];
    NSString *key = [[NSBundle mainBundle] bundleIdentifier];
    data = [self DESDecrypt:data WithKey:key];
    NSString *decodeStr = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
    return decodeStr;
}

/******************************************************************************
 函数名称 : + (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
 函数描述 : 文本数据进行DES加密
 输入参数 : (NSData *)data
 (NSString *)key
 输出参数 : N/A
 返回参数 : (NSData *)
 备注信息 : 此函数不可用于过长文本
 ******************************************************************************/
+ (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
{
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr, kCCBlockSizeDES,
                                          NULL,
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    
    free(buffer);
    return nil;
}

/******************************************************************************
 函数名称 : + (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
 函数描述 : 文本数据进行DES解密
 输入参数 : (NSData *)data
 (NSString *)key
 输出参数 : N/A
 返回参数 : (NSData *)
 备注信息 : 此函数不可用于过长文本
 ******************************************************************************/
+ (NSData *)DESDecrypt:(NSData *)data WithKey:(NSString *)key
{
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr, kCCBlockSizeDES,
                                          NULL,
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer);
    return nil;
}



/******************************************************************************
 函数名称 : + (NSData *)dataWithBase64EncodedString:(NSString *)string
 函数描述 : base64格式字符串转换为文本数据
 输入参数 : (NSString *)string
 输出参数 : N/A
 返回参数 : (NSData *)
 备注信息 :
 ******************************************************************************/
+ (NSData *)dataWithBase64EncodedString:(NSString *)string
{
    if (string == nil)
        [NSException raise:NSInvalidArgumentException format:@""];
    if ([string length] == 0)
        return [NSData data];
    
    static char *decodingTable = NULL;
    if (decodingTable == NULL)
    {
        decodingTable = malloc(256);
        if (decodingTable == NULL)
            return nil;
        memset(decodingTable, CHAR_MAX, 256);
        NSUInteger i;
        for (i = 0; i < 64; i++)
            decodingTable[(short)encodingTable[i]] = i;
    }
    
    const char *characters = [string cStringUsingEncoding:NSASCIIStringEncoding];
    if (characters == NULL)     //  Not an ASCII string!
        return nil;
    char *bytes = malloc((([string length] + 3) / 4) * 3);
    if (bytes == NULL)
        return nil;
    NSUInteger length = 0;
    
    NSUInteger i = 0;
    while (YES)
    {
        char buffer[4];
        short bufferLength;
        for (bufferLength = 0; bufferLength < 4; i++)
        {
            if (characters[i] == '\0')
                break;
            if (isspace(characters[i]) || characters[i] == '=')
                continue;
            buffer[bufferLength] = decodingTable[(short)characters[i]];
            if (buffer[bufferLength++] == CHAR_MAX)      //  Illegal character!
            {
                free(bytes);
                return nil;
            }
        }
        
        if (bufferLength == 0)
            break;
        if (bufferLength == 1)      //  At least two characters are needed to produce one byte!
        {
            free(bytes);
            return nil;
        }
        
        //  Decode the characters in the buffer to bytes.
        bytes[length++] = (buffer[0] << 2) | (buffer[1] >> 4);
        if (bufferLength > 2)
            bytes[length++] = (buffer[1] << 4) | (buffer[2] >> 2);
        if (bufferLength > 3)
            bytes[length++] = (buffer[2] << 6) | buffer[3];
    }
    
    bytes = realloc(bytes, length);
    return [NSData dataWithBytesNoCopy:bytes length:length];
}

/******************************************************************************
 函数名称 : + (NSString *)base64DncodedStringFrom:(NSData *)data
 函数描述 : 文本数据转换为base64格式字符串
 输入参数 : (NSData *)data
 输出参数 : N/A
 返回参数 : (NSString *)
 备注信息 :
 ******************************************************************************/
+ (NSString *)base64DncodedStringFrom:(NSData *)data
{
    if ([data length] == 0)
        return @"";
    
    char *characters = malloc((([data length] + 2) / 3) * 4);
    if (characters == NULL)
        return nil;
    NSUInteger length = 0;
    
    NSUInteger i = 0;
    while (i < [data length])
    {
        char buffer[3] = {0,0,0};
        short bufferLength = 0;
        while (bufferLength < 3 && i < [data length])
            buffer[bufferLength++] = ((char *)[data bytes])[i++];
        //  Encode the bytes in the buffer to four characters, including padding "=" characters if necessary.
        characters[length++] = encodingTable[(buffer[0] & 0xFC) >> 2];
        characters[length++] = encodingTable[((buffer[0] & 0x03) << 4) | ((buffer[1] & 0xF0) >> 4)];
        if (bufferLength > 1)
            characters[length++] = encodingTable[((buffer[1] & 0x0F) << 2) | ((buffer[2] & 0xC0) >> 6)];
        else characters[length++] = '=';
        if (bufferLength > 2)
            characters[length++] = encodingTable[buffer[2] & 0x3F];
        else characters[length++] = '=';
    }
    
    return [[NSString alloc] initWithBytesNoCopy:characters length:length encoding:NSASCIIStringEncoding freeWhenDone:YES];
}


#pragma mark - 加密 & 解密数据
- (NSString *)encryptData:(NSString *)str {
    OSStatus sanityCheck = noErr;
    size_t cipherBufferSize = 0;
    size_t keyBufferSize = 0;
    
    
    NSData *plainData = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSAssert(plainData != nil, @"明文数据为空");
    NSAssert(publicKeyRef != nil, @"公钥为空");
    
    NSData *cipher = nil;
    uint8_t *cipherBuffer = NULL;
    
    // 计算缓冲区大小
    cipherBufferSize = SecKeyGetBlockSize(publicKeyRef);
    keyBufferSize = [plainData length];
    
    if (kTypeOfWrapPadding == kSecPaddingNone) {
        NSAssert(keyBufferSize <= cipherBufferSize, @"加密内容太大");
    } else {
        NSAssert(keyBufferSize <= (cipherBufferSize - 11), @"加密内容太大");
    }
    
    // 分配缓冲区
    cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    memset((void *)cipherBuffer, 0x0, cipherBufferSize);
    
    // 使用公钥加密
    sanityCheck = SecKeyEncrypt(publicKeyRef,
                                kTypeOfWrapPadding,
                                (const uint8_t *)[plainData bytes],
                                keyBufferSize,
                                cipherBuffer,
                                &cipherBufferSize
                                );
    
    NSAssert(sanityCheck == noErr, @"加密错误，OSStatus == %d", sanityCheck);
    
    // 生成密文数据
    cipher = [NSData dataWithBytes:(const void *)cipherBuffer length:(NSUInteger)cipherBufferSize];
    
    if (cipherBuffer) free(cipherBuffer);
    
    return [cipher base64EncodedStringWithOptions:0];
}

- (NSString *)decryptData:(NSString *)str {
    OSStatus sanityCheck = noErr;
    size_t cipherBufferSize = 0;
    size_t keyBufferSize = 0;
    
    NSData *key = nil;
    uint8_t *keyBuffer = NULL;
    
    SecKeyRef privateKey = NULL;
    
    privateKey = [self getPrivateKeyRef];
    NSAssert(privateKey != NULL, @"私钥不存在");
    
    NSData *cipherData = [[NSData alloc]initWithBase64EncodedString:str options:0];
    
    // 计算缓冲区大小
    cipherBufferSize = SecKeyGetBlockSize(privateKey);
    keyBufferSize = [cipherData length];
    
    NSAssert(keyBufferSize <= cipherBufferSize, @"解密内容太大");
    
    // 分配缓冲区
    keyBuffer = malloc(keyBufferSize * sizeof(uint8_t));
    memset((void *)keyBuffer, 0x0, keyBufferSize);
    
    // 使用私钥解密
    sanityCheck = SecKeyDecrypt(privateKey,
                                kTypeOfWrapPadding,
                                (const uint8_t *)[cipherData bytes],
                                cipherBufferSize,
                                keyBuffer,
                                &keyBufferSize
                                );
    
    NSAssert1(sanityCheck == noErr, @"解密错误，OSStatus == %d", sanityCheck);
    
    // 生成明文数据
    key = [NSData dataWithBytes:(const void *)keyBuffer length:(NSUInteger)keyBufferSize];
    
    if (keyBuffer) free(keyBuffer);
    
    return [[NSString alloc]initWithData:key encoding:NSUTF8StringEncoding];
    
}

#pragma mark - 密钥处理
/**
 *  生成密钥对
 */
- (void)generateKeyPair:(NSUInteger)keySize {
    OSStatus sanityCheck = noErr;
    publicKeyRef = NULL;
    privateKeyRef = NULL;
    
    NSAssert1((keySize == 512 || keySize == 1024 || keySize == 2048), @"密钥尺寸无效 %tu", keySize);
    
    // 删除当前密钥对
    [self deleteAsymmetricKeys];
    
    // 容器字典
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
    
    // 设置密钥对的顶级字典
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    // 设置私钥字典
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:_privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    // 设置公钥字典
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:_publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    // 设置顶级字典属性
    [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    
    // SecKeyGeneratePair 返回密钥对引用
    sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKeyRef, &privateKeyRef);
    NSAssert((sanityCheck == noErr && publicKeyRef != NULL && privateKeyRef != NULL), @"生成密钥对失败");
}
/**
 *  加载公钥
 */
- (void)loadPublicKey:(NSString *)publicKeyPath {
    
    NSAssert(publicKeyPath.length != 0, @"公钥路径为空");
    
    // 删除当前公钥
    if (publicKeyRef) CFRelease(publicKeyRef);
    
    // 从一个 DER 表示的证书创建一个证书对象
    NSData *certificateData = [NSData dataWithContentsOfFile:publicKeyPath];
    SecCertificateRef certificateRef = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certificateData);
    NSAssert(certificateRef != NULL, @"公钥文件错误");
    
    // 返回一个默认 X509 策略的公钥对象，使用之后需要调用 CFRelease 释放
    SecPolicyRef policyRef = SecPolicyCreateBasicX509();
    // 包含信任管理信息的结构体
    SecTrustRef trustRef;
    
    // 基于证书和策略创建一个信任管理对象
    OSStatus status = SecTrustCreateWithCertificates(certificateRef, policyRef, &trustRef);
    NSAssert(status == errSecSuccess, @"创建信任管理对象失败");
    
    // 信任结果
    SecTrustResultType trustResult;
    // 评估指定证书和策略的信任管理是否有效
    status = SecTrustEvaluate(trustRef, &trustResult);
    NSAssert(status == errSecSuccess, @"信任评估失败");
    
    // 评估之后返回公钥子证书
    publicKeyRef = SecTrustCopyPublicKey(trustRef);
    NSAssert(publicKeyRef != NULL, @"公钥创建失败");
    
    if (certificateRef) CFRelease(certificateRef);
    if (policyRef) CFRelease(policyRef);
    if (trustRef) CFRelease(trustRef);
}

/**
 *  加载私钥
 */
- (void)loadPrivateKey:(NSString *)privateKeyPath password:(NSString *)password {
    
    NSAssert(privateKeyPath.length != 0, @"私钥路径为空");
    
    // 删除当前私钥
    if (privateKeyRef) CFRelease(privateKeyRef);
    
    NSData *PKCS12Data = [NSData dataWithContentsOfFile:privateKeyPath];
    CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
    CFStringRef passwordRef = (__bridge CFStringRef)password;
    
    // 从 PKCS #12 证书中提取标示和证书
    SecIdentityRef myIdentity;
    SecTrustRef myTrust;
    const void *keys[] =   {kSecImportExportPassphrase};
    const void *values[] = {passwordRef};
    CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    
    // 返回 PKCS #12 格式数据中的标示和证书
    OSStatus status = SecPKCS12Import(inPKCS12Data, optionsDictionary, &items);
    
    if (status == noErr) {
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
        myIdentity = (SecIdentityRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
        myTrust = (SecTrustRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemTrust);
    }
    
    if (optionsDictionary) CFRelease(optionsDictionary);
    
    NSAssert(status == noErr, @"提取身份和信任失败");
    
    SecTrustResultType trustResult;
    // 评估指定证书和策略的信任管理是否有效
    status = SecTrustEvaluate(myTrust, &trustResult);
    NSAssert(status == errSecSuccess, @"信任评估失败");
    
    // 提取私钥
    status = SecIdentityCopyPrivateKey(myIdentity, &privateKeyRef);
    NSAssert(status == errSecSuccess, @"私钥创建失败");
}

/**
 *  删除非对称密钥
 */
- (void)deleteAsymmetricKeys {
    OSStatus sanityCheck = noErr;
    NSMutableDictionary *queryPublicKey = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *queryPrivateKey = [[NSMutableDictionary alloc] init];
    
    // 设置公钥查询字典
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:_publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // 设置私钥查询字典
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:_privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // 删除私钥
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryPrivateKey);
    NSAssert1((sanityCheck == noErr || sanityCheck == errSecItemNotFound), @"删除私钥错误，OSStatus == %d", sanityCheck);
    
    // 删除公钥
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryPublicKey);
    NSAssert1((sanityCheck == noErr || sanityCheck == errSecItemNotFound), @"删除公钥错误，OSStatus == %d", sanityCheck);
    
    if (publicKeyRef) CFRelease(publicKeyRef);
    if (privateKeyRef) CFRelease(privateKeyRef);
}

/**
 *  获得私钥引用
 */
- (SecKeyRef)getPrivateKeyRef {
    OSStatus sanityCheck = noErr;
    SecKeyRef privateKeyReference = NULL;
    
    if (privateKeyRef == NULL) {
        NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
        
        // 设置私钥查询字典
        [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [queryPrivateKey setObject:_privateTag forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        
        // 获得密钥
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
        
        if (sanityCheck != noErr) {
            privateKeyReference = NULL;
        }
    } else {
        privateKeyReference = privateKeyRef;
    }
    
    return privateKeyReference;
}


#pragma -aes128
+ (NSString *)AES128_encrypt:(NSString *)str withKey:(NSString *)key iv:(NSString *)iv{
    //设置秘钥
    NSData *keydata = [key dataUsingEncoding:NSUTF8StringEncoding];
    char keyPtr[kCCKeySizeAES128];
    bzero(keyPtr, sizeof(keyPtr));
    [keydata getBytes:keyPtr length:kCCKeySizeAES128];
    //设置iv偏移量
    char ivPtr[kCCKeySizeAES128];
    memset(ivPtr, 0, sizeof(ivPtr));
    int option = 0;
    //判断是CBC加密还是ECB加密
    //kCCOptionPKCS7Padding                      CBC 的加密
    //kCCOptionPKCS7Padding | kCCOptionECBMode   ECB 的加密
    if(iv){
        option = kCCOptionPKCS7Padding;
    }else{
        option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    //设置输出的缓冲区
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    size_t buffer_size = kCCKeySizeAES128 + data.length;
    void *buffer = malloc(buffer_size);
    //开始加密
    size_t numBytesEncrypted =0;
    /**
     CCCrypt 对称核心函数
     1. kCCEncrypt 加密/ kCCDecrypt 解密
     2. 加密算法，默认使用的是 AES/DES
     3. 加密选项 ECB/CBC
     kCCOptionPKCS7Padding                      CBC 的加密
     kCCOptionPKCS7Padding | kCCOptionECBMode   ECB 的加密
     4. 加密密钥
     5. 密钥长度
     6. iv 初始向量，ECB 不需要指定
     7. 加密的数据
     8. 加密的数据长度
     9. 密文的内存地址
     10. 密文缓冲区大小
     11. 加密结果大小
     */
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
            kCCAlgorithmAES128,
            option,
            keyPtr,
            kCCKeySizeAES128,
            ivPtr,
            [data bytes],
            [data length],
            buffer,
            buffer_size,
            &numBytesEncrypted);
    NSData *result = nil;
    if(cryptStatus == kCCSuccess){
        result = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }else{
        free(buffer);
        NSLog(@"%d",cryptStatus);
    }
    return [result base64EncodedStringWithOptions:0];
}


+ (NSString *)AES128_decrypt:(NSString *)str withKey:(NSString *)key iv:(NSString *)iv{
    //设置秘钥
    NSData *keydata = [key dataUsingEncoding:NSUTF8StringEncoding];
    char keyPtr[kCCKeySizeAES128];
    bzero(keyPtr, sizeof(keyPtr));
    [keydata getBytes:keyPtr length:kCCKeySizeAES128];
    //设置iv偏移量
    char ivPtr[kCCKeySizeAES128];
    memset(ivPtr, 0, sizeof(ivPtr));
    int option = 0;
    //判断是CBC加密还是ECB加密
    //kCCOptionPKCS7Padding                      CBC 的加密
    //kCCOptionPKCS7Padding | kCCOptionECBMode   ECB 的加密
    if(iv){
        option = kCCOptionPKCS7Padding;
    }else{
        option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    //设置输出的缓冲区
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:0];
    size_t buffer_size = kCCKeySizeAES128 + data.length;
    void *buffer = malloc(buffer_size);
    //开始加密
    size_t numBytesDncrypted =0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, option, keyPtr, kCCKeySizeAES128, ivPtr, [data bytes], [data length], buffer, buffer_size, &numBytesDncrypted);
    NSData *result = nil;
    if(cryptStatus == kCCSuccess){
        result = [NSData dataWithBytesNoCopy:buffer length:numBytesDncrypted];
    }else{
        free(buffer);
    }
    return [[NSString alloc]initWithData:result encoding:NSUTF8StringEncoding];
}



@end
