//
//  ENCRYPT.h
//  encrypt
//
//  Created by Jun on 17/2/7.
//  Copyright © 2017年 Jun. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ENCRYPT : NSObject

//HASH
//md5 加密
+ (NSString *)md5:(NSString *)input;
//SHA1
+ (NSString *)SHA1String:(NSString *)str;
//SHA256
+ (NSString *)SHA256String:(NSString *)str;
//SHA512
+ (NSString *)SHA512String:(NSString *)str;

//BASE64加密
+ (NSString *)base64EncodeString:(NSString *)str;
//BASE64解密
+ (NSString *)base64DecodeString:(NSString *)str;

//DES加密 携带秘钥
+ (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key;
//DES解密 携带秘钥
+ (NSData *)DESDecrypt:(NSData *)data WithKey:(NSString *)key;

//BASE64转data
+ (NSData *)dataWithBase64EncodedString:(NSString *)string;
//BASE64转str
+ (NSString *)base64DncodedStringFrom:(NSData *)data;

//AES128加密 base64转码
+ (NSString *)AES128_encrypt:(NSString *)str withKey:(NSString *)key iv:(NSString *)iv;
//AES128解密 base64转码
+ (NSString *)AES128_decrypt:(NSString *)str withKey:(NSString *)key iv:(NSString *)iv;

+ (instancetype)sharedRSACryptor;
//RSA
/**
 *  生成密钥对
 *
 *  @param keySize 密钥尺寸，可选数值(512/1024/2048)
 */
- (void)generateKeyPair:(NSUInteger)keySize;
/**
 *  加载公钥
 *
 *  @param publicKeyPath 公钥路径
 *
 @code
 # 生成证书
 $ openssl genrsa -out ca.key 1024
 # 创建证书请求
 $ openssl req -new -key ca.key -out rsacert.csr
 # 生成证书并签名
 $ openssl x509 -req -days 3650 -in rsacert.csr -signkey ca.key -out rsacert.crt
 # 转换格式
 $ openssl x509 -outform der -in rsacert.crt -out rsacert.der
 @endcode
 */
- (void)loadPublicKey:(NSString *)publicKeyPath;
/**
 *  加载私钥
 *
 *  @param privateKeyPath p12文件路径
 *  @param password       p12文件密码
 *
 @code
 openssl pkcs12 -export -out p.p12 -inkey ca.key -in rsacert.crt
 @endcode
 */
- (void)loadPrivateKey:(NSString *)privateKeyPath password:(NSString *)password;
/**
 *  加密数据 base64转码
 *
 *  @param str 明文数据
 *
 *  @return 密文数据
 */
- (NSString *)encryptData:(NSString *)str;
/**
 *  解密数据 base64转码
 *
 *  @param str 密文数据
 *
 *  @return 明文数据
 */
- (NSString *)decryptData:(NSString *)str;



@end
