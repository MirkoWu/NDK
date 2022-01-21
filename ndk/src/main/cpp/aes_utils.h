//
// Created by ting on 2019-09-17.
//

#ifndef AESTEST_AES_UTILS_H
#define AESTEST_AES_UTILS_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "aes.h"


#define AES_128_CBC_PKCS5_Encrypt  ba
#define AES_128_CBC_PKCS5_Decrypt  bb
#define AES_128_ECB_PKCS5_Encrypt  bj
#define AES_128_ECB_PKCS5_Decrypt  bi
#define getPaddingInput            be
#define findPaddingIndex           bf
#define removePadding              bg


#ifdef __cplusplus
extern "C" {
#endif

/** AES加密, CBC, PKCS5Padding */
char *AES_128_CBC_PKCS5_Encrypt(const char *input, uint8_t *AES_KEY, uint8_t *AES_IV);

/** AES解密, CBC, PKCS5Padding */
char *AES_128_CBC_PKCS5_Decrypt(const char *input, uint8_t *AES_KEY, uint8_t *AES_IV);

/** AES加密, ECB, PKCS5Padding */
char *AES_128_ECB_PKCS5_Encrypt(const char *input, uint8_t *AES_KEY);

/** AES解密, CBC, PKCS5Padding */
char *AES_128_ECB_PKCS5_Decrypt(const char *input, uint8_t *AES_KEY);


#ifdef __cplusplus
}
#endif


#endif //AESTEST_AES_UTILS_H
