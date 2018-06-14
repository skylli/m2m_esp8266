/*******************************************************************************

    This file is part of the up2p.
    Copyright m2m.com
    All right reserved.

    File:    up2pa.h

    No description

    TIME LIST:
    CREATE  skyli   2014-08-20 20:17:45

*******************************************************************************/
#ifndef _up2pa_crypt_h_
#define _up2pa_crypt_h_

#ifdef __cplusplus
extern "C"{
#endif
#include "../../include/m2m_type.h"
/*
 * 数据加密
 * src 源数据 dst 目标数据 len 源数据长度 key0 key1 密钥
 * 返回加密后的数据长度
 * 如果src不为16字节的整数倍,则补0后加密
 */
int data_enc(const char *src, char *dst, int len, int keylen, u8 *p_key);

/*
 * 数据解密
 * src 源数据 dst 目标数据 len 源数据长度 key0 key1 密钥
 * 返回加密后的数据长度
 * 如果src不为16字节的整数倍,则补0后加密
 */
int data_dec(const char *src, char *dst, int len, int keylen, u8 *p_key);

// crc16 校验计算.
// buf 为需要校验的字符.
// len 位 buf 的长度.
unsigned short crc16_ccitt(const void *buf, int len);
u8 crc8_count(const void* vptr, int len) ;

#ifdef __cplusplus
}
#endif

#endif
