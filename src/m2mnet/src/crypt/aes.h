#ifndef _AES_H_
#define _AES_H_

#ifndef ANDROID
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
#endif
#ifdef __cplusplus
extern "C"
{
#endif

void AES128_ECB_encrypt(uint8_t* input, uint8_t* key, uint8_t *output);
void AES128_ECB_decrypt(uint8_t* input, uint8_t* key, uint8_t *output);
#ifdef __cplusplus
}
#endif


#endif //_AES_H_
