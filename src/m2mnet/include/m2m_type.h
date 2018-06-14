/*
 * m2m_type.h
 * description: type declaration. 
 *  Created on: 2018-1-13
 *      Author: skylli
 */
#ifndef _type_h_
#define _type_h_

#ifdef      __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stddef.h>


#ifndef WD_SYSTEM
#define WD_SYSTEM
#endif

#ifndef STATIC
#define STATIC static
#endif


#ifndef INLINE
#define INLINE __inline__
#endif

#ifndef VOLATILE
#define VOLATILE volatile
#endif

#if __x86_64__ || __LP64__
#pragma message("In 64Bit machine \n")

#ifndef s8
typedef char s8;
#endif
typedef unsigned char u8;
typedef signed short  s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;

#else

#pragma message("In 32Bit machine \n")

// 基本类型

#ifndef s8
typedef  signed char s8;
#endif

#ifndef u8
typedef unsigned char u8;
#endif

#ifndef s16
typedef signed short s16;
#endif

#ifndef u16
typedef unsigned short u16;
#endif

#ifndef s32
typedef signed int s32;
#endif 

#ifndef u32 
typedef unsigned int u32;
#endif
#endif // 32 bit or 64 bit


    
#ifndef TRUE
#define TRUE (1==1)
#endif
#ifndef FALSE
#define FALSE (1==0)
#endif
#ifndef BOOL
#define BOOL int
#endif

typedef size_t (*m2m_func)();



#ifdef __cplusplus
}
#endif

#endif /* _type_h_ **/
