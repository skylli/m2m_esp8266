/*******************************************************************************

    This file is part of the debug.c.
    Copyright m2m.com
    All right reserved.

    File:    debug.c

    No description

    TIME LIST:
    CREATE  skyli   2017-05-06 13:47:55

*******************************************************************************/
#ifndef _util_h_

#define _util_h_
#include "m2m_type.h"
#include "m2m.h"
/** define tools *****/
#define _RETURN_VOID_EQUAL(n,c)   do{if( n == c ) return;}while(0)
#define _RETURN_VOID_EQUAL_0(n)   _RETURN_VOID_EQUAL(n,0)

#define _RETURN_UNEQUAL(n,c,r)      do{if( n != c ) return r;}while(0)
#define _RETURN_UNEQUAL_0(n,r)      _RETURN_UNEQUAL(n,0,r)
#define _RETURN_UNEQUAL_FREE(n,c,p,r)     do{if( n != c ) {mfree(p);p = NULL;return r;} }while(0)

#define _RETURN_EQUAL(n,c,r)        do{if( n == c ) return r;}while(0)
#define _RETURN_EQUAL_0(n,r)        _RETURN_EQUAL(n,0,r)
#define _RETURN_EQUAL_FREE(n,c,p,r)    do{if( n == c ) {mfree(p);p = NULL;return r;} }while(0)
#define _RETURN_LT_0(n,r)     do{ if( n < 0) return r;} while(0)

// 两个值的相对差
#define DIFF_(a,b)                  (( a>b )?( a-b ):( b-a ))

#define A_BIGER(a,b,large)            ((a>b) ? (1):( (DIFF_(a,b) > large)?1:0 ))
#define A_BIGER_U32(a,b)    A_BIGER(a,b,0x7fffffff)
#define A_BIGER_U16(a,b)    A_BIGER(a,b,0x7fff)
#define A_BIGER_U8(a,b)    A_BIGER(a,b,0x7f)

// 
#define PACKET_FREE(p)   do{ if(p){ \
                                mfree(p->p_data);\
                                mfree(p);         \
                        }}while(0)
// 绝对值的差
#define ABSOLUTE_DIFF(big,little,max)   ((u32)big > (u32)little)?(big - little):( big + (max - little))

#define ALLOC_COPY(d,s,len)     do{ d = mmalloc(len+1);if(d) mcpy(d,s,len);}while(0)

#define MFREE(p)    do{mfree(p); p = NULL;}while(0)
// 转换
#define CHAR_BELONG(c,a,b)  ( a <= c && c <=b)
#define BYTE_IS_HEX(c)   (('0'<= c && c<='9')|| ('a'<=c && c <= 'f') || ('A'<=c && c <= 'F'))
#define CHAR_2_INT(n,c)  n = (CHAR_BELONG(c,'0','9')?(c-'0'):( CHAR_BELONG(c, 'a', 'b')?(c-'a'+10):( CHAR_BELONG(c,'A','F')?(c-'A' + 10):n) ) )
#define STR_2_INT_ARRAY(d,s,len) do{ int i=0; \
                                 for(i=0;i<len;i++){ CHAR_2_INT(d[i],s[i]);} }while(0)
                                    
#ifdef __cplusplus
                                 extern "C"{
#endif
// util  tool
void *mmalloc(size_t size);
int mmemset(u8 *dst,u8 c,size_t n);

void mfree(void *ptr);
void mcpy(u8 *d,u8 *s,int len);

#ifdef __cplusplus
}
#endif

#endif
