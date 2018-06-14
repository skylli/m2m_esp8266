
#ifndef _WILDDOG_ENDIAN_H_
#define _WILDDOG_ENDIAN_H_

#ifdef __cplusplus
extern "C"
{
#endif

#if M2M_LITTLE_ENDIAN == 1
#define __WD_SWAP32__(val) ( (u32) ((((val) & 0xFF000000) >> 24 ) | \
    (((val) & 0x00FF0000) >> 8) \
             | (((val) & 0x0000FF00) << 8) | (((val) & 0x000000FF) << 24)) )

#define __WD_SWAP16__(val) ( (u16) ((((val) & 0xFF00) >> 8) | \
    (((val) & 0x00FF) << 8)))

#ifndef m2m_htonl
#define m2m_htonl(val)  __WD_SWAP32__(val)
#endif /*htonl */
#ifndef m2m_ntohl
#define m2m_ntohl(val)  __WD_SWAP32__(val)
#endif /* htonl */

#ifndef m2m_htons
#define m2m_htons(val)  __WD_SWAP16__(val)
#endif /*htons */

#ifndef m2m_ntohs
#define m2m_ntohs(val)  __WD_SWAP16__(val)
#endif /*htons */

#else
    
#ifndef m2m_htonl
#define m2m_htonl(val) (val) 
#endif /* htonl */
#ifndef m2m_ntohl
#define m2m_ntohl(val)  (val)
#endif /* htonl */

#ifndef m2m_htons
#define m2m_htons(val)  (val)
#endif /*htons */

#ifndef m2m_ntohs
#define m2m_ntohs(val)  (val)
#endif /*htons */

#endif

#ifdef __cplusplus
}
#endif

#endif /*_WILDDOG_ENDIAN_H_*/

