/*
 * m2m projuct
 *
 * FileName: m2m_api.c
 *
 * Description: api that provide to thrid party applications.
 *
 * Author: skylli
 */
#include "../include/m2m.h"
#include "../include/m2m_app.h"

#include "../include/util.h"
#include "../config/config.h"

#include "../include/m2m_log.h"

#ifdef __cplusplus
extern "C"
{
#endif
int wifi_decode(u8 **pp_dst, u8 *p_cmd, u16 slen, u8 *p_src){
    Lm2m_data_T *p = NULL;

    if(slen < sizeof(Lm2m_data_T) || !p_src || !pp_dst ||!p_cmd)
        return 0;
    
    p = (Lm2m_data_T*) p_src;
    if( p->ver != WIFI_S_VERSION)
        return 0;

    *p_cmd = p->cmd;
    *pp_dst = p->data;
    
    return (int)p->len;
}

int wifi_decode1(u8 **pp_dst, u8 *p_cmd, u16 slen, u8 *p_src){
    WIFI_PACKET1 *p = NULL;

    if(slen < sizeof(WIFI_PACKET1) || !p_src || !pp_dst ||!p_cmd)
        return 0;
    
    p = (WIFI_PACKET1*) p_src;
    if( p->version != WIFI_S_VERSION1)
        return 0;

    *p_cmd = p->cmd;
    *pp_dst = p->payload;
    
    return (int)p->len;
}


#ifdef __cplusplus
}
#endif



