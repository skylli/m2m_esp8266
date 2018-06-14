/*
 * protocol_m2m.h
 * description: m2m protocol declaration file.
 *	Created on: 2018-1-13
 *  	Author: skylli
*/
#ifndef _M2M_ROUTER_H_
#define _M2M_ROUTER_H_
#include "../../../include/m2m_type.h"

typedef struct ROUTER_HDR_T{
    unsigned short version:2;   /* protocol version */
    unsigned short hops:6;
    u8 secret_type;
    u8 msgid;
    u8 crc8;
    u32 stoken;
    M2M_id_T dst_id;
    M2M_id_T src_id;
    u16 payloadlen;
    u8 p_payload[0];
}Router_hdr_T;

#define ROUTER_VER 0

void *relay_list_creat();
void relay_list_destory(void **pp);
int relay_list_add( void **pp,M2M_id_T *p_id,M2M_Address_T *p_addr);
M2M_Address_T *list_addr_find(void *p,M2M_id_T *p_id);
int relay_list_update(void **pp,u32 max_tm);

    
#endif /* _M2M_ROUTER_H_ */
