
#ifndef _M2M_PORT_H_
#define _M2M_PORT_H_

#ifdef __cplusplus
extern "C"
{
#endif


#include "m2m_type.h"

int m2m_gethostbyname(M2M_Address_T* addr,char* host);
int m2m_openSocket(int* socketId,u16 port);
int m2m_closeSocket(int socketId);
int broadcast_enable(int socket_fd);
int get_bcast_list(u32 *list, int maxlen);

int m2m_send
    (
    int socketId,
    M2M_Address_T* addr_in,
    void* tosend,
    s32 tosendLength
    );

/*
 * return <0 have not receive anything >=0 the length，it is a blocked function.
 */
int m2m_receive
    (
    int socketId,
    M2M_Address_T* addr,
    void* buf,
    s32 bufLen,
    s32 timeout
    );
u32 m2m_current_time_get(void);
u32 m2m_get_random();
#ifdef __cplusplus
}
#endif


#endif/*_M2M_PORT_H_*/

