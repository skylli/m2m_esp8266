/*
 * port_esp.c
 * description: esp socket
 *  Created on: 2018-6-9
 *      Author: skylli
 * Time list:
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Arduino.h"
#include <ArduinoOTA.h>
#include "osapi.h"
#include "ets_sys.h"
#include "lwip/inet.h"

#include <stdbool.h>
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>

#include "../../include/m2m.h"
#include "../../include/util.h"

#include "../../src/util/m2m_log.h"
#include "../../src/network/m2m/m2m_endian.h"

#define SYSTIMERUIN      1000  //系统时间单位s

/* c interface */
extern "C" int m2m_gethostbyname(M2M_Address_T* addr,char* host);
extern "C" int m2m_openSocket(int* socketId, u16 port);
extern "C" int m2m_closeSocket(int socketId);
extern "C" int m2m_send(int socketId,M2M_Address_T* addr_in,void* tosend,s32 tosendLength);
extern "C" int m2m_receive(
    int socketId,
    M2M_Address_T* p_src_addr,
    void* buf,
    s32 bufLen, 
    s32 timeout);
extern "C" int m2m_receive_filt_addr
    (
    int socketId,
    M2M_Address_T* addr,
    void* buf,
    s32 bufLen, 
    s32 timeout
    );
extern "C" u32 m2m_current_time_get(void);
extern "C" u32 m2m_get_random();
extern "C" int broadcast_enable(int socket_fd);
extern "C" int get_bcast_list(u32 *list, int maxlen);
extern "C" u8 *getlocal_ip(void);
extern "C" void local_ip_save(void);
/* environment static value*/
static WiFiUDP Udp;

// 获取 host 的ip。
u32 dns_ip(const char *sname)
{
    struct hostent *host;
    u32 host_ip = 0;
    IPAddress hostip;
    if(WiFi.hostByName(sname, hostip))
    {
		host_ip = hostip;
    }
    else
    {
        host_ip = inet_addr(sname);
    }

    if(host_ip == 0xFFFFFFFF)
    {
        m2m_debug_level(M2M_LOG_ERROR,"link server error");
        host_ip = 0;
    }

    return host_ip;
}

/*
 * Function:    m2m_gethostbyname
 * Description: it use the interface in posix.
 * Input:        host: The pointer of host string.
 * Output:      addr: The pointer of the M2M_Address_T.
 * Return:      If success, return 0; else return -1.
*/
int m2m_gethostbyname(M2M_Address_T* addr,char* host)
{

    u32 ip=0;
    if( !host)
        return M2M_ERR_INVALID;
    
    ip = dns_ip(host);
    addr->len = sizeof(u32);
    mcpy(addr->ip,(u8*)&ip, sizeof(u32));
    m2m_debug_level(M2M_LOG,"host: %s ip is %d.%d.%d.%d \n",host,addr->ip[0],addr->ip[1],addr->ip[2],addr->ip[3]);

    return 0;
}
/* 
 * Function:    m2m_openSocket
 * Description: m2m_openSocket it use the interface in posix.
 * Input:        N/A
 * Output:      socketId: The pointer of socket id.
 * Return:      If success, return 0; else return -1.
*/
int m2m_openSocket(int* socketId, u16 port)
{
 	//listen port
	if(  Udp.begin(port) == 0) {
		m2m_debug_level(M2M_LOG_ERROR, "udp listen bind failt !! no sockets available to use");
		delay(3000);
        return M2M_ERR_SOCKETERR;
	}
	else m2m_debug_level(M2M_LOG,"udp listen to %d successfully",port);

    *socketId = (int) port;
    return 0;
}

/*
 * Function:    m2m_closeSocket
 * Description: it use the interface in posix.
 * Input:        socketId: The socket id.
 * Output:      N/A
 * Return:      If success, return 0; else return -1.
*/
int m2m_closeSocket(int socketId)
{
    Udp.stop();
    return 0;
}

/*
 * Function:  m2m_send
 * Description: send function, it use the interface in posix.
 * Input:        socketId: The socket id.
 *                  addr_in:  The pointer of M2M_Address_T
 *                  tosend: The pointer of the send buffer
 *                  tosendLength: The length of the send buffer.
 * Output:      N/A
 * Return:      If success, return the sended number. else return -1.
*/
int m2m_send
    (
    int socketId,
    M2M_Address_T* addr_in,
    void* tosend,
    s32 tosendLength
    )
{
	int ret = M2M_ERR_SOCKETERR;

	//send back a reply, to the IP address and port we got the packet from
    if(!Udp.beginPacket(addr_in->ip, addr_in->port))
		  return M2M_ERR_SENDERR;
    
	// write it
    ret = Udp.write((u8*)tosend,tosendLength);
    
	// send it
    if(Udp.endPacket())
		  return ret;
    m2m_debug_level(M2M_LOG_DEBUG, \
                    "## socket %d send to addr_in->port = %d, ip = %u.%u.%u.%u", \
                    socketId,addr_in->port, addr_in->ip[0], \
                    addr_in->ip[1], addr_in->ip[2], \
                    addr_in->ip[3]);
    return tosendLength;//M2M_ERR_SENDERR;
}
    

/*
 * Function:    m2m_receive_
 * Description:  receive function, it use the interface in posix.
 * Input:        socketId: The socket id.
 *                  addr:  The pointer of M2M_Address_T
 *                  buf: The pointer of the send buffer
 *                  bufLen: The length of the send buffer.
 *                  timeout: The max timeout in recv process.
 * Output:      N/A
 * Return:      If success, return the number of bytes received; else return -1.
*/
int m2m_receive
    (
    int socketId,
    M2M_Address_T* p_src_addr,
    void* buf,
    s32 bufLen, 
    s32 timeout
    )
{
    u32 rip;
    u8 *p_buf = NULL;
	if(!buf || !bufLen )
		return -1;
    p_buf = (u8*)buf;
	// receive incoming UDP packets
	int packetSize = Udp.parsePacket();
	if(packetSize <= 0)
		return packetSize;
	
    m2m_debug_level(M2M_LOG_DEBUG, "Received %d bytes from %s, port %u\n", packetSize, Udp.remoteIP().toString().c_str(), Udp.remotePort());
	//read receive byte.
    int read_len = Udp.read((char*)buf, bufLen);
    if (read_len > 0)
    {
      p_buf[read_len] = 0;
    }
	
	rip = Udp.remoteIP();
	p_src_addr->port = Udp.remotePort();
    mcpy(p_src_addr->ip, (u8*)&rip, sizeof(u32));

    m2m_debug_level_noend(M2M_LOG_DEBUG, "socket %d received %d bytes from  %d.%d.%d.%d  prot %d\n", socketId,read_len,\
            p_src_addr->ip[0],p_src_addr->ip[1],p_src_addr->ip[2],p_src_addr->ip[3],p_src_addr->port);
    
    return read_len;
}
#if 0
/*
 * Function:    m2m_receive
 * Description:  receive function, it use the interface in posix.
 * Input:        socketId: The socket id.
 *                  addr:  The pointer of M2M_Address_T
 *                  buf: The pointer of the send buffer
 *                  bufLen: The length of the send buffer.
 *                  timeout: The max timeout in recv process.
 * Output:      N/A
 * Return:      If success, return the number of bytes received; else return -1.
*/
int m2m_receive_filt_addr
    (
    int socketId,
    M2M_Address_T* addr,
    void* buf,
    s32 bufLen, 
    s32 timeout
    )
{
    struct sockaddr_in remaddr;
    socklen_t addrlen = sizeof(remaddr);
    int recvlen;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = timeout*1000;

    setsockopt(socketId, SOL_SOCKET, SO_RCVTIMEO, \
               (char *)&tv,sizeof(struct timeval));

    recvlen = recvfrom(socketId, buf, bufLen, 0, \
                       (struct sockaddr *)&remaddr, &addrlen);
    if(recvlen < 0)
    {
        return -1;
    }
    if(memcmp(addr->ip, &remaddr.sin_addr.s_addr, addr->len) || \
        m2m_ntohs(remaddr.sin_port) != addr->port)
    {
        m2m_debug_level(M2M_LOG_WARN,"ip or port not match!");
        return -1;
    }
    else
    {
        m2m_debug_level(M2M_LOG_WARN, "received %d bytes",recvlen);
    }
    return recvlen;
}
#endif
// 获取系统时间
u32 m2m_current_time_get(void)
{
    return ( millis());
}
u32 m2m_get_random(){
	return (u32)os_random();
}

int broadcast_enable(int socket_fd){
    return 0;
}
int get_bcast_list(u32 *list, int maxlen)
{
  return 0;
}
static u8 local_ip[32];
void local_ip_save(void){
    mmemset(local_ip, 0, 32);
    sprintf((char*)local_ip,"%u.%u.%u.%u",WiFi.localIP()[0],WiFi.localIP()[1],WiFi.localIP()[2],WiFi.localIP()[3]);
    printf("local ip %s\n", (char*)local_ip);
}
u8 *getlocal_ip(void){
    return local_ip;
}

