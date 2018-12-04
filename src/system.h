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

# if 0
#include "Arduino.h"
#include "osapi.h"
#include "ets_sys.h"
#include "lwip/inet.h"

#include <stdbool.h>
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#endif

#ifndef _FUNCTION_H
#define _FUNCTION_H

#ifdef __cplusplus
extern "C"{
#endif
#include "m2mnet/include/m2m_type.h"

typedef enum SYS_CNN_STATUS{

	SYS_CNN_CONFIGING_STA,
	SYS_CNN_CONFIGING_AP,
	SYS_CNN_LOST_CONNECT,
	SYS_CNN_OFFLINE,
	SYS_CNN_ONLINE,
	SYS_CNN_MAX
}SYS_cnn_status;
typedef struct SYS_HOST_INFO{
	u16 port;
	u16 len;
	u8 cname[0];
}SYS_Host_info_t;

void sys_setup(void);
void sys_factory_reset(void);
int sys_smartconfig_auto_connet(void);
void sys_sta_smartconfig(void);
void local_ip_save(void);
int sys_ssid_pw_reset(LM2M_router_conf *p_router);
SYS_cnn_status sys_connect_status_hanle(size_t net);
int sys_cmd_handle(u8 cmd,u8*p_data,int recv_len);
SYS_Host_info_t *sys_host_creat(void );

#ifdef __cplusplus
}
#endif


#endif // _FUNCTION_H

