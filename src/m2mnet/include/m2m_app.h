
#ifndef _M2M_APP_H_
#define _M2M_APP_H_

#ifdef __cplusplus
extern "C"
{
#endif
#include "m2m_type.h"

typedef enum{
	WIFI_CMD_NONE = 0X00,
	WIFI_CMD_SYS_VERSION_RQ   = 0x01,   // 查询版本号

	WIFI_CMD_SYS_RELAYHOST_SET_RQ,     // 设置 中转服务器地址9

	WIFI_CMD_ROUTER_CONF,        //设置AP模式的用户名与密码

	WIFI_CMD_SYS_REBOOT_RQ, 	// 重新启动
    WIFI_CMD_SYS_OTA_UPDATE_RQ,        // 直接更新 wifi 固件7
    WIFI_CMD_SYS_BROADCASTSETTING_RQ, // 设置模块是否接受广播包.
	
    //WIFI_CMD_TO_CONNECT   ,         	//直接连接一个特定的WIFI
    WIFI_CMD_APP_UART_SEND_RQ = 0x50,  // 串口透传.
    WIFI_CMD_APP_LED_TWINKLE_RQ = 0x61,  // supper twinkle.
    
    
    WIFICMD_MAX
}WIFI_CMD;


typedef struct WIFI_PACKET{
    u8 version;     // 验证数,表示协议和协议版本，目前是 0x01
    u8 cmd;         // 命令类型
    u8 idx;			// 序号, 预留
    u8 len;         // 数据长度
    char payload[0];// 数据
} Wifi_pkt;



typedef struct UART_PACKET{
	u8 version; 	 // 验证数,表示协议和协议版本，目前默认是 0x55
	u8 cmd; 		 // 命令类型
	u8 idx; 		// 序号, 预留给 sensor 使用
	u8 len; 		// 数据长度
	char payload[0];   // 数据
} Uart_pkt;


#define WIFI_S_VERSION  (0x01)
#define WIFI_S_VERSION1  (0x01)


int wifi_decode(u8 **pp_dst, u8 *p_cmd, u16 slen, u8 *p_src);


#ifdef __cplusplus
}
#endif


#endif/*_M2M_APP_H_*/

