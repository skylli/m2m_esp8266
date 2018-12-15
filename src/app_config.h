/* 打印给单片机串口的*/
#ifndef H_APP_CONFIG_H

#define H_APP_CONFIG_H

#include "../config/product_config.h"
#define VERSION  0x55
#define CMD  0x01
#define IDX  0x00
#define LEN  0x01

#define CONNECT_WAIT    0x01
#define CONNECT_FAILED  0x02
//#define CONNECT_WAITCONNECT    0x03
#define CONNECT_SUCCESS 0x04
//#define TURNON_BROADCAST

/********* server configure ***/
/** 设备端 配置 ***********************************************************/
#define TST_DEV_LOCAL_ID    (8)
#define TST_DEV_LOCAL_PORT  PRODUCT_LOCAL_PORT//(9529)
#define TST_DEV_LOCAL_KEY   PRODUCT_KEY//"123"

//#define TST_REMOTE_HOST  ("192.168.0.196")
//#define TST_REMOTE_PORT (9528)

#define TST_SERVER_ID	("00000000000000000000000000000000")
#define TST_SERVER_HOST  (PRODUCT_SERVER_CNAME)//("192.168.0.94")
#define TST_SERVER_PORT (PRODUCT_SERVER_PORT)

#define NOTIFY_INTERVAL_TM 	(10000)  // 定时发送 notify 的时间间隔
#define CHECK_ONLINE_TM 	(10000)  // 检查设备是否在线的时间间隔

#define TST_DEVOBS_NOTIFY_PUS1	("abcd123")
#define TCONF_NOTIFY_DATA1	"notify test data111"

/*************************************************************/

#endif //H_APP_CONFIG_H