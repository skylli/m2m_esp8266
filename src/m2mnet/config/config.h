#ifndef _CONFIG_H
#define _CONFIG_H

/**log define ****/
//#define CONF_LOG_TIME		1
//#define HAS_LINUX_MUTEX	1
/** net thing **/
#define PROTO_VERSION_HDR   (1)
/* platform  **/
#define  PLATFORM_ESP   // esp8266 support.

/* enable broadcast */
#define CONF_BROADCAST_ENABLE 

//#define C_HAS_FILE
#define NOSTDOUTPUT
/** timeout  **/
#define NET_RETRAMIT_TIMOUT_MS  (10000)

// max si
#define M2M_PROTO_PKT_MAXSIZE   (1024)

// max hops 
#define M2M_MAX_HOPS    (20)
// socket receive time out 
#define M2M_SOCKET_RECV_TIMEOUT_MS (500)

/** 应用层 data 部分数据版本 u16 大小**/
#define M2M_BASDATA_VERSION_1   (0X01)
#define M2M_BASDATA_VERSION_2   (0X02)

/*
* define the endian type
*/
#ifndef M2M_LITTLE_ENDIAN
#define M2M_LITTLE_ENDIAN 1
#endif
#define DEFAULT_DEVICE_PORT (9529)
#define DEFAULT_APP_PORT (9528)
#define DEFAULT_SERVER_PORT (9527)
#define DEFAULT_HOST ("192.168.0.196")
#define DEFAULT_INTERVAL_PING_TM_MS  (20*1000)

#define DEFAULT_DEVICE_KEY   "1234567890123456"
#define DEFAULT_SERVER_KEY    "1234560123456789"
#define DEFAULT_APP_KEY       "0123456789023456"

/********* PORT ****************************/
// #define M2M_PORT_TYPE_MXCHIP
// #define M2M_PORT_TYPE_ESP



/********* product *****************************/
/**
**  类型 + 厂家 + 品牌 + 品类 + 产品  + mac
	版本： 1 byte
    类型： 1 byete ： 0 为设备， 1 为APP端，2 为服务端
    厂家： 2 byete： 默认为 0
    品类： 2 byte 为led 灯饰类， 2 为智能家具类
    产品： 4 byte
    产品 mac：  6 byte 
******/

#define ID_VERSION		(0x01)
#define ID_TYPE_SERVER 	(2)
#define ID_TYPE_APP  	(1)
#define ID_TYPE_DEVICE  (0)

#define ID_CLASS_LED	(0x01)
#define ID_CLASS_HOME	(0X02)
#define ID_PRODUCT_LED_SHOWHOME	(0X01)
#define ID_PRODUCT_LED_SHOWHOME	(0X01)

#endif // _CONFIG_H

