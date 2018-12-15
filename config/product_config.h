/****
 *  产品层面的配置， 设置 产品 id， 品类， 默认服务器地址以及端口， 本地设备端口， 默认会话秘钥
 * ***/
#ifndef H_PRODUCT_CONFIG_H
#define H_PRODUCT_CONFIG_H

/*品类*/
#define PRODUCT_CLASS (0x01) 
/* 产品 id */
#define PRODUCT_ID (0X02)
/*服务器 ID*/
#define PRODUCT_SERVER_ID ("00000000000000000000000000000000")
/*服务器 地址*/
#define PRODUCT_SERVER_CNAME ("192.168.0.196")
/*服务器端口*/
#define PRODUCT_SERVER_PORT   (9528)
/*本地端口*/
#define PRODUCT_LOCAL_PORT  (9529)
/*会话秘钥*/
#define PRODUCT_KEY ("123")

#endif
