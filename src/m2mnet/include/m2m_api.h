/*
 * m2m projuct
 *
 * FileName: m2m_api.h
 *
 * Description: api that provide to thrid party applications.
 *
 * Author: skylli
 */

#ifndef _M2M_API_H_
#define _M2M_API_H_

#ifdef __cplusplus
extern "C"
{
#endif
#include "m2m.h"
#include "m2m_type.h"
//#include "../src/network/network.h"
typedef struct {
    size_t net;
    size_t session;
}M2M_T;
typedef struct M2M_CONF_T{
    u8 def_enc_type;  // 秘钥的类型，默认使用 M2M_ENC_TYPE_AES128
    u8 do_relay;	 // 是否支持中转，若开启该功能则需要实现中转函数，只有服务的需要打开该功能。	
	u8 *p_version;	// 版本号，必须释放
	Func_arg cb;	//  仅仅在 python 用于释放资源。
    u32 max_router_tm;
}M2M_conf_T;

// 获取该库的版本号
u8 *m2m_version(void);
// 初始化 m2m
M2M_Return_T m2m_int(M2M_conf_T *p_conf);

// 注销退出
M2M_Return_T m2m_deint(void);

// 创建一个 net
// 一个 net 维护一个 port，同时在一个 net 里可以创建多个 session
size_t m2m_net_creat( M2M_id_T *p_id,int port, int key_len, u8 *p_key, M2M_id_T *p_hid,u8 *p_host, int hostport,m2m_func func, void *p_args);

// 销毁 net
M2M_Return_T m2m_net_destory(size_t net);

// 在 net 里创建一个会话
// 返回一个 session。
size_t m2m_session_creat(size_t net,M2M_id_T *p_id,u8 *p_host,int port, int key_len,u8 *p_key, m2m_func func, void *p_args);

// 销毁 session
M2M_Return_T m2m_session_destory(     M2M_T *p_m2m );

// 申请刷新 session token
M2M_Return_T m2m_session_token_update(M2M_T *p_m2m,m2m_func func, void *p_args);

// 更新会话秘钥
M2M_Return_T m2m_session_secret_set(M2M_T *p_m2m,int len,u8 *p_data,m2m_func func,void *p_args);

#ifdef CONF_BROADCAST_ENABLE
// 开启不断发送广播包.
M2M_Return_T m2m_broadcast_data_start(size_t p_n,int port,int len,u8 *p_data,m2m_func func, void *p_args);

// 停止广播包的发送
M2M_Return_T m2m_broadcast_data_stop(size_t p_n);
void m2m_broadcast_enable(size_t p_n);
void m2m_broadcast_disable(size_t p_n);

#endif  //CONF_BROADCAST_ENABLE
// 发送数据 
M2M_Return_T m2m_session_data_send(M2M_T *p_m2m,int len,u8 *p_data,m2m_func func,void *p_args);

// 重发，接收处理
M2M_Return_T m2m_trysync(size_t net);
M2M_Return_T m2m_event_host_offline(size_t net);

M2M_Return_T m2m_dev_online_check(size_t p_net, u8 *p_remoteHost, int remote_port, M2M_id_T *p_id, m2m_func func, void *p_args);
BOOL m2m_session_connted(M2M_T *p_m2m);
BOOL m2m_net_connted(size_t p);
M2M_Return_T m2m_net_secretkey_set(size_t net,M2M_id_T *p_id,u8 *p_host,int port, int key_len,u8 *p_key,int newkey_len, u8 *p_newkey,m2m_func func, void *p_args);

// observer 数据发送 
/*****************************************************
** description: start observer
** args:
**      1. p_m2m - 发送 observer 请求的 net/session。
**      2. p_len - 数据的长度.  p_data - 数据.
**      2. p_user_func - 接收到对端响应时触发的回调函数.
** return: 本地发送是否成功.
*****************************************************/
size_t  m2m_session_observer_start(M2M_T *p_m2m,Pkt_ack_type_T ack_type,int len,u8 *p_data,m2m_func func, void *p_args);

/*****************************************************
** description: stop observer
** args:
**      1. p_m2m - 发送 observer 请求的 net/session。
**      2. p_obserindex: observer 节点的指针
**      2. p_user_func - 接收到对端响应时触发的回调函数.
** return: 本地发送是否成功.
*****************************************************/
M2M_Return_T m2m_session_observer_stop(M2M_T *p_m2m, void *p_obserindex);
/*****************************************************
** description: push an notify to observer
** args:
**      1. p_m2m - 发送 observer 请求的 net/session。
**		2. len: 推送数据的长度； p_data: 推送的数据;
**      2. p_obserindex: observer 节点的指针
**      2. p_user_func - 接收到对端响应时触发的回调函数.
** return: 本地发送是否成功.
*****************************************************/
M2M_Return_T m2m_session_notify_push(M2M_T *p_m2m, void *p_obserindex,int len,u8 *p_data,m2m_func func, void *p_args);


// todo
//M2M_Return_T m2m_session_observer(M2M_T *p_m2m,m2m_func func,void *p_args,int len,u8 *p_data);
// 路由
/** callback sample api *******************************************************************************/
/*****************************************************
** description: handle notify callback function.
** args:
**      1. code:	M2M_REQUEST_NOTIFY_PUSH - receive an new notify.
**				 	M2M_REQUEST_NOTIFY_ACK - notify push ack.
**      2. pp_ack_data - ack to the remoter witch have been push the notify.
**      2. p_robs - include receive payload and pointer that deal with the notify.
** 
*****************************************************/
void sample_notify_handle_callback(int code,M2M_packet_T **pp_ack_data,M2M_obs_payload_T *p_robs, void *p_arg);
/*****************************************************
** description: 除非特别指明，否则 m2m 均会以该形式为回调函数的格式。
** args:
**      1. code:	
**      2. pp_ack_data - 输出用，指向包含 ack 的数据，sdk 底层发出 ack 后会释放该结构。
**      2. p_recv_pkt - 接受的数据，应用层无需释放.
** 
*****************************************************/
void sample_normal_callback(int code,M2M_packet_T **pp_ack_pkt, M2M_packet_T *p_recv_pkt,void *p_arg);

#ifdef __cplusplus
}
#endif

#endif/*_M2M_API_H_*/

