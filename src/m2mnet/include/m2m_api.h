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
#include "../src/network/network.h"
typedef struct {
    size_t net;
    size_t session;
}M2M_T;
typedef struct M2M_CONF_T{
    u8 def_enc_type;
    u8 do_relay;
    m2m_func net_ioctl_func;
    u32 max_router_tm;
    M2M_id_T host_id;
}M2M_conf_T;

// 初始化 m2m
M2M_Return_T m2m_int(M2M_conf_T *p_conf);

// 注销退出
M2M_Return_T m2m_deint(void);

// 创建一个 net
// 一个 net 维护一个 port，同时在一个 net 里可以创建多个 session
size_t m2m_net_creat( M2M_id_T *p_id,int port, int key_len,u8 *p_key,u8 *p_host, int hostport,m2m_func func, void *p_args);

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
M2M_Return_T m2m_broadcast_data_start(Net_T *p_n,int port,int len,u8 *p_data,m2m_func func, void *p_args);

// 停止广播包的发送
M2M_Return_T m2m_broadcast_data_stop(Net_T *p_n);
void m2m_broadcast_enable(Net_T *p_n);
void m2m_broadcast_disable(Net_T *p_n);

#endif  //CONF_BROADCAST_ENABLE
// 发送数据 
M2M_Return_T m2m_session_data_send(M2M_T *p_m2m,int len,u8 *p_data,m2m_func func,void *p_args);

// 重发，接收处理
M2M_Return_T m2m_trysync(size_t net);
M2M_Return_T m2m_dev_online_check(Net_T *p_net, u8 *p_remoteHost, int remote_port, M2M_id_T *p_id, m2m_func func, void *p_args);

// todo
//M2M_Return_T m2m_session_observer(M2M_T *p_m2m,m2m_func func,void *p_args,int len,u8 *p_data);
// 路由


#ifdef __cplusplus
}
#endif

#endif/*_M2M_API_H_*/

