/*
 * network.h
 * description: handle connetion,socket
 *  Created on: 2018-1-13
 *      Author: skylli
 */

#ifndef _NETWORK_H_
#define _NETWORK_H_
#include "../../include/m2m.h"
#include "m2m/m2m_protocol.h"

#ifdef HAS_LINUX_MUTEX
#include <pthread.h>
#endif // HAS_LINUX_MUTEX

#define INTERVAL_PING_TM_MS    DEFAULT_INTERVAL_PING_TM_MS 
/** struct ***
* 1. 等待 ack 认领节点队列。
* 2. ping，接收节点独立一个队列。
* 3. 线程安全，所有队列需要加锁,可以实现在不同线程处理接收和重发。
* 4. 重发管理.
* 5. 发送缓存，解决一次发送多个包产生拥堵的问题。(服务器需要)。
****/
typedef struct M2M_REQUEST_PKT_T{

    struct M2M_REQUEST_PKT_T *next;
    
    u8 messageid;
    u8 transmit_count;
    
    M2M_Proto_Cmd_T cmd;
    u32 next_send_time;
    u32 register_time;
    
    u16 len;
    Func_arg callback_arg;
    u8 *p_proto_data;
    
}M2M_request_pkt_T;


typedef struct NET_REQUEST_NODE_T{

    struct NET_REQUEST_NODE_T *next;
    
    M2M_Proto_Cmd_T cmd;
    u8 retransmit_count;

    u32 next_send_time;
    u32 stoken; //idetify eatch packet.
    
    Net_enc_T enc;
    M2M_Address_T remote;

    Func_arg callback_arg;
    M2M_packet_T payload;
}Net_request_node_T;

// 接收包的数据结构
typedef enum SESSION_TYPE_T{
    SESSION_TYPE_MASTER,
    SESSION_TYPE_SLAVE,
    SESSION_TYPE_MAX
}Session_TYPE;
/*************
session 数据结构
*************/
typedef struct SESSION_T{

    struct SESSION_T *next;
    
    Session_TYPE    type;

    u8 *p_host;
    M2M_id_T dst_id;
    M2M_Address_T dest_addr;

    u32 stoken;
    u32 ctoken;
    u8 messageid;
    u8 sending_id;
    u8 keep_ping_en;
    Net_enc_T enc;

    M2M_session_Sta state;
    M2M_Protocol_T protocol;

    u32 next_ping_send_tm;   // 下一个 ping time.
    u32 last_alive_tm;      // 最近收发包的时间。
    
    M2M_request_pkt_T *p_request_head;
    
}Session_T;
typedef enum M2M_NET_CMD_T{

    M2M_NET_CMD_SESSION_CREAT = 0,
    M2M_NET_CMD_SESSION_DESTORY,
    M2M_NET_CMD_SESSION_TOKEN_UPDATE,
    M2M_NET_CMD_SESSION_SECRETKEY_SET,
    M2M_NET_CMD_SESSION_DATA_SEND,
    M2M_NET_CMD_SESSION_PING_SEND,

#ifdef CONF_BROADCAST_ENABLE
    M2M_NET_CMD_BROADCAST_START,  // 开始 广播包
    M2M_NET_CMD_BROADCAST_STOP,
#endif //CONF_BROADCAST_ENABLE

    M2M_NET_CMD_TRYSYNC,
    M2M_NET_CMD_ONLINE_CHECK,
    
    M2M_NET_CMD_MAX
    
}M2M_Net_Cmd_T;
typedef struct  NET_INIT_ARGS_T{
    M2M_id_T my;
    M2M_id_T host_id;
    
    Net_enc_T enc;
    u8 *p_host;
    
    u8 relay_en;
    u16 port;
    u16 hostport;
    u32 max_router_tm;
    Func_arg func_arg;
    
}Net_Init_Args_T;
typedef struct NET_HOST_T{

    M2M_id_T host_id;
    u8 *p_host;
    void *p_router_list;
    M2M_Address_T addr;

    u8 keep_ping_host_en;// 持续向 host 发送 ping包.
    u8 relay_en;
    u8 msgid;
    u8 retransmit_count;
    u32 stoken;
    u32 next_ping_tm;
}Net_host_T;
/*
* 1. 二维链表结构，每次创建一个 session 建立一个子链表。
* 2.接收数据处理时，先根据 ctoken 确定子链表，再根据 message id 确定节点。
*
*   heard ---> token1 ---> token2 ---> token3
*                |           |          |
*                node       node       node
*                |           |          |
*                node       node        node  
**/
typedef struct NET_T{

    Session_T *p_session_head;
    M2M_Protocol_T protocol;
    m2m_func ioctl_session;
    Func_arg func_arg;
    M2M_id_T my;
    Net_enc_T enc;
    
    Net_request_node_T *p_request_hd;    // 所有的广播包.
    u8 broadcast_en;
    size_t key_addr; // 秘钥保存的索引.
    u16 stoken_index;
    u16 ctoken_index;
    u32 max_router_tm;
    
#ifdef HAS_LINUX_MUTEX
    pthread_mutex_t locker;
#endif
    Net_host_T host;
    
}Net_T;

typedef struct NET_REMOT_ADDRESS_T{
    u8 *p_host;
    M2M_Address_T dst_address;
}Net_Remot_Address_T;
typedef struct  NET_ARGS_T{
    Net_T *p_net;       // 一个 net 监听一个 port，可以维护多个 session。
    Session_T *p_s;     // 当前 session.
    M2M_id_T remote_id;
    Net_Remot_Address_T remote;
    Net_enc_T enc;
    Func_arg callback;
    
    u16 len;
    void *p_data;
}Net_Args_T;


Net_T *net_creat( Net_Init_Args_T *p_arg,int flags);
M2M_Return_T net_destory(Net_T *p_net);
 
#endif /* _NETWORK_H_ */
