/*
 * network.h
 * description: handle connetion,socket
 *  Created on: 2018-1-13
 *      Author: skylli
 */
#include <string.h>
#include "network.h"
#include "../../include/m2m_port.h"
#include "../../include/util.h"
#include "../../include/utlist.h"
#include "../../include/app_implement.h"
#include "../../include/m2m_port.h"

#include "../../config/config.h"
#include "../../include/m2m_log.h"
#include "m2m/m2m_protocol.h"

#ifdef HAS_LINUX_MUTEX
#include <pthread.h>
#endif // HAS_LINUX_MUTEX


/***** network setting ..**************************************/
#define _MAX_SESSION_IDLE_TIME_MS   (6*60*1000)

#define _RETRANSMIT_DEFAULT_INTERVAL (1) 
// 连续 发送 _OBSERVER_MAX_LOST 个包均没有收到回应，认为该 observer 被弃用，需要回收.
#define _OBSERVER_MAX_LOST	(10)
#define _NOTIFY_RETRANSMIT_CNT_MAX	(2)
//#define _OBSERVER_LOST_MAX	(3*_NOTIFY_RETRANSMIT_CNT_MAX)

/** Define ****************************************************/
typedef enum _OBS_TYPE_T{
	OBS_TYPE_OFF = 0X00,
	OBS_TYPE_ON = 0X01,
	OBS_TYPE_MAX,	
}_Obs_type_T;

typedef enum _EXTRA_CMD_T{
	EXTRA_CMD_NONE	= 0X00,
	EXTRA_CMD_OBSERVER = 0X01,
	EXTRA_CMD_NOTIFY = 0X02,
	EXTRA_CMD_OBSERVER_MAX,	
}_Extra_cmd_T;

#define _PROTO_CMD_CREAT(p_s,cmd,p_args) do{                                             \
                mmemset( (u8*)&cmd,0,sizeof(M2M_Proto_Cmd_Arg_T));                       \
                cmd.socket_fd = p_args->p_net->protocol.socket_fd;                       \
                mcpy( (u8*)&cmd.address, (u8*)&p_s->dest_addr,sizeof(M2M_Address_T));    \
                cmd.p_enc = &p_s->enc;                                                   \
                cmd.stoken = p_s->stoken;                                                \
                cmd.ctoken = p_s->ctoken;                                                \
                cmd.messageid  = _session_messageid_increase(p_s);                           \
                cmd.payloadlen = p_args->len;                                            \
                cmd.p_payload  = p_args->p_data;                                         \
                mcpy( (u8*)&cmd.src_id, (u8*)&p_args->p_net->my,ID_LEN);          \
                mcpy( (u8*)&cmd.dst_id,(u8*) &p_s->dst_id,ID_LEN);      \
            }while(0)                                                                         

#define ENC_COPY(denc,senc) do{                                     \
                denc.type = senc.type;                    \
                denc.keylen = senc.keylen;                        \
                if( denc.keylen > 0 && senc.p_enckey)           \
                mcpy( (u8*)denc.p_enckey, (u8*)senc.p_enckey,senc.keylen); \
            }while(0)
            
#define ENC_ALLOC_COPY(denc,senc) do{                                     \
                                    denc.type = senc.type;                    \
                                    denc.keylen = senc.keylen;                        \
                                    if( denc.keylen > 0 && senc.p_enckey ){           \
                                        denc.p_enckey = mmalloc(denc.keylen +1);         \
                                        if( denc.p_enckey ) \
                                            mcpy( (u8*)denc.p_enckey, (u8*)senc.p_enckey,senc.keylen);\
                                        }   \
                                }while(0)
                                
#define PENC_ALLOC_COPY(pdenc,psenc) do{                                  \
                    pdenc->type = psenc->type;                    \
                    pdenc->keylen = psenc->keylen;                        \
                    if(pdenc->keylen && psenc->p_enckey){                  \
                        pdenc->p_enckey = mmalloc(psenc.keylen + 1);            \
                        if( pdenc->p_enckey)                                 \
                            mcpy( (u8*)pdenc->p_enckey, (u8*)psenc->p_enckey,psenc->keylen);}\
                }while(0)
#define _ACK_HEAD_FULL( p_ack, p_raw) do{    mcpy((u8*)&p_ack->remote_addr, (u8*)&p_raw->remote,sizeof(M2M_Address_T) ); \
                                CPY_DEV_ID( p_ack->src_id,p_raw->dst_id );    \
                                CPY_DEV_ID(p_ack->dst_id,p_raw->src_id);  \
                                p_ack->ctoken = p_raw->ctoken;            \
                                p_ack->stoken = p_raw->stoken;\
                                p_ack->socket_fd = p_raw->socket_fd;\
                                p_ack->msgid = p_raw->msgid;}while(0)
                                
#define _SESSION_HAS_TOKEN(p_s) ( p_s->state == M2M_SESSION_STA_HAS_TOKEN )
#define _SESSION_STA_SET_TOKEN(p_s) ( p_s->state = M2M_SESSION_STA_HAS_TOKEN )
#define _PING_INTERVAL_TM   ( m2m_current_time_get() + INTERVAL_PING_TM_MS)
// todo we need better practices.
#define _SESSION_NODE_CAN_SEND(p_s,id_tosend)	(TRUE)// ( p_s->sending_id == id_tosend )
#define _ROUTER_LIST_ADD_DEVICE(p_net,p_raw)   do{  if( p_net->host.relay_en){\
                                                    m2m_relay_list_add( &p_net->host.p_router_list, &p_raw->src_id, &p_raw->remote);\
                                                 }}while(0)
// #define _SESSION_NODE_CAN_SEND(p_s,id_tosend) (1 )
#define _USERFUNC_(p_node,p_recv,ret) do{ if(p_node->callback_arg.func){    \
                ret = p_node->callback_arg.func((int)p_recv->code, NULL, &p_recv->payload,p_node->callback_arg.p_user_arg); \
            } }while(0)
#define NODE_CMD_NOT_AUTH(cmd) ( cmd == M2M_PROTO_CMD_TOKEN_RQ || cmd == M2M_PROTO_CMD_PING_RQ )
#define _SESSION_NODE_CNT_REDUCE(p_s)	(p_s->node_cnt = (p_s->node_cnt > 0)?(p_s->node_cnt -1):0)

static M2M_request_pkt_T *_net_session_node_find(Session_T *p_s,u8 msgid);
M2M_Return_T net_destory(Net_T *p_net);
static M2M_Return_T session_destory(Net_Args_T *p_a,int flag);

static Net_request_node_T *net_request_packet_find(Net_request_node_T *p_hd, u32 stoken);
static M2M_Return_T net_request_retransmit(Net_T *p_net);
static M2M_Return_T broadcast_recv_handle
    (   Net_T *p_net,
        M2M_proto_recv_rawpkt_T *p_raw);
static M2M_Return_T net_request_packet_destory(Net_request_node_T **pp_node );
static M2M_Return_T _obs_free(M2M_observer_T **pp_obs);

static M2M_Return_T net_ack(	u16 code,M2M_Proto_Ioctl_Cmd_T ioc_cmd, m2m_func proto_func, 
								Net_enc_T *p_enc, M2M_proto_recv_rawpkt_T *p_recv,M2M_packet_T *p_payload,void *p_extra);

static M2M_Return_T obs_is_belong(Session_T *p_s, M2M_request_pkt_T *p_obs);
static Session_T *_session_node_belong_find(Net_T *p_net, M2M_request_pkt_T *p_pkt);

#ifdef HAS_LINUX_MUTEX

static INLINE int _m2m_net_lock(Net_T *p_net){

    if(pthread_mutex_lock( &p_net->locker ) !=0){
        m2m_debug_level(M2M_LOG_WARN, "lock list error");
        return M2M_ERR_NULL;
    }
    return M2M_ERR_NOERR;
}
static void _m2m_net_unlock(Net_T *p_net){
    pthread_mutex_unlock( p_net->locker );
}
// if lock 返回 noerror.
static INLINE M2M_Return_T _m2m_net_trylock(Net_T *p_net){
    if( pthread_mutex_trylock( &p_net->locker ) )
        return M2M_ERR_NULL;

    return M2M_ERR_NOERR;
}

#else

static INLINE int _m2m_net_lock(Net_T *p_net){return 0;}
static void _m2m_net_unlock(Net_T *p_net){}
static INLINE M2M_Return_T _m2m_net_trylock(Net_T *p_net){ return 0;}

#endif

static M2M_connt_Sta _connt_handle(M2M_cnnt_status *p_cs, M2M_connt_Sta status){

	if (status == M2M_CONNT_LOST)
		m2m_log_debug("---> MAX_PING_PKG_LOST");
	if( status == M2M_CONNT_LOST && ( ++(p_cs->count) ) >= MAX_PING_PKG_LOST ){
			p_cs->status = M2M_CONNT_LOST;
			p_cs->count = 0;
	} else 
		p_cs->status = M2M_CONNET_ON;

	return p_cs->status;
}
static INLINE void ack_destory(M2M_proto_ack_T *p_ack){
    if( p_ack && p_ack->payload.p_data)
        mfree( p_ack->payload.p_data);
}
static INLINE void _ne_sendingId_init(Session_T *p_s){
    p_s->sending_id = p_s->messageid;
}
static INLINE u8 _ne_sendingId_increase(Session_T *p_s){
	p_s->sending_id++;
    return p_s->sending_id ;
}
static INLINE BOOL _session_msgid_aliave(Session_T *p_s, u8 msgid){
	M2M_request_pkt_T *p_el = NULL, *p_tmp = NULL;

	LL_FOREACH_SAFE(p_s->p_request_head, p_el, p_tmp){
		if( p_el->messageid == msgid){
			return TRUE;
		}		
	}
	
	return FALSE;	
}

static INLINE u8 _session_messageid_increase(Session_T *p_s){
	u8 tmp = p_s->messageid++;
	int i = 0;
	for(i=0;i<255 && _session_msgid_aliave(p_s, tmp); i++){
		tmp++;
	}		
    p_s->messageid = tmp;
    return p_s->messageid;
}
static INLINE u32 _net_token_creat(){
     return m2m_get_random();
}
static INLINE u32 _net_getNextSendTime(int count){
    return ( m2m_current_time_get() +  ((_RETRANSMIT_DEFAULT_INTERVAL << count) * 1000 ));
}

static INLINE int _session_pkt_retransmit_increase( M2M_request_pkt_T *p_req ){
    p_req->transmit_count++;
    p_req->next_send_time = _net_getNextSendTime( p_req->transmit_count );
    m2m_debug_level(M2M_LOG_DEBUG,"currenttime %d retransmit count %d, next send time %d !!\n",m2m_current_time_get() ,p_req->transmit_count,p_req->next_send_time);
    return M2M_ERR_NOERR;
}
static INLINE void _session_aliveTime_update(Session_T *p_s){

    p_s->last_alive_tm = m2m_current_time_get();
}
// all ps node will be send in next trysync
static void _session_update_sendtime(Session_T *p_s){
    M2M_request_pkt_T *p_el = NULL, *p_tmp = NULL;
    u32 current_tm = m2m_current_time_get();
    LL_FOREACH_SAFE(p_s->p_request_head, p_el, p_tmp){
        p_el->next_send_time = current_tm;
    }

}
static INLINE BOOL _session_timeout(Session_T *p_s){
    return (A_BIGER_U32( m2m_current_time_get(), (p_s->last_alive_tm + _MAX_SESSION_IDLE_TIME_MS)) );
}
static u32 _net_ctoken_creat(Net_T *p_n){
    p_n->ctoken_index++;
    return ( (m2m_get_random() << 16)| p_n->ctoken_index );
}
static u32 _net_stoken_creat(Net_T *p_n){
    p_n->stoken_index++;
    return ( (m2m_get_random() << 16)| p_n->stoken_index );
}

// 注册 ctoken/messageid/payload/regist time/next send time
static M2M_request_pkt_T *session_node_creat(M2M_Proto_Cmd_T cmd,M2M_Proto_Cmd_Arg_T *p_args,Func_arg *p_callback){

    m2m_assert(p_args,0);

    M2M_request_pkt_T *p_req = mmalloc(sizeof(M2M_request_pkt_T) +1);
    _RETURN_EQUAL_0(p_req, 0);

    p_req->cmd = cmd;
    p_req->transmit_count = 1;
    p_req->messageid = p_args->messageid;
    p_req->len = p_args->payloadlen; 
    
    if(p_callback) {
        p_req->callback_arg.func = p_callback->func;
        p_req->callback_arg.p_user_arg = p_callback->p_user_arg;
    }

    if( p_args->payloadlen > 0 && p_args->p_payload ){
        p_req->p_proto_data = (u8*)mmalloc( p_args->payloadlen);
        _RETURN_EQUAL_FREE( p_req->p_proto_data, 0, p_req, 0);
         mcpy( (u8*)p_req->p_proto_data, (u8*)p_args->p_payload, p_req->len);
    }
    
    // time counting.
    p_req->register_time = m2m_current_time_get();
    p_req->next_send_time = _net_getNextSendTime( p_req->transmit_count );
    
    return p_req;
}
// 1. 摘除。
// 2. 释放。
static M2M_Return_T session_node_destory(M2M_request_pkt_T **pp_head,M2M_request_pkt_T **pp_pkt){

	_RETURN_EQUAL_0(pp_pkt, M2M_ERR_INVALID);
	
	// touch callback // M2M_ERR_REQUEST_DESTORY
	M2M_request_pkt_T *p_node = (M2M_request_pkt_T*)*pp_pkt;

	if( p_node->callback_arg.func){
		p_node->callback_arg.func((int)M2M_ERR_REQUEST_DESTORY, NULL, NULL,p_node->callback_arg.p_user_arg); 
		p_node->callback_arg.func = NULL;
		p_node->callback_arg.p_user_arg = NULL;
	}

	// free extra arg
	if(p_node->p_extra){
		
		_obs_free((M2M_observer_T**)&p_node->p_extra);
	}
	LL_DELETE( *pp_head, *pp_pkt);
    mfree( (*pp_pkt)->p_proto_data);
    mfree( *pp_pkt);
    m2m_debug_level(M2M_LOG_DEBUG,"node [%p] destory !!\n", *pp_pkt);
    *pp_pkt = NULL;
    
    return M2M_ERR_NOERR;
}
static M2M_Return_T _net_proto_request_retransmit_send(Net_T *p_net,Session_T *p_s,M2M_request_pkt_T *p_s_node){
    int ret = 0;
    m2m_assert(p_s_node, M2M_ERR_INVALID);
    m2m_assert(p_s, M2M_ERR_INVALID);

    M2M_Proto_Cmd_Arg_T cmdargs;
    mmemset((u8*)&cmdargs,0,sizeof(M2M_Proto_Cmd_Arg_T));

    cmdargs.messageid = p_s_node->messageid;
    cmdargs.stoken = p_s->stoken;
    cmdargs.ctoken = p_s->ctoken;
    cmdargs.socket_fd =  p_net->protocol.socket_fd;
    cmdargs.payloadlen = p_s_node->len;
    cmdargs.p_payload = p_s_node->p_proto_data;
    cmdargs.p_enc = &p_s->enc;
	cmdargs.p_extra = p_s_node->p_extra;
    
    mcpy( (u8*)&cmdargs.address, (u8*)&p_s->dest_addr,sizeof(M2M_Address_T));
    mcpy((u8*)&cmdargs.dst_id, (u8*)&p_s->dst_id, ID_LEN);
    mcpy((u8*)&cmdargs.src_id, (u8*)&p_net->my, ID_LEN);
    
    if( ( NODE_CMD_NOT_AUTH(p_s_node->cmd) || _SESSION_HAS_TOKEN(p_s) ) && \
        _SESSION_NODE_CAN_SEND(p_s, p_s_node->messageid)){
        _session_pkt_retransmit_increase(p_s_node);

        m2m_debug_level( M2M_LOG_DEBUG,"session (%p) retransmiting time %d node [%p] retransmit cmd %d", p_s,m2m_current_time_get(), p_s_node,p_s_node->cmd);
        return ( p_s->protocol.func_proto_ioctl )(p_s_node->cmd,&cmdargs,0);
    }else 
        return M2M_ERR_NOERR;
}
/***
** 发送
***/
static M2M_Return_T _session_request_send( 
	M2M_Proto_Ioctl_Cmd_T ioctl_cmd,
	
	M2M_Proto_Cmd_T cmd,
	M2M_Proto_Cmd_Arg_T *p_cmdargs,
	Session_T *p_s,Func_arg *p_callback,int flags){

	m2m_assert(p_cmdargs,M2M_ERR_INVALID);
	m2m_assert(p_s,M2M_ERR_INVALID);
	
	// send out.
	if( ( NODE_CMD_NOT_AUTH(cmd)|| _SESSION_HAS_TOKEN(p_s) )&& \
		_SESSION_NODE_CAN_SEND(p_s,p_cmdargs->messageid) ){
		
		int ret = ( p_s->protocol.func_proto_ioctl)(ioctl_cmd,p_cmdargs,0);
		_RETURN_LT_0( ret, ret);
		}
	return M2M_ERR_NOERR;
}

/*
* 1.封包发送。
* 2.创建节点。
* 3.挂入链表。
**/
static M2M_Return_T session_rq_node_send( 
    M2M_Proto_Ioctl_Cmd_T ioctl_cmd,
    
    M2M_Proto_Cmd_T cmd,
    M2M_Proto_Cmd_Arg_T *p_cmdargs,
    Session_T *p_s,Func_arg *p_callback,int flags){

    m2m_assert(p_cmdargs,M2M_ERR_INVALID);
    m2m_assert(p_s,M2M_ERR_INVALID);
    
    // send out.
    if( ( cmd == M2M_PROTO_CMD_TOKEN_RQ || cmd == M2M_PROTO_CMD_PING_RQ || _SESSION_HAS_TOKEN(p_s) )&& \
        _SESSION_NODE_CAN_SEND(p_s,p_cmdargs->messageid) ){
        
        int ret = ( p_s->protocol.func_proto_ioctl)(ioctl_cmd,p_cmdargs,0);
        _RETURN_LT_0( ret, ret);
        }

    // ctoken request 节点挂入 该session 的 request 链表，以便对接收进行回应。
    M2M_request_pkt_T *p_request_node = session_node_creat(cmd,p_cmdargs,p_callback);
    
    m2m_debug_level(M2M_LOG_DEBUG,"session (%p) creat node [%p] !!\n", p_s, p_request_node);
    if( NULL == p_request_node){
        // todo.
        //ret = ( p_s->protocol.func_proto_ioctl )(M2M_PROTO_CMD_SESSION_DESTORY_RQ,p_cmdargs,flags);
        return M2M_ERR_NULL;
        }
	p_s->node_cnt++;
   	LL_APPEND( p_s->p_request_head,p_request_node);
   // update session.
    _session_aliveTime_update(p_s);
    return M2M_ERR_NOERR;
}
/** token request.******************************/
#if 0
static _net_secret_update(Net_T *p_net,u8 *p_key,u16 keylen){

    if( keylen != (sizeof(u32) *2)
        return M2M_ERR_INVALID;
    if( p_net->enc.p_enckey == NULL){
            p_net->enc.p_enckey = mmalloc(keylen);
            _RETURN_EQUAL_0(p_net->enc.p_enckey, M2M_ERR_NULL);
    }
    
    return M2M_ERR_NOERR;
}
#endif
/**
** 对于 slave 的 session.
** 1. 仅仅有 ctoken 和message 用于过滤包.
** 2. 同时也不仅存在 node 节点问题，更不会主动 发 ping 维持连接。
***/
static M2M_Return_T _net_session_slave_creat(Net_T *p_net,M2M_proto_recv_rawpkt_T *p_raw,u32 *p_token){

    Session_T *p_s = mmalloc(sizeof(Session_T) +1);
    _RETURN_EQUAL_0(p_s,M2M_ERR_NULL);

    p_s->type = SESSION_TYPE_SLAVE;
    p_s->ctoken = _net_token_creat();
    p_s->messageid = 1;
    p_s->stoken = p_raw->stoken;

	mcpy((u8*) &p_s->dest_addr, (u8*)&p_raw->remote, sizeof( M2M_Address_T));
	// do not copy call back arg may be double free.
	//mcpy((u8*)&p_s->callback, (u8*)&p_net->callback, sizeof(Func_arg));
	mcpy( (u8*)&p_s->protocol,(u8*)&p_net->protocol, sizeof(M2M_Protocol_T));
    // 
    mcpy( (u8*)&p_s->dst_id,(u8*)&p_raw->src_id, ID_LEN);
    ENC_ALLOC_COPY(p_s->enc,p_net->enc);
    *p_token = p_s->ctoken;
    
    LL_APPEND( p_net->p_session_head, p_s);
	_SESSION_STA_SET_TOKEN(p_s);
    _session_aliveTime_update(p_s);
    m2m_debug_level( M2M_LOG_DEBUG,"session (%p) creating token = %x", p_s,p_s->ctoken);
    m2m_debug_level( M2M_LOG_DEBUG,"slave session (%p) creat for receiving and handle remote package.",p_s);
    return M2M_ERR_NOERR;
}
                                                   
/*description:
* 1. 获取 remote ip.
* 2. 向对端申请token.
* 3. 设置 session 状态 no ctoken(session 状态的切换需要在接收里进行处理.)
* 4. 把 session 注册到 net 链表。
* 5  把 ctoken reques 包挂到 session 链表。
*******/
static Session_T *session_creat_rq(Net_Args_T *p_args,int flags){

    m2m_assert(p_args,NULL);
    m2m_assert(p_args->p_net,NULL); 

    Net_Remot_Address_T *p_remote = &p_args->remote;
    
    int ret  = -1;
    /* session  */
    Session_T *p_s = mmalloc( sizeof(Session_T) );
    _RETURN_EQUAL_0( p_s, NULL);
    // 获取 ip.
    if( p_remote->p_host ){
        ALLOC_COPY( p_s->p_host, p_remote->p_host, sizeof(p_remote->p_host));
        _RETURN_EQUAL_FREE( p_s->p_host, 0, p_s, NULL);
        //  get remote ip.
        m2m_gethostbyname( &p_s->dest_addr, (char*)p_remote->p_host);
        // get remote port 
        p_s->dest_addr.port = p_args->remote.dst_address.port;
    }else if( p_remote->dst_address.len > 0 )
        mcpy( (u8*) &p_s->dest_addr,(u8*)&p_remote->dst_address ,sizeof(M2M_Address_T));
	// 注册 callback
	mcpy((u8*) &p_s->callback, (u8*)&p_args->callback,sizeof(Func_arg));

    // 获取秘钥.
    if(p_args->enc.keylen > 0 && p_args->enc.p_enckey){
            p_s->enc.p_enckey = mmalloc( p_args->enc.keylen );
            _RETURN_EQUAL_FREE(p_s->enc.p_enckey, 0, p_s, NULL);
            ENC_COPY(p_s->enc, p_args->enc);
    }
    // 获取 server 端 token.
    p_s->stoken = _net_stoken_creat(p_args->p_net);
    mcpy( (u8*)&p_s->dst_id, (u8*)&p_args->remote_id, ID_LEN);
    mcpy( (u8*)&p_s->protocol, (u8*)&p_args->p_net->protocol, sizeof( M2M_Protocol_T));
    // 2. 建立 session
    M2M_Proto_Cmd_Arg_T args;
    _PROTO_CMD_CREAT(p_s,args,p_args);
    _ne_sendingId_init(p_s);
    
    // 2.1 获取 token。
    ret = session_rq_node_send( M2M_PROTO_IOC_CMD_TOKEN_RQ,M2M_PROTO_CMD_TOKEN_RQ,&args,p_s, NULL,0);
    _RETURN_UNEQUAL_FREE(ret, M2M_ERR_NOERR, p_s,NULL);
    
    // 2.2 设置 session 状态为缺失 ctoken 
    p_s->state = M2M_SESSION_STA_NOTOKEN;
    p_s->type = SESSION_TYPE_MASTER;
    p_s->keep_ping_en = 1;
    // 3 注册 session.
    p_args->p_s = p_s;
    
    LL_APPEND(p_args->p_net->p_session_head,p_s);

    m2m_debug_level(M2M_LOG,"session (%p) creat successfully",p_s);
    return p_s;
}
/*
* 申请更新 ctoken.
**/
/**
*** recv --> 若不是本地，则查询路由表  ---> 路由转发
***             |--> 若是本地     --> 查询 session 链表，调用对应的 callback.
***             |                    |--> 若无 session 节点 认领 则调用 trysync 回调函数。
***             |--> 丢弃.
***/

static M2M_Return_T session_token_update(Net_Args_T *p_args,int flags){

    m2m_assert(p_args, M2M_ERR_INVALID);
    m2m_assert(p_args->p_s,M2M_ERR_INVALID );

    int ret = M2M_ERR_NULL;
    Session_T *p_s = p_args->p_s;
    Net_Remot_Address_T *p_remote = &p_args->remote;

    // creat protocol cmd.
    M2M_Proto_Cmd_Arg_T cmd;
    _PROTO_CMD_CREAT(p_s,cmd,p_args);

    ret = session_rq_node_send( M2M_PROTO_IOC_CMD_TOKEN_RQ, M2M_PROTO_CMD_TOKEN_RQ,&cmd,p_s,&p_args->callback,0);
    _RETURN_UNEQUAL(ret, M2M_ERR_NOERR,ret);
    // 设置 session 状态为缺失 ctoken 
    p_s->state = M2M_SESSION_STA_NOTOKEN;
    
    m2m_debug_level(M2M_LOG,"session (%p) send token update request successfully",p_s);
    return M2M_ERR_NOERR;
}
// 1. 更新 远端的key.
// 2. 接收到回应时才更新 本端 session 的秘钥 key.
static M2M_Return_T session_secretkey_set(Net_Args_T *p_args,int flags){

    m2m_assert(p_args,M2M_ERR_IGNORE);
    m2m_assert(p_args->p_s,M2M_ERR_IGNORE);

    Session_T *p_s = p_args->p_s;

    M2M_Proto_Cmd_Arg_T cmd;
    _PROTO_CMD_CREAT(p_s,cmd,p_args);
    
    int ret = session_rq_node_send( M2M_PROTO_IOC_CMD_SESSION_SETKEY_RQ,M2M_PROTO_CMD_SESSION_SETKEY_SET_RQ,&cmd,p_s,&p_args->callback,0);
    
    m2m_debug_level(M2M_LOG,"session (%p) send set key request successfully",p_s);
    return ret;
}
/**
* 发送数据包
**/
static M2M_Return_T session_data_send(Net_Args_T *p_args,int flags){

    m2m_assert(p_args, M2M_ERR_INVALID);
    m2m_assert(p_args->p_s,M2M_ERR_INVALID );

    int ret = M2M_ERR_NULL;
    Session_T *p_s = p_args->p_s;
    Net_Remot_Address_T *p_remote = &p_args->remote;

    M2M_Proto_Cmd_Arg_T cmd;
    _PROTO_CMD_CREAT(p_s,cmd,p_args);
    
    ret = session_rq_node_send( M2M_PROTO_IOC_CMD_DATA_RQ, M2M_PROTO_CMD_DATA_RQ,&cmd,p_s, &p_args->callback,0);
    _RETURN_UNEQUAL(ret, M2M_ERR_NOERR,ret);
    
    m2m_debug_level(M2M_LOG,"session (%p) send data request successfully",p_s);
    // count next send time.
    if(ret == M2M_ERR_NOERR)
        p_s->next_ping_send_tm = m2m_current_time_get() + INTERVAL_PING_TM_MS;
    
    return ret;
}
/** observer **********************************************************************/
static M2M_observer_T *_obs_alloc(Pkt_ack_type_T ack,u32 index){
	M2M_observer_T *p_obs = (M2M_observer_T*) mmalloc(sizeof(M2M_observer_T));
	p_obs->ack_type = ack;
	p_obs->index = index;
	
	m2m_log_debug("creat observer %p", p_obs);
	return p_obs;
}
static M2M_Return_T _obs_free(M2M_observer_T **pp_obs){
	m2m_assert(pp_obs, M2M_ERR_INVALID);
	m2m_assert(*pp_obs, M2M_ERR_INVALID);
	M2M_observer_T *p_obs = *pp_obs;

	mfree(p_obs->payload.p_data);
	p_obs->payload.p_data = NULL;
	p_obs->payload.len = 0;

	m2m_log_debug("free observer %p", p_obs);
	mfree(*pp_obs);
	*pp_obs = NULL;
	
	return M2M_ERR_NOERR;
}
static INLINE u16 _obs_index_increase(M2M_observer_T *p_obs_indx){
	p_obs_indx->index++;
	return p_obs_indx->index;
}

static INLINE BOOL _obs_connect_break(M2M_observer_T *p_obs_indx){

	if( p_obs_indx->lost_index > _OBSERVER_MAX_LOST)
		return TRUE;
	else return FALSE;
}
/** push notify ****************************************/
/**
* push an notify to remote.
**/
static M2M_Return_T obs_is_belong(Session_T *p_s, M2M_request_pkt_T *p_obs){

	M2M_request_pkt_T *p_el, *p_tmp;
	
	LL_FOREACH_SAFE(p_s->p_request_head, p_el, p_tmp){
		if(p_el == p_obs)
			return TRUE;
	}
	return FALSE;
}
static M2M_Return_T obs_notify_retransmit( Net_T *p_net,Session_T *p_s,M2M_request_pkt_T *p_s_node){

	int ret = M2M_ERR_NOERR;
    m2m_assert(p_s_node, M2M_ERR_INVALID);
    m2m_assert(p_s, M2M_ERR_INVALID);	

	M2M_observer_T *p_obs;

	_RETURN_EQUAL_0(p_s_node->p_extra, M2M_ERR_INVALID);
	p_obs = (M2M_observer_T*)p_s_node->p_extra;
	
	_RETURN_EQUAL_0( p_obs, M2M_ERR_INVALID);
	_RETURN_UNEQUAL( p_s_node->extra_cmd, EXTRA_CMD_NOTIFY, M2M_ERR_INVALID);
	_RETURN_UNEQUAL( p_obs->ack_type, TYPE_ACK_MUST, M2M_ERR_NOERR);

	if( !A_BIGER_U32(m2m_current_time_get(), p_obs->next_send_tm))
		return M2M_ERR_NOERR;
	
	// if notify timout remove that observer.
	if(p_obs->retransmit_cnt > _NOTIFY_RETRANSMIT_CNT_MAX){
	// touch user call back.
		M2M_obs_payload_T obs_pkt;
		obs_pkt.p_obs_node = p_s_node;
		obs_pkt.p_payload  = NULL;
		p_s_node->callback_arg.func( (int)M2M_ERR_OBSERVER_DISCARD, NULL, &obs_pkt, p_s->callback.p_user_arg); 
	// delete node
		session_node_destory(&p_s->p_request_head, &p_s_node);
		_SESSION_NODE_CNT_REDUCE(p_s);
		return M2M_ERR_NOERR;
	}
	// time to retansmit.
	if( p_obs->next_send_tm &&  A_BIGER_U32( m2m_current_time_get(), p_obs->next_send_tm )) {
		
	    M2M_Proto_Cmd_Arg_T cmdargs;
		
		mmemset((u8*)&cmdargs,0,sizeof(M2M_Proto_Cmd_Arg_T));
		cmdargs.messageid = p_s_node->messageid;
		cmdargs.stoken = p_s->stoken;
		cmdargs.ctoken = p_s->ctoken;
		cmdargs.socket_fd =  p_s->protocol.socket_fd;
		cmdargs.p_enc = &p_s->enc;
		cmdargs.payloadlen = p_obs->payload.len;
		cmdargs.p_payload = p_obs->payload.p_data;
		cmdargs.p_extra = (void*)&p_obs;

		mcpy((u8*)&cmdargs.dst_id, (u8*)&p_s->dst_id, sizeof(M2M_id_T));
		mcpy((u8*)&cmdargs.src_id, (u8*)&p_net->my, sizeof(M2M_id_T));
		mcpy((u8*)&cmdargs.address, (u8*)&p_s->dest_addr, sizeof(M2M_Address_T));

		if( ( NODE_CMD_NOT_AUTH(p_s_node->cmd) || _SESSION_HAS_TOKEN(p_s) ) && \
			_SESSION_NODE_CAN_SEND(p_s, p_s_node->messageid)){
				_session_pkt_retransmit_increase(p_s_node);
				ret = ( p_s->protocol.func_proto_ioctl )(p_s_node->cmd,&cmdargs,0);
		}
		p_obs->retransmit_cnt++;
		p_obs->next_send_tm = _net_getNextSendTime( p_obs->retransmit_cnt );
	}
	return ret;
}
// 解析 observer index, 
// obs index == 0x01  则为 observer start 在 session 内部构建 node 节点。
// obs index > 1 则为 notify 推送，
// obs index == 0x00 则为 observer stop，把该 node 从 session 中摘掉。	
/** 该函数只为 slave 调用，只处理  observer start request，observer stop request, notify ack。*****/
static M2M_Return_T obs_rq_handle( Net_T *p_net,Session_T *p_s, M2M_proto_recv_rawpkt_T *p_raw,M2M_proto_dec_recv_pkt_T *p_dec){
	// get obs index
	M2M_observer_T *p_obs = (M2M_observer_T*)p_dec->p_extra;
	int ret = 0;
	// drop notify
	if( p_obs->index >1 ){
		m2m_log_warn("slave session receive an notify, drop it.");
		return M2M_ERR_INVALID;
	}
	
	if( p_obs->index == OBS_TYPE_ON){
	// receive observer start.
	// creat session node .	
	    M2M_packet_T *p_ack_payload = NULL;	
		M2M_observer_T *p_nobs = (M2M_observer_T*)mmalloc(sizeof(M2M_observer_T));
		_RETURN_EQUAL_0( p_nobs, M2M_ERR_NULL);
		
    	M2M_request_pkt_T *p_node = (M2M_request_pkt_T*)mmalloc(sizeof(M2M_request_pkt_T));
		_RETURN_EQUAL_FREE( p_node, NULL, p_nobs,M2M_ERR_NULL);

		p_node->cmd = M2M_PROTO_CMD_SESSION_OBSERVER_RQ;
		p_node->messageid = p_dec->msgid;
		///mcpy( (u8*)&p_node->callback_arg, (u8*)&p_net->callback, sizeof(Func_arg));
		
		p_nobs->ack_type = p_obs->ack_type;
		p_nobs->index = p_obs->index;
		//mcpy((u8*)&p_nobs->callback, (u8*)&p_net->callback, sizeof(Func_arg) );
		
		p_node->extra_cmd = EXTRA_CMD_NOTIFY;
		p_node->p_extra = p_nobs;

		p_s->node_cnt++;
		LL_APPEND(p_s->p_request_head, p_node);
		m2m_log_debug("session (%p) creat observer node [%p]", p_s, p_node);
		// tell application we get an observer start through call back.
		if(p_net->callback.func){
			M2M_obs_payload_T obs_pkt;
			obs_pkt.p_obs_node = p_node;
			obs_pkt.p_payload  = &p_dec->payload;
			p_net->callback.func( (int)M2M_REQUEST_OBSERVER_RQ, &p_ack_payload, &obs_pkt, p_net->callback.p_user_arg); 
		}
	// ack to the remote.
        ret = net_ack( (u16)M2M_HTTP_OK, M2M_PROTO_IOC_CMD_SESSION_OBSERVER_ACK, \
							p_s->protocol.func_proto_ioctl, &p_s->enc, p_raw,(M2M_packet_T*)p_ack_payload,(void*)p_nobs);	
		// free ack payload
		PACKET_FREE(p_ack_payload);
	}else if( p_obs->index == OBS_TYPE_OFF ){
	// receive an observer stop
		M2M_request_pkt_T *p_del = _net_session_node_find(p_s, p_dec->msgid);
		_RETURN_EQUAL(p_del, NULL, M2M_ERR_INVALID);
		// tell application that observer will be remove.
		if( p_net->callback.func ){
			M2M_obs_payload_T obs_pkt;
			obs_pkt.p_obs_node = p_del;
			obs_pkt.p_payload  = NULL;
			p_net->callback.func( (int)M2M_ERR_OBSERVER_DISCARD, NULL, &obs_pkt, p_net->callback.p_user_arg); 
		}
		session_node_destory(&p_s->p_request_head, &p_del);
		_SESSION_NODE_CNT_REDUCE(p_s);
	}
	return M2M_ERR_NOERR;
}
static M2M_Return_T obs_ack_handle(Session_T *p_s, M2M_request_pkt_T *p_node,M2M_proto_recv_rawpkt_T *p_raw,M2M_proto_dec_recv_pkt_T *p_dec){
	int ret = 0;
	M2M_observer_T *p_robs = (M2M_observer_T*)p_dec->p_extra;
	M2M_observer_T *p_nobs = (M2M_observer_T*)p_node->p_extra;
	_RETURN_EQUAL_0(p_robs, M2M_ERR_INVALID);	
	_RETURN_EQUAL_0(p_nobs, M2M_ERR_INVALID);
	_RETURN_UNEQUAL( p_nobs->index, p_robs->index, M2M_ERR_INVALID);	
	_RETURN_UNEQUAL( p_nobs->index, OBS_TYPE_ON, M2M_ERR_INVALID);


	_USERFUNC_(p_node,p_dec,ret);
	_ne_sendingId_increase(p_s);
	p_node->next_send_time = 0;
	p_node->transmit_count = 0;
	// notify 节点将会永远挂在 session 里。
	if(p_dec->code == M2M_HTTP_OK)
		p_node->extra_cmd = EXTRA_CMD_NOTIFY;

    return M2M_ERR_NOERR;
}
/** 处理 notify，仅仅在 master session 中调用，回应M2M_PROTO_CMD_SESSION_OBSERVER_ACK ******************/
static M2M_Return_T obs_notify_rq_handle(Session_T *p_s, M2M_request_pkt_T *p_node, M2M_proto_recv_rawpkt_T *p_raw, M2M_proto_dec_recv_pkt_T *p_dec){
	// get obs index
	int ret = 0;
	M2M_observer_T *p_robs = (M2M_observer_T*)p_dec->p_extra;
	M2M_observer_T *p_nobs = (M2M_observer_T*)p_node->p_extra;
	_RETURN_EQUAL_0(p_robs, M2M_ERR_INVALID);	
	_RETURN_EQUAL_0(p_nobs, M2M_ERR_INVALID);

	// index filter 
	if( A_BIGER_U16(p_robs->index, p_nobs->index)){
		M2M_packet_T *p_ack_payload = NULL;
	// get notify and push to application.
		 if(p_node->callback_arg.func){
			p_node->callback_arg.func( (int)M2M_REQUEST_NOTIFY_PUSH, &p_ack_payload, &p_dec->payload, p_node->callback_arg.p_user_arg);
			p_nobs->index = p_robs->index;
		 }
	// ack notify.
		if(p_nobs->ack_type == TYPE_ACK_MUST){
				
			   ret = net_ack( (u16)M2M_HTTP_OK, M2M_PROTO_IOC_CMD_SESSION_OBSERVER_ACK, \
							p_s->protocol.func_proto_ioctl, &p_s->enc, p_raw,(M2M_packet_T*)p_ack_payload,(void*)p_nobs);	
		}
		PACKET_FREE(p_ack_payload);
	}else{
		m2m_log_warn("notify index was too old drop it >>");
	}

	
	return ret;
}
/** 只在 salve session 接受中调用，不 ack。*************/
static M2M_Return_T obs_notify_ack_handle(Session_T *p_s, M2M_request_pkt_T *p_node, M2M_proto_recv_rawpkt_T *p_raw, M2M_proto_dec_recv_pkt_T *p_dec){

	
	int ret = 0;
	M2M_observer_T *p_robs = (M2M_observer_T*)p_dec->p_extra;
	M2M_observer_T *p_nobs = (M2M_observer_T*)p_node->p_extra;
	_RETURN_EQUAL_0(p_robs, M2M_ERR_INVALID);	
	_RETURN_EQUAL_0(p_nobs, M2M_ERR_INVALID);
	_RETURN_UNEQUAL( p_nobs->index, p_robs->index, M2M_ERR_INVALID);

	// notify application 
	if( p_nobs->callback.func){
	 	M2M_obs_payload_T obs_pkt;
		obs_pkt.p_obs_node = p_node;
		obs_pkt.p_payload  = &p_dec->payload;
		p_nobs->callback.func( (int)M2M_REQUEST_NOTIFY_ACK, NULL, &obs_pkt, p_nobs->callback.p_user_arg);
		mmemset( (u8*)&p_nobs->callback, 0, sizeof(Func_arg));
	}
	mfree(p_nobs->payload.p_data);
	mmemset( (u8*)&p_nobs->payload, 0, sizeof(M2M_packet_T));

	// clearn lost counter.
	p_nobs->lost_index = 0;
	p_nobs->next_send_tm =0;
	p_nobs->retransmit_cnt = 0;
	
	return M2M_ERR_NOERR;
}
static u8 *obs_notify_msgid_alloc(Session_T *p_s, u32 *p_len){
	BOOL has_obs = FALSE;
	int i = 0;
	M2M_request_pkt_T *p_el = NULL, *p_tmp =NULL;
	_RETURN_EQUAL_0(p_s, NULL);
	_RETURN_EQUAL_0(p_s->node_cnt, NULL);
	u8 *p = NULL;

	if( p_len && p_s->node_cnt > 0){
		p =mmalloc(p_s->node_cnt);
		_RETURN_EQUAL_0(p, NULL);
		LL_FOREACH_SAFE( p_s->p_request_head, p_el, p_tmp){
			if(p_el->extra_cmd == EXTRA_CMD_NOTIFY){
				p[i] = p_el->messageid;
				i++;
			}
		}
		*p_len = (u32)i;
	}
	
	return p;
}

static M2M_Return_T obs_single_notify_clean(Session_T *p_s, M2M_packet_T *p_pkt){
	if( !p_s->p_request_head)
		return M2M_ERR_NOERR;

	int i = 0;
	
	M2M_request_pkt_T *p_mel = NULL, *p_mtmp = NULL, *p_del = NULL;
	u8 *p_msgid = p_pkt->p_data;

	LL_FOREACH_SAFE(p_s->p_request_head, p_mel, p_mtmp){

		if(p_mel->extra_cmd != EXTRA_CMD_NOTIFY)
			continue;
		if( p_pkt && p_pkt->len > 0){
			for(i=0; i<p_pkt->len;i++){
				if(p_mel->messageid == p_msgid[i]){
						break;
				}
			}
			if( p_mel && i == p_pkt->len){
				p_del  = p_mel;
			}
		} else 
			p_del = p_mel;

		if(p_del){
			if( p_del->callback_arg.func){
				p_del->callback_arg.func((int)M2M_ERR_OBSERVER_DISCARD, NULL, NULL,p_del->callback_arg.p_user_arg); 
			}
			session_node_destory(&p_s->p_request_head, &p_del);
			p_del = NULL;
		}
	}
	return M2M_ERR_NOERR;
}
static M2M_Return_T session_obs_notify_push(Net_Args_T *p_args,int flags){

    m2m_assert(p_args, M2M_ERR_INVALID);

    int ret = M2M_ERR_NOERR;
    Session_T *p_s = NULL;
    M2M_Proto_Cmd_Arg_T cmdargs;
	M2M_request_pkt_T *p_node = (M2M_request_pkt_T*)p_args->p_extra;
	M2M_observer_T *p_obs = NULL;

	_RETURN_EQUAL_0(p_node, M2M_ERR_INVALID);
	mmemset((u8*)&cmdargs, 0, sizeof(M2M_Proto_Cmd_Arg_T));

	// find observers
	
	p_s = _session_node_belong_find(p_args->p_net, p_node);
	_RETURN_EQUAL_0(p_s, M2M_ERR_OBSERVER_DISCARD);
	
	p_obs = (M2M_observer_T *)p_node->p_extra;
	_RETURN_EQUAL_0(p_obs, M2M_ERR_INVALID);
	// must be an notify.
	_RETURN_UNEQUAL(p_node->extra_cmd, EXTRA_CMD_NOTIFY, M2M_ERR_INVALID );
	if(_obs_connect_break(p_obs)){
		m2m_log_warn("observer have been discard!！");
		return M2M_ERR_OBSERVER_DISCARD;
	}
	
    cmdargs.messageid = p_node->messageid;
    cmdargs.stoken = p_s->stoken;
    cmdargs.ctoken = p_s->ctoken;
    cmdargs.socket_fd =  p_s->protocol.socket_fd;
    cmdargs.payloadlen = p_args->len;
    cmdargs.p_payload = p_args->p_data;
    cmdargs.p_enc = &p_s->enc;
	cmdargs.p_extra = p_obs;

    mcpy( (u8*)&cmdargs.address, (u8*)&p_s->dest_addr,sizeof(M2M_Address_T));
    mcpy((u8*)&cmdargs.dst_id, (u8*)&p_s->dst_id, ID_LEN);
    mcpy((u8*)&cmdargs.src_id, (u8*)&p_args->p_net->my, ID_LEN);
	
	// observer index increas
	_obs_index_increase( p_obs );
	// dele 
	if(p_obs->payload.p_data){
		mfree( p_obs->payload.p_data);
		p_obs->payload.len = 0;
		p_obs->payload.p_data = NULL;
	}
	
	p_obs->payload.p_data = mmalloc(p_args->len);
	_RETURN_EQUAL_0(p_obs->payload.p_data, M2M_ERR_NULL);
	mcpy(p_obs->payload.p_data, p_args->p_data, p_args->len);
	p_obs->payload.len = p_args->len;
	mcpy( (u8*)&p_obs->callback, (u8*)&p_args->callback, sizeof(Func_arg));
	
    if( ( NODE_CMD_NOT_AUTH(p_node->cmd) || _SESSION_HAS_TOKEN(p_s) ) && \
        _SESSION_NODE_CAN_SEND(p_s, p_node->messageid)){
        ret = ( p_s->protocol.func_proto_ioctl )(p_node->cmd,&cmdargs,0);
    }
		
	if( p_obs->ack_type == TYPE_ACK_NONE){
		mfree( p_obs->payload.p_data);
		p_obs->payload.len = 0;
		p_obs->payload.p_data = NULL;
	}else 
		p_obs->next_send_tm = _net_getNextSendTime(++p_obs->retransmit_cnt);
    return 0;
}

/**
* start an observer request.
**/
static size_t session_obs_start(Net_Args_T *p_args,int flags){

    m2m_assert(p_args, M2M_ERR_INVALID);
    m2m_assert(p_args->p_s,M2M_ERR_INVALID );

    int ret = 0;
    Session_T *p_s = p_args->p_s;
    Net_Remot_Address_T *p_remote = &p_args->remote;
	M2M_observer_T *p_obs = NULL;

    M2M_Proto_Cmd_Arg_T cmd;
    _PROTO_CMD_CREAT(p_s,cmd,p_args);
	
    // ctoken request 节点挂入 该session 的 request 链表，以便对接收进行回应。
    M2M_request_pkt_T *p_request_node = session_node_creat(M2M_PROTO_CMD_SESSION_OBSERVER_RQ,&cmd,&p_args->callback);
    _RETURN_EQUAL(p_request_node, NULL,0);	
	
	p_request_node->extra_cmd = EXTRA_CMD_OBSERVER;
	p_obs = _obs_alloc( *((Pkt_ack_type_T*)p_args->p_extra), OBS_TYPE_ON);
	//mcpy((u8*)&p_obs->callback, (u8*)&p_args->callback, sizeof(Func_arg));
	p_request_node->p_extra = p_obs;
	if( !p_request_node->p_extra ){
		session_node_destory(&p_s->p_request_head, &p_request_node);
		return 0;
	}
	
    cmd.p_extra = p_request_node->p_extra;
	ret = _session_request_send(M2M_PROTO_IOC_CMD_SESSION_OBSERVER_RQ, M2M_PROTO_CMD_SESSION_OBSERVER_RQ,&cmd,p_s, &p_args->callback,0);
	if(ret < 0){
		session_node_destory(&p_s->p_request_head, &p_request_node);
		return 0;
	}
	
	p_s->node_cnt++;
   	LL_APPEND( p_s->p_request_head,p_request_node);
    // count next send time.
    if(ret == M2M_ERR_NOERR)
        p_s->next_ping_send_tm = m2m_current_time_get() + INTERVAL_PING_TM_MS;

	m2m_log_debug("session (%p)  node [%p] have been creat", p_s,p_request_node);
    return (size_t)p_request_node;
}

static M2M_Return_T session_obs_stop(Net_Args_T *p_args,int flags){

	m2m_assert(p_args, M2M_ERR_INVALID);
	// m2m_assert(p_args->p_s,M2M_ERR_INVALID );
	
	 int ret = M2M_ERR_NOERR;
	 Session_T *p_s =  NULL;
	 M2M_Proto_Cmd_Arg_T cmdargs;
	 M2M_request_pkt_T *p_node = (M2M_request_pkt_T*)p_args->p_extra;
	 M2M_observer_T *p_obs;
	
	 _RETURN_EQUAL_0(p_node, M2M_ERR_INVALID);
	 mmemset((u8*)&cmdargs, 0, sizeof(M2M_Proto_Cmd_Arg_T));
	
	 // find session that node belong to.
	 p_s = _session_node_belong_find(p_args->p_net, p_node);
	 
	 _RETURN_EQUAL_0(p_s, M2M_ERR_OBSERVER_DISCARD);
	// in salve session we just want free that node .
	if(p_s->type == SESSION_TYPE_SLAVE){
		session_node_destory(&p_s->p_request_head, &p_node);
		_SESSION_NODE_CNT_REDUCE(p_s);
		return M2M_ERR_NOERR;
	}

	p_obs = _obs_alloc(TYPE_ACK_NONE, OBS_TYPE_OFF);
	_RETURN_EQUAL_0(p_obs, M2M_ERR_NULL);
	 
	 cmdargs.messageid = p_node->messageid;
	 cmdargs.stoken = p_s->stoken;
	 cmdargs.ctoken = p_s->ctoken;
	 cmdargs.socket_fd =  p_s->protocol.socket_fd;
	 cmdargs.payloadlen = p_node->len;
	 cmdargs.p_payload = p_node->p_proto_data;
	 cmdargs.p_enc = &p_s->enc;
	 cmdargs.p_extra = p_obs;
	
	 mcpy( (u8*)&cmdargs.address, (u8*)&p_s->dest_addr,sizeof(M2M_Address_T));
	 mcpy((u8*)&cmdargs.dst_id, (u8*)&p_s->dst_id, ID_LEN);
	 mcpy((u8*)&cmdargs.src_id, (u8*)&p_args->p_net->my, ID_LEN);
	 
	 if( ( NODE_CMD_NOT_AUTH(p_node->cmd) || _SESSION_HAS_TOKEN(p_s) ) && \
		 _SESSION_NODE_CAN_SEND(p_s, p_node->messageid)){
		 ret = ( p_s->protocol.func_proto_ioctl )(p_node->cmd,&cmdargs,0);
	 }

	_obs_free(&p_obs );
	// delete 
	session_node_destory(&p_s->p_request_head, &p_node);
	_SESSION_NODE_CNT_REDUCE(p_s);
	return M2M_ERR_NOERR;
}

// 延迟下一个 ping 包发送的时间。
static void session_pingDelay(Session_T *p_s){
    p_s->next_ping_send_tm =_PING_INTERVAL_TM;
}
static M2M_Return_T _net_host_ping(Net_T *p_net){
    int ret = 0;
    if(p_net->host.p_host == NULL|| p_net->host.addr.len == 0)
        return M2M_ERR_INVALID;
    
    int tm = m2m_current_time_get();
    if( A_BIGER_U32( m2m_current_time_get(), p_net->host.next_ping_tm) ){
        M2M_Proto_Cmd_Arg_T cmd;
        Net_enc_T no_enc;
    
        mmemset((u8*)&cmd,0,sizeof(M2M_Proto_Cmd_Arg_T));
        mmemset((u8*)&no_enc,0,sizeof(Net_enc_T));
        cmd.socket_fd = p_net->protocol.socket_fd;
        cmd.stoken = p_net->host.stoken;
        cmd.messageid = p_net->host.msgid++;

        no_enc.type = M2M_ENC_TYPE_NOENC;
        cmd.p_enc = &no_enc;
            
        CPY_DEV_ID(cmd.src_id,p_net->my);
        CPY_DEV_ID(cmd.dst_id,p_net->host.host_id);
        mcpy( (u8*)&cmd.address, (u8*)&p_net->host.addr, sizeof(M2M_Address_T));
        
        ret = ( p_net->protocol.func_proto_ioctl)( M2M_PROTO_IOC_CMD_PING_RQ, &cmd,0);
        m2m_debug_level( M2M_LOG_DEBUG,"net <%p> sending ping to host %s \n", p_net,p_net->host.p_host);
        if(p_net->host.retransmit_count++ > 3){
            p_net->host.next_ping_tm = _PING_INTERVAL_TM;
            p_net->host.retransmit_count = 0;
        	_connt_handle( &p_net->host.connt, M2M_CONNT_LOST);
            m2m_debug_level( M2M_LOG_DEBUG,"net <%p> sending too many ping package to host %s \n", p_net,p_net->host.p_host);
        }else
            p_net->host.next_ping_tm = _net_getNextSendTime( p_net->host.retransmit_count);
        }
    return ret;
}
static BOOL session_connt_chack(Net_Args_T *p_args,int flags){

	m2m_assert(p_args, M2M_ERR_INVALID);
	m2m_assert(p_args->p_s, M2M_ERR_INVALID);

	
	Session_T *p_s = p_args->p_s;
	return	( (p_s->connt.status != M2M_CONNET_ON)? 0:1 );
}

// 连接的维持.
static M2M_Return_T session_ping_send(Net_Args_T *p_args,int flags){

    m2m_assert(p_args, M2M_ERR_INVALID);
    m2m_assert(p_args->p_s,M2M_ERR_INVALID );

    int ret = M2M_ERR_NULL;
    Session_T *p_s = p_args->p_s;

    M2M_Proto_Cmd_Arg_T cmd;
    Net_enc_T enc;

	mmemset((u8*)&enc,0,sizeof(Net_enc_T));
    _PROTO_CMD_CREAT(p_s,cmd,p_args);

	
    if(flags)
        cmd.p_enc = &enc;
    
    ret = session_rq_node_send( M2M_PROTO_IOC_CMD_PING_RQ, M2M_PROTO_CMD_PING_RQ,&cmd,p_s,NULL,0);
	_RETURN_UNEQUAL_FREE(ret, M2M_ERR_NOERR, cmd.p_payload, ret);
    
    m2m_debug_level(M2M_LOG_DEBUG,"session (%p) sending ping package\n",p_s);
    // count next send time.
    if(ret == M2M_ERR_NOERR)
        session_pingDelay( p_s );

    return ret;
}
#if 0
// 1. 每个 session 均发送 ping.
static M2M_Return_T net_session_system_handle(Net_T *p_net ,int flags){ 

    m2m_assert( p_net, M2M_ERR_INVALID);
    // no session.
    m2m_assert( p_net->p_session_head,M2M_ERR_NOERR );

    int ret = M2M_ERR_NULL;
    Session_T *p_el,*p_tmp;
    LL_FOREACH_SAFE(p_net->p_session_head, p_el, p_tmp ){
        if( m2m_current_time_get() > p_el->next_ping_send_tm ){

            Net_Args_T args;
            mmemset( &args,0,sizeof(Net_Args_T));
            mcpy(&args.remote.dst_address, &p_el->dest_addr,sizeof(M2M_Address_T));
            args.p_net = p_net;
            args.p_s = p_el;
            ret = session_ping_send( &args,0);
        }
    }
    
    return ret;
}
#endif
/*description:
// 1. Destory session 内所有的节点。
// 2. net 里移除 session。
*****/
static M2M_Return_T session_destory(Net_Args_T *p_a,int flag){
    Net_T *p_net = p_a->p_net;
    Session_T *p_s = p_a->p_s;
    
    // 1. 清理所有的 node.
    M2M_request_pkt_T *p_el = NULL, *p_tmp = NULL;
	_RETURN_EQUAL_0(p_s, M2M_ERR_NOERR);
    LL_FOREACH_SAFE( p_s->p_request_head, p_el,p_tmp){
        
         _ne_sendingId_increase(p_s);
        session_node_destory( &p_s->p_request_head, &p_el);
		_SESSION_NODE_CNT_REDUCE(p_s);
    }
    // 3. 移除 session
    LL_DELETE(p_net->p_session_head,p_s);
    // 5. 释放 session 资源.
    if(p_s->enc.p_enckey){
        mfree(p_s->enc.p_enckey);
        p_s->enc.p_enckey = NULL;
    }
    // 释放 host 
    if(p_s->p_host){
        mfree( p_s->p_host);
        p_s->p_host = 0;
    }
	// 回调触发,并释放回调函数
	if( p_s->callback.func){
		p_s->callback.func((int)M2M_ERR_REQUEST_DESTORY, NULL, NULL,p_s->callback.p_user_arg); 
		p_s->callback.func = NULL;
		p_s->callback.p_user_arg = NULL;
	}
	
    mfree(p_s);
    m2m_debug_level(M2M_LOG,"session (%p) destory\n",p_a->p_s);
    p_a->p_s = NULL;
    return M2M_ERR_NOERR;
}
/************** 接收处理 *************************************************************************************/
static M2M_Return_T _net_ack(M2M_Proto_Ioctl_Cmd_T ioc_cmd,Net_T *p_net,M2M_proto_ack_T *p_ack){

    p_ack->socket_fd = p_net->protocol.socket_fd;
    return p_net->protocol.func_proto_ioctl(ioc_cmd,p_ack,0);
}
static M2M_Return_T net_ack(	u16 code,M2M_Proto_Ioctl_Cmd_T ioc_cmd, m2m_func proto_func, 
								Net_enc_T *p_enc, M2M_proto_recv_rawpkt_T *p_recv,M2M_packet_T *p_payload,void *p_extra){

    M2M_proto_ack_T pkt_ack, *p_ack;

    mmemset( (u8*)&pkt_ack, 0, sizeof(M2M_proto_ack_T));
    p_ack = &pkt_ack;
    
    p_ack->code = code;
    p_ack->p_enc = p_enc;
    p_ack->p_extra = p_extra;
	
    _ACK_HEAD_FULL(p_ack,p_recv);

    if( p_payload )
        mcpy( (u8*)&p_ack->payload, (u8*)p_payload,sizeof( M2M_packet_T) );
    return proto_func(ioc_cmd,p_ack,0);
}
static M2M_Return_T _net_secret_key_update(Net_enc_T *p_enc,u8 *p_key,int enc_len){
    Enc_T *p_new_enc = (Enc_T*)p_key;

    if( p_new_enc->keylen >= enc_len  )
        return M2M_ERR_INVALID;
    
    if(p_enc->keylen != p_new_enc->keylen){
        if(p_enc->p_enckey) 
            mfree( p_enc->p_enckey);
        
        p_enc->p_enckey = mmalloc( p_new_enc->keylen + 1);
        _RETURN_EQUAL_0(p_enc->p_enckey, M2M_ERR_NULL);
    }
    mcpy( (u8*)p_enc->p_enckey, (u8*)p_new_enc->key,p_new_enc->keylen);
    p_enc->type =  p_new_enc->type;
    p_enc->keylen = p_new_enc->keylen;
    return M2M_ERR_NOERR;
}

// 中转包
static M2M_Return_T _net_relay_handle(Net_T *p_net, M2M_proto_recv_rawpkt_T *p_raw){
	int ret = 0 ;
    M2M_Address_T addr;
	mmemset((u8*)&addr, 0, sizeof(M2M_Address_T ));
    if( !m2m_relay_id_find(&addr,p_net->host.p_router_list, &p_raw->dst_id)){
		m2m_log_warn("can't relay dev");
		m2m_bytes_dump("can't relay dev: ", (u8*)&p_raw->dst_id, sizeof(M2M_id_T));
		return M2M_ERR_NOERR;
    	}

    M2M_protocol_relay_T args;

	// 注册在线，防止回包接不到.
    _ROUTER_LIST_ADD_DEVICE(p_net,p_raw);
    mmemset((u8*)&args,0,sizeof(M2M_protocol_relay_T));

    args.socket_fd = p_net->protocol.socket_fd;
    args.p_remote_addr = &addr;
    args.p_payload = &p_raw->payload;

    return p_net->protocol.func_proto_ioctl(M2M_PROTO_IOC_CMD_RELAY, &args, 0);
}
/**
** description: 1. 解码 payload 部分。
**              2. 对于非 ping 则正常回应，token 则生成 新的token 并创建 session。
**  3 处理 ping，广播，查询设备在线的包。
**/
static M2M_Return_T _net_recv_handle_without_session
    ( 
        Net_T *p_net,
        M2M_proto_recv_rawpkt_T *p_raw){
    int ret =0;
    M2M_proto_dec_recv_pkt_T pkt_dec,*p_dec;
    M2M_dec_args_T dec_args;
    Net_enc_T enc;
    M2M_packet_T ack_payload;

    mmemset( (u8*)&pkt_dec, 0, sizeof(M2M_proto_dec_recv_pkt_T));
    mmemset( (u8*)&enc,0,sizeof(Net_enc_T));
    mmemset( (u8*)&ack_payload, 0, sizeof(M2M_packet_T));
    
    p_dec = &pkt_dec;
    
    dec_args.p_dec = &pkt_dec;
    dec_args.p_rawpkt = p_raw;
    pkt_dec.p_enc = &p_net->enc;

    if( p_raw->enc_type == M2M_ENC_TYPE_NOENC)
        enc.type = M2M_ENC_TYPE_NOENC;
    else mcpy( (u8*)&enc, (u8*)&p_net->enc,sizeof( Net_enc_T) ); // todo!!! 注意 指针指向 net 的enc 所以 多线程时必须重构
    
    // 4. 解密并解包.
    ret =  ( p_net->protocol.func_proto_ioctl )( M2M_PROTO_IOC_CMD_DECODE_PKT_RQ,&dec_args,0);
    
    // 获取错误码.
    if( ret != 0){
        m2m_log_error("net <%p> receive package that can't decode.", p_net); 
        goto NO_SESSION_HANDLE_END;
    }
	
	m2m_debug_level( M2M_LOG_WARN,"No token cmd is %d", p_dec->cmd);
    switch( p_dec->cmd){
        case M2M_PROTO_CMD_PING_RQ:
            // 更新 路由列表
            net_ack( (u16)M2M_HTTP_OK, M2M_PROTO_IOC_CMD_PING_ACK, p_net->protocol.func_proto_ioctl, &enc, p_raw,NULL, NULL);
            break;
        case M2M_PROTO_CMD_PING_ACK:
            // update net ping time.
            //m2m_bytes_dump((u8*)"receive ping ack from id ", (u8*)&p_raw->src_id, sizeof(M2M_id_T));
            p_net->host.next_ping_tm = _PING_INTERVAL_TM;            		
        	_connt_handle( &p_net->host.connt, M2M_CONNET_ON);
            break;
        case M2M_PROTO_CMD_TOKEN_RQ:
            {
                //  token 必须加密.
                u32 new_token = 0;
                if(p_raw->enc_type == M2M_ENC_TYPE_NOENC)
                    break;

                ack_payload.p_data = (u8*)&new_token;
                ack_payload.len = sizeof(u32);

                ret = _net_session_slave_creat(p_net,p_raw, &new_token);
                
                DEV_ID_LOG_PRINT(M2M_LOG_DEBUG,p_raw->src_id,"Sending token to dev ",".");
                ret = net_ack( (u16)M2M_HTTP_OK, M2M_PROTO_IOC_CMD_TOKEN_ACK, p_net->protocol.func_proto_ioctl, &enc, p_raw,&ack_payload, NULL);
            }
            break;
#ifdef M2M_PROTO_CMD_BROADCAST_RQ
        case M2M_PROTO_CMD_BROADCAST_RQ:
            {
            
                M2M_packet_T *p_ack_payload = NULL;
                ret = p_net->callback.func( M2M_REQUEST_BROADCAST, &p_ack_payload, &p_dec->payload,p_net->callback.p_user_arg);
                ret = net_ack( M2M_HTTP_OK, M2M_PROTO_IOC_CMD_BROADCAST_ACK, p_net->protocol.func_proto_ioctl,&enc, p_raw, p_ack_payload, NULL);
                PACKET_FREE(p_ack_payload);
                p_ack_payload = NULL;
            }
            break;
        case M2M_PROTO_CMD_BROADCAST_ACK:
            {
            Net_request_node_T *p_find = net_request_packet_find(p_net->p_request_hd,p_raw->stoken);
            if( p_find )
                ret =  p_find->callback_arg.func( p_dec->code, NULL, &p_dec->payload, p_find->callback_arg.p_user_arg);
            }
            break;
#endif // M2M_PROTO_CMD_BROADCAST_RQ
        // 查询 设备 id 是否在该节点 路由里
        case M2M_PROTO_CMD_ONLINK_CHECK_RQ:
            {   
                if( p_dec->payload.p_data && p_dec->payload.len == sizeof(M2M_id_T)){
					M2M_Address_T addr;
					mmemset((u8*)&addr, 0 ,sizeof(M2M_Address_T));				
                    if( m2m_relay_id_find(&addr, p_net->host.p_router_list, (M2M_id_T*) p_dec->payload.p_data) ){ //  id 在路由记录里.
                        ack_payload.len = sizeof( M2M_Address_T);
                        ack_payload.p_data = (u8*)&addr;
                        ret = net_ack( (u16)M2M_HTTP_OK, M2M_PROTO_IOC_CMD_ONLINK_CHECK_ACK, \
							p_net->protocol.func_proto_ioctl,&enc, p_raw, &ack_payload, NULL);
                    }else{ // id 不在路由记录里
                        ret = net_ack( (u16)M2M_HTTP_NO_CONTENT, M2M_PROTO_IOC_CMD_ONLINK_CHECK_ACK, \
							p_net->protocol.func_proto_ioctl, &enc, p_raw, NULL,NULL);
                    }
                }
            }
            break;
        case M2M_PROTO_CMD_ONLINK_CHECK_ACK:
        {
            Net_request_node_T *p_find = net_request_packet_find(p_net->p_request_hd,p_raw->stoken);
            if( p_find )
                ret =  p_find->callback_arg.func( p_dec->code, NULL, &p_dec->payload, p_find->callback_arg.p_user_arg);
                // destory node .
                LL_DELETE(p_net->p_request_hd, p_find);
                net_request_packet_destory(&p_find);
        }
            break;
		case M2M_PROTO_CMD_NET_SETKEY_RQ:
			// 更新 net secret key.
			if( p_raw->enc_type != M2M_ENC_TYPE_AES128)
				break;
			if(p_dec->payload.len >= sizeof( Net_enc_T) &&  p_dec->payload.p_data ){
			    // 刷新 net 秘钥，
				// 返回到应用层,应用层需要保存起来，再次开机时可以用得到。
				Net_enc_T enc;
				mmemset((u8*)&enc, 0, sizeof(Enc_T));
				enc.type = M2M_ENC_TYPE_NOENC;
				M2M_packet_T *p_ack_payload = NULL;
				m2m_debug_level(M2M_LOG_DEBUG, "net (%p) receive new key.",p_net);
				m2m_debug_level_noend(M2M_LOG_DEBUG, "session receive new key : ");
				m2m_byte_print(p_dec->payload.p_data,p_dec->payload.len);
				ret =  p_net->callback.func( M2M_REQUEST_NET_SET_SECRETKEY,&p_ack_payload, &p_dec->payload,p_net->callback.p_user_arg);
				ret = net_ack( (u16)M2M_HTTP_OK, M2M_PROTO_IOC_NET_SETKEY_ACK, p_net->protocol.func_proto_ioctl, 
				              &enc, p_raw,(M2M_packet_T*)p_ack_payload, NULL);
				PACKET_FREE(p_ack_payload);
				p_ack_payload = NULL;
				// 刷新当前 session 的秘钥.
				_net_secret_key_update( &p_net->enc, (u8*)p_dec->payload.p_data,p_dec->payload.len);
			}
			break;
		case M2M_PROTO_CMD_NET_SETKEY_ACK:
			{
			// update secret key
				Net_request_node_T *p_find = net_request_packet_find(p_net->p_request_hd,p_raw->stoken);
				if(p_find){
					// 使用新的 秘钥 key.
					if( p_find->cmd == M2M_PROTO_CMD_NET_SETKEY_RQ && \
						M2M_ERR_NOERR == _net_secret_key_update(&p_net->enc,  p_find->payload.p_data, p_find->payload.len) ){
						m2m_debug_level_noend(M2M_LOG_DEBUG, "client ack new key setup :");
						m2m_byte_print(p_dec->payload.p_data,p_dec->payload.len);
						_USERFUNC_(p_find,p_dec,ret);
					}
				// destory it 		
				LL_DELETE(p_net->p_request_hd, p_find);
				net_request_packet_destory(&p_find);
            	}
			}
		case M2M_PROTO_CMD_DATA_RQ:
			m2m_debug_level(M2M_LOG_ERROR,">>token was not match rceive ctoken %u stoken %u", p_raw->ctoken, p_raw->stoken);
			net_ack( (u16)M2M_HTTP_TOKEN_NOMATCH, M2M_PROTO_IOC_CMD_DATA_ACK, p_net->protocol.func_proto_ioctl, &enc, p_raw,NULL, NULL);
			// token 不匹配.
			break;
		default:
			m2m_log_warn("receive unknow command.");
			break;
    }

NO_SESSION_HANDLE_END:

    if( p_dec->payload.p_data)
        mfree( p_dec->payload.p_data);
    
    return ret;
}
/**
** 处理 slave 模式下接受 master 发来的包。
** 1. ctoken requests 创建一个 session。 注意 session 应该有不活跃时间，一旦超时应该注销该 session。
** 2. 保存 key，往后该 net 所有的 session 均使用该 key。
** 3. M2M_PROTO_CMD_DATA_RQ 把 payload 上传到上层。
***/
static M2M_Return_T _net_recv_slave_hanle(Net_T *p_net,Session_T *p_s,M2M_proto_recv_rawpkt_T *p_raw){

    int ret = M2M_ERR_NOERR;
    M2M_proto_dec_recv_pkt_T pkt_dec,*p_dec;
    M2M_packet_T ack_payload;
    M2M_dec_args_T dec_args;
    M2M_packet_T *p_ack_payload = NULL;
	M2M_request_pkt_T *p_node = NULL;

    mmemset((u8*)&pkt_dec, 0, sizeof(M2M_proto_dec_recv_pkt_T) );
    mmemset( (u8*)&ack_payload, 0, sizeof(M2M_packet_T));
    
    p_dec = &pkt_dec;
    dec_args.p_dec = &pkt_dec;
    dec_args.p_rawpkt = p_raw;
    pkt_dec.p_enc = &p_s->enc;
    
#if 0
    // list 内存在该节点则 接受。
    // list 内不存在，且接受的 pkt msgid 大于 session 当前的 msgid 则为新的请求包。
    if( !_session_msgid_aliave(p_s, p_raw->msgid) && A_BIGER_U8( p_s->messageid, p_raw->msgid) ){
			m2m_log_warn("id was not match my id is %d receive id is %d", p_s->messageid, p_raw->msgid);
		  	return net_ack( (u16)M2M_HTTP_MSGID_NOMATCH, M2M_PROTO_IOC_CMD_ERR_PKT_ACK, \
           					p_s->protocol.func_proto_ioctl,&p_s->enc, p_raw,NULL, NULL);
    	}
#endif
    // update lift time.
    _session_aliveTime_update(p_s);
    // 4. 解密并解包.
    ret =  ( p_s->protocol.func_proto_ioctl )( M2M_PROTO_IOC_CMD_DECODE_PKT_RQ,&dec_args,0);
    // 获取错误码.
    if( ret != 0){
        if( ret > 0)
            ret = net_ack( (u16)ret, M2M_PROTO_IOC_CMD_ERR_PKT_ACK, \
            			p_s->protocol.func_proto_ioctl,&p_s->enc, p_raw,NULL, NULL);
        m2m_debug_level(M2M_LOG_ERROR, "session <%p> receive package that can't decode.", p_s);
        goto SLAVE_SESSION_HANDLE_END;
    }
	// todo remvoe 
	
	m2m_log_debug("recv cmd = %d", p_dec->cmd);
    // 续命
    switch(p_dec->cmd){
        case M2M_PROTO_CMD_ERR_PKT_RQ:
        case M2M_PROTO_CMD_ERR_PKT_ACK:
            // 对端回应 加密，crc，protocol 解析出错
            p_s->messageid = p_dec->msgid;
            break;
            
        case M2M_PROTO_CMD_TOKEN_RQ:
            {
                M2M_packet_T ack_payload;
                p_s->ctoken = _net_token_creat();
                p_s->messageid = p_dec->msgid;
                
                ack_payload.len = sizeof(u32);
                ack_payload.p_data = (u8*) &p_s->ctoken;
                
                m2m_debug_level( M2M_LOG,"session (%p) creat client token = %x to remote master.", p_s, p_s->ctoken);
                ret = net_ack( (u16)M2M_HTTP_OK, M2M_PROTO_IOC_CMD_TOKEN_ACK, p_s->protocol.func_proto_ioctl,&p_s->enc, p_raw,&ack_payload, NULL);
            }
            break;
        case M2M_PROTO_CMD_SESSION_SETKEY_SET_RQ:
            // 更新 net secret key.
            p_s->messageid = p_dec->msgid;
            if(p_dec->payload.len >= sizeof( Net_enc_T) &&  p_dec->payload.p_data){
                // 刷新 net 秘钥，
               // 返回到应用层,应用层需要保存起来，再次开机时可以用得到。
		        m2m_debug_level(M2M_LOG_DEBUG, "session (%p) receive new key.",p_s);
		        m2m_debug_level_noend(M2M_LOG_DEBUG, "session receive new key : ");
		        m2m_byte_print(p_dec->payload.p_data,p_dec->payload.len);
				if(p_net->callback.func	)
		        	ret =  p_net->callback.func( M2M_REQUEST_SESSION_SET_SECRETKEY,&p_ack_payload, &p_dec->payload,p_net->callback.p_user_arg);
		        ret = net_ack( (u16)M2M_HTTP_OK, M2M_PROTO_IOC_CMD_SESSION_SETKEY_ACK, p_s->protocol.func_proto_ioctl, \
		                        &p_s->enc, p_raw,(M2M_packet_T*)p_ack_payload, NULL);
		        PACKET_FREE(p_ack_payload);
		        p_ack_payload = NULL;
		        // 刷新当前 session 的秘钥.
		        _net_secret_key_update( &p_s->enc, (u8*)p_dec->payload.p_data,p_dec->payload.len);
          	}
            break;
        case M2M_PROTO_CMD_PING_RQ:
        	{
        		M2M_packet_T ack_payload;

				mmemset((u8*) &ack_payload, 0, sizeof(M2M_packet_T));
	            p_s->messageid = p_dec->msgid;
				if(p_s->node_cnt > 0){
					ack_payload.p_data = obs_notify_msgid_alloc(p_s, &ack_payload.len);
					_RETURN_EQUAL_0(ack_payload.p_data , M2M_ERR_NULL);
				}
			    ret = net_ack( (u16)M2M_HTTP_OK, M2M_PROTO_IOC_CMD_PING_ACK, p_s->protocol.func_proto_ioctl,&p_s->enc, p_raw, &ack_payload, NULL);
				mfree(ack_payload.p_data);
        	}
            break;
       	case M2M_PROTO_CMD_DATA_RQ:
        // 把数据回应到应用层。
            p_s->messageid = p_dec->msgid;
			if(p_net->callback.func)
            	ret =  p_net->callback.func( M2M_REQUEST_DATA, &p_ack_payload, &p_dec->payload,p_net->callback.p_user_arg);
            ret = net_ack( (u16)M2M_HTTP_OK, M2M_PROTO_IOC_CMD_DATA_ACK, \
							p_s->protocol.func_proto_ioctl,&p_s->enc, p_raw,(M2M_packet_T*)p_ack_payload, NULL);
            PACKET_FREE(p_ack_payload);
            p_ack_payload = NULL;
            break;
		
		case M2M_PROTO_CMD_SESSION_OBSERVER_RQ:
			ret = obs_rq_handle(p_net, p_s,p_raw, p_dec);
			break;
	
		case M2M_PROTO_CMD_SESSION_OBSERVER_ACK:
			p_node = _net_session_node_find(p_s,p_raw->msgid);
			ret = obs_notify_ack_handle(p_s, p_node, p_raw, p_dec);
			break;
		default:
			m2m_log_warn("slave receive unknow command");
			break;
    }

SLAVE_SESSION_HANDLE_END:

   if(p_dec->p_extra){
		_obs_free((M2M_observer_T**)&p_dec->p_extra);
   }
  
   if( p_dec->payload.p_data)
        mfree( p_dec->payload.p_data);
    return ret;
}


            
static M2M_Return_T _net_recv_master_hanel(
    Net_T *p_net,Session_T *p_s,
    M2M_proto_recv_rawpkt_T *p_raw){

    int ret = M2M_ERR_NOERR;
    M2M_proto_dec_recv_pkt_T pkt_dec,*p_dec;
    M2M_dec_args_T dec_args;

    mmemset((u8*)&pkt_dec, 0, sizeof(M2M_proto_dec_recv_pkt_T) );
    
    p_dec = &pkt_dec;
    dec_args.p_dec = &pkt_dec;
    dec_args.p_rawpkt = p_raw;
    // use session secret key to decode it.
    pkt_dec.p_enc = &p_s->enc;

    //  根据 msgid 查询 node 节点.
    
    M2M_request_pkt_T *p_node = _net_session_node_find(p_s,p_raw->msgid);
    if( p_node == NULL){
        return M2M_ERR_NOERR;
    }
      // 4. 解密并解包.
    ret =  ( p_net->protocol.func_proto_ioctl )( M2M_PROTO_IOC_CMD_DECODE_PKT_RQ,&dec_args,0);
    // 获取错误码.
    if( ret != 0){
        p_dec->code = (u16)ret;
        
        m2m_debug_level(M2M_LOG_ERROR, "net <%p> (%p) receive ack that can't decode.", p_net, p_s);
    // 解析出错，回应应用层
       _USERFUNC_(p_node,p_dec,ret);
       session_node_destory(&p_s->p_request_head,&p_node);
	   _SESSION_NODE_CNT_REDUCE(p_s);
        goto MASTER_RECV_HANDLE_END;
    }
    // 续命
    //_session_aliveTime_update( p_s );
	_connt_handle(&p_s->connt, M2M_CONNET_ON);

	m2m_log_error("Master receive cmd %d", p_node->cmd);
	switch(p_node->cmd){
        case M2M_PROTO_CMD_ERR_PKT_RQ:
        case M2M_PROTO_CMD_ERR_PKT_ACK:
            // 对端回应 加密，crc，protocol 解析出错
            _USERFUNC_(p_node,p_dec,ret);
            break;
        // 更新 ctoken
        case M2M_PROTO_CMD_TOKEN_RQ:
            if( p_dec->cmd == M2M_PROTO_CMD_TOKEN_ACK && p_dec->payload.len ==  sizeof(u32) && p_dec->payload.p_data){
                mcpy( (u8*)&p_s->ctoken, (u8*)p_dec->payload.p_data,sizeof(u32));
                _SESSION_STA_SET_TOKEN(p_s);
                // all unsending node will be send in next trysync 
                _session_update_sendtime(p_s);
                m2m_debug_level( M2M_LOG,"net <%p> (%p) receive client token = %x.", p_net, p_s, p_s->ctoken);
            }
            // 回调
            _USERFUNC_(p_node,p_dec,ret);
            // 删除节点.
            // todo is  the base way ??
            _ne_sendingId_increase(p_s);
            session_node_destory(&p_s->p_request_head,&p_node);
			_SESSION_NODE_CNT_REDUCE(p_s);
            break;
        case M2M_PROTO_CMD_SESSION_SETKEY_SET_RQ:
            {
                Enc_T *p_enc = (Enc_T*) p_node->p_proto_data;
            // 使用新的 秘钥 key.
                if( p_dec->cmd == M2M_PROTO_CMD_SESSION_SETKEY_SET_ACK && \
                    M2M_ERR_NOERR == _net_secret_key_update(&p_s->enc, p_node->p_proto_data, p_node->len) ){
                    m2m_debug_level_noend(M2M_LOG_DEBUG, "client ack new key setup :");
                    m2m_byte_print(p_dec->payload.p_data,p_dec->payload.len);
                    _USERFUNC_(p_node,p_dec,ret);
                }
                
                _ne_sendingId_increase(p_s);
                session_node_destory(&p_s->p_request_head,&p_node);
				_SESSION_NODE_CNT_REDUCE(p_s);
            }
            break;
        case M2M_PROTO_CMD_PING_RQ:
        // 延迟下一次ping 的时间.
            session_pingDelay(p_s);
            _ne_sendingId_increase(p_s);
			// 检查 notify，若回应的 notify 跟自身的 notify 对不上清除掉。
			obs_single_notify_clean(p_s, &p_dec->payload);
            session_node_destory(&p_s->p_request_head,&p_node);
			_SESSION_NODE_CNT_REDUCE(p_s);
            break;
        // 接收数据。
        case M2M_PROTO_CMD_DATA_RQ:
            m2m_debug_level(M2M_LOG_DEBUG,"net <%p> (%p) receive data.", p_net, p_s);
            _USERFUNC_(p_node,p_dec,ret);
        
            _ne_sendingId_increase(p_s);
            session_node_destory(&p_s->p_request_head,&p_node);
			_SESSION_NODE_CNT_REDUCE(p_s);
            break;
		// handle notification. handle ack.
		case M2M_PROTO_CMD_SESSION_OBSERVER_RQ:
		// handle observer ack
			if( p_dec->cmd == M2M_PROTO_CMD_SESSION_OBSERVER_ACK){
				obs_ack_handle(p_s, p_node, p_raw, p_dec);
			}else if( p_dec->cmd == M2M_PROTO_CMD_SESSION_OBSERVER_RQ ){
				ret = obs_notify_rq_handle(p_s, p_node, p_raw, p_dec);
			}
			break;
		default:
			m2m_log_warn("master receive unknow command");
			break;
    }
MASTER_RECV_HANDLE_END:

	if(p_dec->p_extra){
		 _obs_free((M2M_observer_T**)&p_dec->p_extra);
	}
    if( p_dec->payload.p_data)
        mfree( p_dec->payload.p_data);
    return M2M_ERR_NOERR;
}
static Session_T *_net_session_find(Net_T *p_net,M2M_proto_recv_rawpkt_T *p_pkt){

    Session_T *p_el = NULL, *p_tmp = NULL, *p_s_find = NULL;
    
    LL_FOREACH_SAFE( p_net->p_session_head, p_el, p_tmp){
		if( DEV_ID_EQUAL(p_pkt->src_id,p_el->dst_id)  
			&& p_pkt->stoken ==  p_el->stoken 
			&& p_pkt->ctoken ==  p_el->ctoken ){
	            p_s_find = p_el;
	            break;
        }
    }
    return p_s_find;
}
static M2M_request_pkt_T *_net_session_node_find(Session_T *p_s,u8 msgid){
        M2M_request_pkt_T *p_find = NULL,*p_el,*p_tmp;
        LL_FOREACH_SAFE( p_s->p_request_head, p_el, p_tmp){
        if( p_el->messageid == msgid)
            return p_el;
        }
        return NULL;
}
static Session_T *_session_node_belong_find(Net_T *p_net, M2M_request_pkt_T *p_pkt){
    Session_T *p_sel = NULL, *p_stmp = NULL, *p_sfind = NULL;
    
    LL_FOREACH_SAFE( p_net->p_session_head, p_sel, p_stmp){
		
		M2M_request_pkt_T *p_find = NULL,*p_el,*p_tmp;
		LL_FOREACH_SAFE( p_sel->p_request_head, p_el, p_tmp){
			if( p_el == p_pkt ){
					p_sfind = p_sel;
					break;
			}
		}

    }
    return p_sfind;

}
// 1. 对发给本地的包进行接收处理.
// 
static M2M_Return_T _net_recv_handle( Net_T *p_net){
    int ret = 0;
    Session_T *p_s = NULL;
    
    M2M_proto_recv_rawpkt_T  recv_rawpkt, *p_raw;
    m2m_assert(p_net,M2M_ERR_INVALID);
   
    mmemset( (u8*)&recv_rawpkt,0,sizeof(M2M_proto_recv_rawpkt_T));


    recv_rawpkt.payload.p_data = mmalloc( M2M_PROTO_PKT_MAXSIZE );
    _RETURN_EQUAL_0(recv_rawpkt.payload.p_data, M2M_ERR_NULL);

    recv_rawpkt.payload.len = M2M_PROTO_PKT_MAXSIZE;
    recv_rawpkt.socket_fd = p_net->protocol.socket_fd;
    p_raw = &recv_rawpkt;
    if(p_net->protocol.func_proto_ioctl == 0)
		goto RECV_HAND_END;
// 1. 接收数据.  
    ret = ( p_net->protocol.func_proto_ioctl )( M2M_PROTO_IOC_CMD_RECVPKT_RQ,&recv_rawpkt,0);
    if( ret <= 0 ){
        if(ret < 0)
            m2m_log_warn("net <%p> (%p) receive package access an error !!", p_net, p_s);
        // no package was received.
        goto RECV_HAND_END;
        }
#ifdef CONF_BROADCAST_ENABLE
    //处理广播包
    if( p_net->broadcast_en && recv_rawpkt.enc_type == M2M_ENC_TYPE_BROADCAST){
        ret = broadcast_recv_handle(p_net, &recv_rawpkt);
        goto RECV_HAND_END;
    }
#endif // CONF_BROADCAST_ENABLE

// 2. 若不是发送给本地则查询是否需要转发.
    if(  !DEV_ID_EQUAL( p_net->my, recv_rawpkt.dst_id)){
        // relay package. id　不匹配
        m2m_debug_level( M2M_LOG_DEBUG,"Id was not match.");
        ret = _net_relay_handle(p_net,&recv_rawpkt);
        goto RECV_HAND_END;
    }
	// id 匹配 正确
	// 刷新设备的在线时间。
    _ROUTER_LIST_ADD_DEVICE(p_net,p_raw);
    p_s = _net_session_find(p_net,&recv_rawpkt);
    if( p_s == NULL){
        m2m_debug_level( M2M_LOG_WARN,"Token was not match.");
        _net_recv_handle_without_session(p_net,&recv_rawpkt);
        goto RECV_HAND_END;
    }else {
            if( p_s->type == SESSION_TYPE_SLAVE ){
                ret = _net_recv_slave_hanle(p_net,p_s, &recv_rawpkt);
            } else if(p_s->type == SESSION_TYPE_MASTER){
                ret  = _net_recv_master_hanel(p_net,p_s, &recv_rawpkt);
            }
        }
RECV_HAND_END:
    if( recv_rawpkt.payload.p_data )
        mfree( recv_rawpkt.payload.p_data );
    return ret;
}
/************** 重发处理 *************************************************************************************/
static BOOL _net_isTimeout(u32 src, u32 dst, u32 timeout){
    if(src >= dst){
        if(src - dst >
         timeout)
            return TRUE;
        return FALSE;
    }else{
        //fallbackp
        if(src + (0xffffffff - dst) > timeout)
            return TRUE;
        return FALSE;
    }
}

/**
** 1. 重发每个 session 中超时没有收到回应的节点包。
** 2. 若超出重发次数，则删除该节点。
*****/
static M2M_Return_T session_retransmit(Net_T *p_net){
    int ret = 0;
    m2m_assert(p_net,M2M_ERR_INVALID);

    // 1. 遍寻每个 session.
    Session_T *p_el,*p_tmp;
    LL_FOREACH_SAFE( p_net->p_session_head, p_el, p_tmp){
        M2M_request_pkt_T *p_node_el,*p_node_tmp;
    // 2.遍寻session 中每个节点.
        LL_FOREACH_SAFE(p_el->p_request_head, p_node_el, p_node_tmp){
    // 3. 对于notify 节点只会重发     的 notify 数据，不会自动再 trysync 中删除
    		if( p_node_el->extra_cmd == EXTRA_CMD_NOTIFY  ){
					ret = obs_notify_retransmit(p_net, p_el, p_node_el); 
					continue;
			}
   // 3. 超时删除.
            if( _net_isTimeout(m2m_current_time_get(),p_node_el->register_time,NET_RETRAMIT_TIMOUT_MS)){
  // 3.1 触发超时回调.
                if( p_node_el->callback_arg.func != 0)
                    p_node_el->callback_arg.func( M2M_ERR_TIMEOUT,0,NULL,p_node_el->callback_arg.p_user_arg);
  // 3.2 移除节点。
                m2m_debug_level(M2M_LOG_DEBUG,"net <%p> (%p) node %p timeout, delete it.",  p_net, p_el,p_node_el);
				
				// ping 丢失 没有响应  则 设置 session 状态
				if( p_node_el->cmd == M2M_PROTO_CMD_PING_RQ )
					_connt_handle(&p_el->connt, M2M_CONNT_LOST);
				
                _ne_sendingId_increase(p_el);
                session_node_destory( &p_el->p_request_head, &p_node_el);
				_SESSION_NODE_CNT_REDUCE(p_el);
  // 4. 到达下一个重发节点，重发.
            }else if( A_BIGER_U32(m2m_current_time_get(),p_node_el->next_send_time) ){
					ret = _net_proto_request_retransmit_send(p_net,p_el,p_node_el);
            }
        }  // end with session node circulation.
    }
    return M2M_ERR_NOERR;
}
/**
* descript: 维持连接.定时发送ping.
*   1.判断是否达到发送ping 的时间。
*   2. 发送   ping.
**/ 
static M2M_Return_T session_keepAlive(Net_T *p_net){
    int ret = 0; 
    m2m_assert(p_net,M2M_ERR_INVALID);

    Session_T *p_el,*p_tmp;
    //if( NULL ==  p_net->host.p_host )
    //    return M2M_ERR_NOERR;
    
    LL_FOREACH_SAFE(p_net->p_session_head, p_el, p_tmp){
    //1.发送 ping 包.
        if( p_el->keep_ping_en &&A_BIGER_U32( m2m_current_time_get(),p_el->next_ping_send_tm)){
            Net_Args_T args;
            mmemset( (u8*)&args,0,sizeof(Net_Args_T));
            args.p_s = p_el;
            args.p_net = p_net;
            mcpy( (u8*)&args.remote.dst_address, (u8*)&p_el->dest_addr,sizeof(M2M_Address_T));
            session_ping_send(&args,0);
        }
            
    }
    return 0;
}
// 清理长时间不活跃的僵尸 session
static M2M_Return_T net_session_clearn(Net_T *p_net){
    Session_T *p_el,*p_tmp;
    LL_FOREACH_SAFE( p_net->p_session_head, p_el, p_tmp){
    if( p_el->type == SESSION_TYPE_SLAVE && _session_timeout(p_el) ){
            Net_Args_T na;
            na.p_net = p_net;
            na.p_s = p_el;
            m2m_debug_level(M2M_LOG_DEBUG,"net <%p> clearn session %p", p_net, p_el);
            session_destory(&na,0);
        }
    }
    return M2M_ERR_NOERR;
}
// 1. 接收处理.
// 2. 重发处理.
// 3. 连接的维持，ping 的发送.
static M2M_Return_T net_trysync( Net_Args_T *p_args,int flags ){

    m2m_assert(p_args,M2M_ERR_INVALID);
    m2m_assert(p_args->p_net,M2M_ERR_INVALID);

    Net_T *p_net = p_args->p_net;
    // 1. 接收处理
    int ret =  _net_recv_handle(p_net);
    
    // 2. 重发处理.
    session_retransmit(p_net);
    // 3.连接维持.
    // todo 
     session_keepAlive(p_net);
    // 广播、 onlink check 包发送.
    // 4. session 维护，清理僵尸 session.
    net_session_clearn(p_net);
    net_request_retransmit(p_net);
    // 5. session 
    // 5. 定期往 host 发送 ping
    if( p_net->host.p_host && p_net->host.keep_ping_host_en){
        _net_host_ping( p_net);
    }
    // 6. 清理不活跃的 ip 列表。
    if( p_net->host.relay_en ){
        
        m2m_relay_list_update( &p_net->host.p_router_list, p_net->max_router_tm);
    }
    return 0;
}
// 构造   net request  node, 并挂到 net 链表
static Net_request_node_T *net_request_packet_creat(Net_Args_T *p_args,M2M_Proto_Cmd_T cmd){
    m2m_assert(p_args, NULL);

    int ret = M2M_ERR_NULL;
    Net_T *p_n = p_args->p_net;

    Net_request_node_T *p_node = mmalloc( sizeof(Net_request_node_T));
    _RETURN_EQUAL_0(p_node, NULL);
    Net_Remot_Address_T *p_remote = &p_args->remote;

    // 获取远端的 ip
    if( p_remote->p_host ){
       //  get remote ip.
       m2m_gethostbyname( &p_node->remote, (char*)p_remote->p_host);
    }else if( p_remote->dst_address.len > 0 )
       mcpy( (u8*) &p_node->remote,(u8*)&p_remote->dst_address ,sizeof(M2M_Address_T));
    
    // 获取秘钥.
    p_node->enc.type = p_args->enc.type;
    if(p_args->enc.keylen > 0 && p_args->enc.p_enckey){
           p_node->enc.p_enckey = mmalloc( p_args->enc.keylen );
           _RETURN_EQUAL_FREE(p_node->enc.p_enckey, 0, p_node, NULL);
           ENC_COPY(p_node->enc, p_args->enc);
    }

    p_node->remote.port = p_args->remote.dst_address.port;
    p_node->cmd = cmd;
    p_node->payload.len = p_args->len;
    p_node->stoken = _net_stoken_creat( p_args->p_net);
    p_node->next_send_time = m2m_current_time_get();
       
    p_node->callback_arg.func = p_args->callback.func;
    p_node->callback_arg.p_user_arg = p_args->callback.p_user_arg;
	mcpy((u8*)&p_node->rid, (u8*)&p_args->remote_id, sizeof(M2M_id_T));

    if( p_args->len > 0 && p_args->p_data ){
       p_node->payload.p_data = mmalloc( p_args->len + 1);
       if( !p_node->payload.p_data && p_node->enc.p_enckey)
            mfree(p_node->enc.p_enckey);
       _RETURN_EQUAL_FREE(p_node->payload.p_data, 0, p_node, NULL);
       mcpy( (u8*)p_node->payload.p_data, (u8*)p_args->p_data,p_args->len);
    }

    LL_APPEND(p_n->p_request_hd, p_node);
    return p_node;
}
static M2M_Return_T net_request_packet_destory(Net_request_node_T **pp_node ){
	
    Net_request_node_T *p_node = *pp_node;
	// free 
	if( !p_node)
		return M2M_ERR_INVALID;
	if( p_node->callback_arg.func){
		p_node->callback_arg.func( (int)M2M_ERR_REQUEST_DESTORY, NULL, NULL, p_node->callback_arg.p_user_arg); 
		p_node->callback_arg.p_user_arg = NULL;
	}
    if( pp_node && p_node && p_node->payload.p_data ){
        mfree( p_node->payload.p_data);
        p_node->payload.p_data = NULL;
    }

    if(p_node && p_node->enc.p_enckey)
        mfree( p_node->enc.p_enckey);
    
    mfree(p_node);
    *pp_node = NULL;
	
	return M2M_ERR_NOERR;
}
static Net_request_node_T *net_request_packet_find(Net_request_node_T *p_hd, u32 stoken){
    Net_request_node_T *p_find = NULL, *p_tmp;

    // find node 
    if( p_hd){
        LL_FOREACH_SAFE( p_hd, p_find, p_tmp){
            if( p_find->stoken == stoken )
                return p_find;
        }
    }
    
    return NULL;
}
static M2M_Return_T net_request_send(Net_T *p_net, Net_request_node_T *p_el){

    
    M2M_Proto_Cmd_Arg_T args;
    mmemset((u8*)&args, 0, sizeof(M2M_Proto_Cmd_Arg_T));

    args.socket_fd = p_net->protocol.socket_fd;
    args.payloadlen = p_el->payload.len;
    args.p_payload = p_el->payload.p_data;
    args.p_enc = &p_el->enc;
    args.stoken = p_el->stoken;
    
    CPY_DEV_ID(args.src_id,p_net->my);
    CPY_DEV_ID(args.dst_id,p_el->rid);
    mcpy( (u8*)&args.address, (u8*)&p_el->remote, sizeof(M2M_Address_T));
    return p_net->protocol.func_proto_ioctl( p_el->cmd, &args, 0);
    
}
// 对于挂在 net 里 非 广播包进行重传
static M2M_Return_T net_request_retransmit(Net_T *p_net){
    Net_request_node_T *p_hd, *p_el, *p_tmp;
    int ret = 0;
    
    LL_FOREACH_SAFE(p_net->p_request_hd, p_el, p_tmp){

        // 不重发 广播包.
#ifdef CONF_BROADCAST_ENABLE
        if(p_el->cmd == M2M_PROTO_CMD_BROADCAST_RQ ){
            ret = net_request_send(p_net, p_el);
            }else
#endif // CONF_BROADCAST_ENABLE
            { // 非广播包.
            if( p_el->retransmit_count >= 5){
                //  超时，不再重传
                if( p_el->callback_arg.func){
                    p_el->callback_arg.func( M2M_ERR_TIMEOUT,0,NULL,p_el->callback_arg.p_user_arg);
                }
                LL_DELETE(p_net->p_request_hd, p_el);
                net_request_packet_destory( &p_el);
                }
            else if( A_BIGER_U32( m2m_current_time_get(),  p_el->next_send_time) ){
                // 重传.
                ret = net_request_send(p_net, p_el);
                p_el->next_send_time =  _net_getNextSendTime(  ++(p_el->retransmit_count) );
            }
        }
    }
    return 0;
}
static M2M_Return_T net_requestlist_destory(Net_T *p_net){
    Net_request_node_T *p_current,*p_tmp;
    LL_FOREACH_SAFE(p_net->p_request_hd, p_current, p_tmp){
        LL_DELETE(p_net->p_request_hd, p_current);
        net_request_packet_destory(&p_current);
    }
    m2m_debug_level(M2M_LOG_DEBUG,"net <%p> request list destory!!",p_net);
    return M2M_ERR_NOERR;
}
static M2M_Return_T net_secretkey_set_rq(Net_Args_T *p_args, int flags){
    m2m_assert(p_args, M2M_ERR_INVALID );
    int ret = M2M_ERR_NOERR;
    
    Net_request_node_T *p_node = net_request_packet_creat(p_args,M2M_PROTO_CMD_NET_SETKEY_RQ);
    _RETURN_EQUAL_0(p_node, M2M_ERR_NULL);

    ret = net_request_send(p_args->p_net, p_node);
    // send out secretkey set request. 
    m2m_debug_level( M2M_LOG,"net <%p> send out secert key set request successfully!!", p_args->p_net);
    return ret;
}

static M2M_Return_T net_online_check_rq(Net_Args_T *p_args, int flags){
    m2m_assert(p_args, M2M_ERR_INVALID );
    int ret = M2M_ERR_NOERR;

	CPY_DEV_ID(p_args->remote_id, p_args->p_net->host.host_id);
    Net_request_node_T *p_node = net_request_packet_creat(p_args,M2M_PROTO_CMD_ONLINK_CHECK_RQ);
    _RETURN_EQUAL_0(p_node, M2M_ERR_NULL);

    ret = net_request_send(p_args->p_net, p_node);
    // send out onlink check
    m2m_debug_level( M2M_LOG,"net <%p> send out onlink chek to %s successfully!!", p_args->p_net,p_args->remote.p_host);
    return ret;
}
static BOOL net_connt_status_get(Net_Args_T *p_args, int flags){

    m2m_assert(p_args, 0);
    m2m_assert(p_args->p_net, 0);

	Net_T *p_net =  p_args->p_net;
	return (BOOL) p_net->host.connt.status;
}
#ifdef CONF_BROADCAST_ENABLE
// 开始发送广播包
static M2M_Return_T broadcast_start( Net_Args_T *p_args,int flags){
    int ret = 0;
	
    mmemset( (u8*)&p_args->remote_id, 0, sizeof(M2M_id_T ));
    Net_request_node_T *p_node = net_request_packet_creat(p_args, M2M_PROTO_CMD_BROADCAST_RQ);
    if( p_node != M2M_ERR_NOERR)
        return M2M_ERR_NULL;
    
    ret =  net_request_send( p_args->p_net, p_node);
    m2m_debug_level( M2M_LOG,"net <%p> start broadcast  successfully!!",p_args->p_net);
    return ret;
}
// 停止发送
static M2M_Return_T broadcast_stop( Net_T *p_net,int flags ){
    
    Net_request_node_T *p_current,*p_tmp;
    LL_FOREACH_SAFE(p_net->p_request_hd, p_current, p_tmp){

        if(p_current->cmd == M2M_PROTO_CMD_BROADCAST_RQ){
            LL_DELETE(p_net->p_request_hd, p_current);
            net_request_packet_destory(&p_current);
            }
    }
    m2m_debug_level(M2M_LOG_DEBUG,"net <%p> broadcast stop !!",p_net);
    return M2M_ERR_NOERR;
}
/**
** description: 1. 解码 payload 部分。
**              2. 对于非 ping 则正常回应，token 则生成 新的token 并创建 session。
**  3 处理 ping，广播，查询设备在线的包。
**/
static M2M_Return_T broadcast_recv_handle
    ( 
        Net_T *p_net,
        M2M_proto_recv_rawpkt_T *p_raw){
    int ret =0;
    M2M_proto_dec_recv_pkt_T pkt_dec,*p_dec;
    M2M_dec_args_T dec_args;
    Net_enc_T enc;
    M2M_packet_T ack_payload;

    mmemset( (u8*)&pkt_dec, 0, sizeof(M2M_proto_dec_recv_pkt_T));
    mmemset( (u8*)&enc,0,sizeof(Net_enc_T));
    mmemset( (u8*)&ack_payload, 0, sizeof(M2M_packet_T));
    
    p_dec = &pkt_dec;
    
    dec_args.p_dec = &pkt_dec;
    dec_args.p_rawpkt = p_raw;
    pkt_dec.p_enc = &p_net->enc;
    enc.type = p_raw->enc_type;

    // 4. 解密并解包.
    ret =  ( p_net->protocol.func_proto_ioctl )( M2M_PROTO_IOC_CMD_DECODE_PKT_RQ,&dec_args,0);
    
    // 获取错误码.
    if( ret != 0){
        // no ack  while receive wrong broad cast package.
        m2m_debug_level(M2M_LOG_ERROR, "net <%p> receive package that can't decode.", p_net); 
        goto RECV_BROADCAST_END;
    }
    switch( p_dec->cmd){

        case M2M_PROTO_CMD_BROADCAST_RQ:
            {
                M2M_packet_T *p_ack_payload = NULL;
                ret = p_net->callback.func( M2M_REQUEST_BROADCAST, &p_ack_payload, &p_dec->payload,p_net->callback.p_user_arg);
                ret = net_ack( M2M_HTTP_OK, M2M_PROTO_IOC_CMD_BROADCAST_ACK, \
								p_net->protocol.func_proto_ioctl, &enc, p_raw, p_ack_payload, NULL);
                PACKET_FREE(p_ack_payload);
                p_ack_payload = NULL;
            }
            break;

        case M2M_PROTO_CMD_BROADCAST_ACK:
            {
            Net_request_node_T *p_find = net_request_packet_find(p_net->p_request_hd,p_raw->stoken);
            if( p_find )
                ret =  p_find->callback_arg.func( M2M_REQUEST_BROADCAST_ACK, NULL, &p_dec->payload, p_find->callback_arg.p_user_arg);
            }
            break;
    }
RECV_BROADCAST_END:

    if( p_dec->payload.p_data)
        mfree( p_dec->payload.p_data);

    return ret;
}

#endif //CONF_BROADCAST_ENABLE.

// 1.同 net_trysync().
// 2.自带锁功能.
static M2M_Return_T net_trysync_lock(Net_Args_T *p_args,int flags){
    return 0;
}
/* protocol :: coap  interface */
m2m_func net_funcTable[M2M_NET_CMD_MAX + 1] = 
{


    //M2M_NET_CMD_SESSION_CREAT = 0,
    (m2m_func) session_creat_rq,
    //M2M_NET_CMD_SESSION_DESTORY,
    (m2m_func) session_destory,
    //M2M_NET_CMD_SESSION_TOKEN_UPDATE,
    (m2m_func) session_token_update,
    //M2M_NET_CMD_SESSION_SECRETKEY_SET,
    (m2m_func) session_secretkey_set,
    //M2M_NET_CMD_SESSION_DATA_SEND,
    (m2m_func) session_data_send,
    //M2M_NET_CMD_SESSION_PING_SEND,
    (m2m_func) session_ping_send,
    // M2M_NET_CMD_SESSION_CONNT_CHECK
	(m2m_func) session_connt_chack,
	//M2M_NET_CMD_SESSION_OBSERVER_START,
	(m2m_func) session_obs_start,
	//M2M_NET_CMD_SESSION_OBSERVER_STOP,
	(m2m_func) session_obs_stop,
	//M2M_NET_CMD_SESSION_NOTIFY_PUSH,
	(m2m_func) session_obs_notify_push,
#ifdef CONF_BROADCAST_ENABLE
    //M2M_NET_CMD_BROADCAST_START,  // 开始 广播包
    (m2m_func) broadcast_start,
    //M2M_NET_CMD_BROADCAST_STOP,
    (m2m_func) broadcast_stop,
#endif //CONF_BROADCAST_ENABLE
	//M2M_NET_CMD_NET_SECRETKEY_SET
	(m2m_func) net_secretkey_set_rq,
    // M2M_NET_CMD_TRYSYNC,
    (m2m_func) net_trysync,
    // M2M_NET_CMD_ONLINE_CHECK
    (m2m_func) net_online_check_rq,
    // M2M_NET_CMD_CONNT_CHECK
    ( m2m_func) net_connt_status_get,
    //M2M_NET_CMD_MAX
    NULL
};
// 获取协议处理函数.
size_t net_ioctl
    ( M2M_Proto_Cmd_T cmd,void *p_args,int flags)
{
    
    Net_Args_T *p = p_args;
    size_t ret = 0;
    if( cmd >= M2M_NET_CMD_MAX )
        return M2M_ERR_INVALID;

    if(net_funcTable[cmd]){
        
        _m2m_net_lock(p->p_net);
        ret = (net_funcTable[cmd])(p_args,flags);
        _m2m_net_unlock( p->p_net);
        return ret;
    }else{
        m2m_debug_level(M2M_LOG_WARN, "net function Cannot find function %d!",cmd);
        return 0;
    }
}
    
/** 功能：
* 1.管理： 双链表响应接收包.
* 2.封包发送，把请求节点挂入链表。
* 3.重发。
* 4.持续发送心跳维持 session.
***************/
/**
** decription: 创建 net.
**          1. 建立 socket,获取 host ip,计算下一个发往 host ping 的时间.
**          2. 初始化下一层协议.
**          3. 初始化路由列表.
** args:    p_arg - 参数.
**          flags - 扩展之用.
**********************/
Net_T *net_creat( Net_Init_Args_T *p_arg,int flags){

    int ret = 0;
    Net_T *p_net = mmalloc(sizeof(Net_T));
    if( !p_net )
        return 0;

#ifdef HAS_LINUX_MUTEX
    ret = pthread_mutex_lock(&p_net->locker);  //返回0为成功    
    if(ret){
        m2m_debug_level(M2M_LOG_ERROR," creat mutex failt.");
        return 0;
    }
#endif

    CPY_DEV_ID(p_net->my,p_arg->my);
    CPY_DEV_ID(p_net->host.host_id,p_arg->host_id);

    // ioctl 函数 注册.
    p_net->ioctl_session = net_ioctl;
    p_net->callback.func = p_arg->callback.func;
    p_net->callback.p_user_arg = p_arg->callback.p_user_arg;
    p_net->max_router_tm = p_arg->max_router_tm;
    p_net->broadcast_en = 1; // enable broadcast.
    // key copy.
    ENC_ALLOC_COPY(p_net->enc,p_arg->enc);
    if( p_net->enc.keylen > 0 )
        _RETURN_EQUAL_FREE(p_net->enc.p_enckey , 0, p_net, NULL);

    // protocol init 
    p_net->protocol.local_port = p_arg->port;
    ret = m2m_protocol_init( &p_net->protocol );
    if(ret < 0){
        m2m_debug_level(M2M_LOG_ERROR,"Net <%p> open socket failt ret = %d", p_net,ret);
        mfree(p_net);
        return 0;
    }
    
    m2m_debug_level(M2M_LOG,"net <%p> successfully creat!!",p_net);
    /** host server config ************/
    // 1. get host
    // 2. get host ip
    p_net->host.relay_en = p_arg->relay_en;
    p_net->host.addr.port = p_arg->hostport;
    if( p_net->host.relay_en){
       p_net->host.stoken = _net_stoken_creat(p_net);
       p_net->host.p_router_list = m2m_relay_list_creat();
    }
    if( p_arg->p_host ){
        p_net->host.relay_en = p_arg->relay_en;
        ALLOC_COPY( p_net->host.p_host, p_arg->p_host,strlen( (const char*)p_arg->p_host));
        // 获取 host ip
        m2m_gethostbyname( &p_net->host.addr, (char*)p_arg->p_host );
    
        if( p_net->host.p_host == NULL){
            // todo destory p_net
            net_destory(p_net);
            return NULL;
        }else{
            p_net->host.keep_ping_host_en = 1;
            _net_host_ping(p_net);
            }
        // 是否为其它包提供中转功能.
    }
    
    return p_net;
}
/****
** description: 删除 Net.
**      1. 清空 session 里的node。
**      2. 清空 session.
**      3. 关闭 socket，清空 net.
****/
M2M_Return_T net_destory(Net_T *p_net){
    int ret = 0;
    m2m_assert(p_net, M2M_ERR_INVALID);
    Session_T *p_s_el,*p_s_tmp;
    
    LL_FOREACH_SAFE(p_net->p_session_head, p_s_el, p_s_tmp){
    // 1. 清空 session 里的 node.
    // 2. 清空 session.
        Net_Args_T na;
        na.p_net = p_net;
        na.p_s = p_s_el;
        session_destory(&na,0);
    }

	// touch callback
	if( p_net->callback.func ){
		p_net->callback.func( (int)M2M_ERR_REQUEST_DESTORY, NULL, NULL,p_net->callback.p_user_arg); 
		p_net->callback.p_user_arg = NULL;
	}
	net_requestlist_destory(p_net);
    // destory protocol, 例如关闭 socket.
    m2m_protocol_deInit(&p_net->protocol);
    
#ifdef HAS_LINUX_MUTEX
    pthread_mutex_t locker = p_net->locker;
#endif

    mfree(p_net->enc.p_enckey);
    //  host free
    if(p_net->host.p_host){
        mfree( p_net->host.p_host );
        p_net->host.p_host = 0;
    }
    // 释放 在线列表
    m2m_relay_list_destory(&p_net->host.p_router_list);
    m2m_debug_level(M2M_LOG,"net <%p> destory.\n",p_net);
    mfree(p_net);

#ifdef HAS_LINUX_MUTEX
    pthread_mutex_unlock(&locker);
    pthread_mutex_destroy(&locker);
#endif

    return M2M_ERR_NOERR;
}

