/*
 * m2m projuct
 *
 * FileName: m2m_api.c
 *
 * Description: api that provide to thrid party applications.
 *
 * Author: skylli
 */
#include "../../include/m2m.h"
#include "../../include/util.h"
#include "../../include/m2m_api.h"
#include "../../config/config.h"

#include "../network/network.h"
#include "../network/m2m/m2m_protocol.h"
#include "../util/m2m_log.h"

#ifdef __cplusplus
extern "C"
{
#endif

M2M_conf_T m2m_conf;


#define NET_IOCTL(p_n,cmd,arg,flag) do{    if(p_n->ioctl_session) \
                                                p_n->ioctl_session(,arg,0);}while(0);

#define _NET_ARG_CPY(arg,p_m2m,func,p_args)  do{     arg.p_net = (Net_T*) p_m2m->net;        \
                                arg.p_s = (Session_T*) p_m2m->session;  \
                                arg.callback.func = func;   \
                                arg.callback.p_user_arg = p_args;  }while(0)


void m2m_version(void){
    m2m_printf(" m2m version ... \n");
}

// 创建一个 net
// 一个 net 维护一个 port，同时在一个 net 里可以创建多个 session
/**
** decription: 创建 net，建立 socket，初始化本地一个 net。
**          net 可以维护多个 session，同时维持一个跟 host 的连接.
**          server 端单独调用该接口就可以直接 调用 trysync 对表进行接收并处理;
** args:    p_id - net 的 id, port - socket 端口.
**          p_key - net 本地的秘钥，其它 net 要跟该net 通讯时需要使用该秘钥加解密。 key_len - 秘钥长度.
**          p_host - 该 net 连接的 host. 没有上一级 host 则设置为 NULL.
**          p_func - 该 net 接收到数据包的回调函数. 作为 server 时，net 接收到的包会触发该回调。
**              注意： 收到发送给本 id 的包才会触发，其它包则丢弃，或者 直接转发.
**         
**********************/
size_t m2m_net_creat( M2M_id_T *p_id,int port, int key_len, u8 *p_key, M2M_id_T *p_hid,u8 *p_host, int hostport,m2m_func func, void *p_args){

	u8 *p_key_alloc = NULL;
    Net_Init_Args_T cmd;
    Net_T *p_n = NULL;
    m2m_log_debug("creating Net...");
    mmemset( (u8*) &cmd,0,sizeof(Net_Init_Args_T));

    mcpy((u8*) &cmd.my, (u8*)p_id,sizeof(M2M_id_T));

	if(p_hid)
    	mcpy((u8*) &cmd.host_id, (u8*) p_hid, sizeof(M2M_id_T));
	

	cmd.port = port;
    cmd.p_host = p_host;
    
    cmd.callback.func = func;
    cmd.callback.p_user_arg = p_args;
    cmd.enc.type = m2m_conf.def_enc_type;

	if(key_len < 16){
		p_key_alloc = (u8*)mmalloc(17);
		_RETURN_EQUAL_0(p_key_alloc, 0);
		mcpy(p_key_alloc, p_key, key_len);
		cmd.enc.keylen = 16;
		cmd.enc.p_enckey = p_key_alloc;
	}else{
		cmd.enc.keylen = key_len;
    	cmd.enc.p_enckey = p_key;
		}
	cmd.max_router_tm = m2m_conf.max_router_tm;
    cmd.relay_en = m2m_conf.do_relay;
    cmd.max_router_tm = 6* (DEFAULT_INTERVAL_PING_TM_MS);
    cmd.hostport =  hostport;

    // creat network
    p_n = net_creat(&cmd,0);
    m2m_log_debug("network <%p> have been creat.\n",p_n);

	mfree(p_key_alloc);
    return (size_t)p_n;
}
/**
**description: 销毁 net。
**          清除net 内所有的 session，以及对应的节点，关闭 socket。
****************/
M2M_Return_T m2m_net_destory(size_t net){
    if(net)
        net_destory((Net_T*)net);
    return M2M_ERR_NOERR;
}

M2M_Return_T m2m_net_secretkey_set(size_t net,M2M_id_T *p_id,u8 *p_host,int port, int key_len,u8 *p_key,
										int newkey_len, u8 *p_newkey,m2m_func func, void *p_args){
	int ret = 0;
	Net_T *p_net ;
	u8 tmp_key[20], tmp_newkey[20];
    u8 *p = mmalloc( sizeof(Enc_T) + 17 );
	Enc_T *p_new_enc = NULL;

	if( !net || !p_host || !p_id || !p_newkey )
    	return M2M_ERR_INVALID;
    
    Net_Args_T arg;
	// get net
	arg.p_net = (Net_T*) net;
	// get remote id.
	mcpy( (u8*)&arg.remote_id, (u8*)p_id, sizeof(M2M_id_T));
	// get remote address.
	arg.remote.p_host = p_host;
	arg.remote.dst_address.port = (u16)port;
	
	// get remote key.
	arg.enc.type = m2m_conf.def_enc_type;
	if(key_len < 16){
		mmemset( tmp_key, 0, 20);
		mcpy(tmp_key, p_key, key_len);
		arg.enc.p_enckey = tmp_key;
		arg.enc.keylen = 16;
	}else{
		arg.enc.p_enckey = p_key;
		arg.enc.keylen = key_len;
	}

	p_new_enc = (Enc_T*)p;
	p_new_enc->type = m2m_conf.def_enc_type;
	p_new_enc->keylen = M_MIN(16, newkey_len);
	mcpy((u8*)p_new_enc->key, p_newkey, p_new_enc->keylen);
	
	arg.p_data = p;
	arg.len = sizeof(Enc_T) + 17;
	arg.callback.func = func;
	arg.callback.p_user_arg = p_args;

	p_net = (Net_T*)net;
	
	if( p_net->ioctl_session )
       p_net->ioctl_session( M2M_NET_CMD_NET_SECRETKEY_SET, &arg,0);
	
	mfree(p);
	return M2M_ERR_NOERR;
}
// 在 net 里创建一个会话
// 返回一个 session。
/**
** description : 创建 session.
**          1. 获取远端    ip 和 port.
**          2. 创建 session.
** args:
**      net - 当下使用的 net. p_id -  远端的 id.
**      p_host - 远端 host. port - 远端的port. p_enc - 远端 net 的加密.
**      p_user_func - creat 创建成功触发的回调。
** return :
**         创建的 session。注意该调用会立即返回，但是此刻仅仅是在本地建立了 session，需要远端回应触发回调才能确定 session 建立成功。
*************************/
size_t m2m_session_creat(size_t net,M2M_id_T *p_id,u8 *p_host,int port, int key_len,u8 *p_key, m2m_func func, void *p_args){
    //int ret = 0;
    Net_T *p_n = (Net_T*)net;
    Net_Args_T arg;
    arg.p_net = NULL;
    Session_T *p_s = NULL;

    mmemset( (u8*)&arg, 0, sizeof(Net_Args_T));
    mcpy( (u8*) &arg.remote_id, (u8*)p_id,sizeof(M2M_id_T));
    
    m2m_log_debug("net <%p> creating session...", (void*)net);

    // get ip or port.
    if( !p_host || !p_key){
        m2m_debug_level( M2M_LOG_WARN,"host or  secret key not find \n");
        return 0;
    }

    arg.p_net = p_n;
    // get host
    arg.remote.p_host = p_host;
    // get secret key
    arg.enc.type = m2m_conf.def_enc_type;
    arg.enc.keylen = key_len;
    arg.callback.func = func;
    arg.callback.p_user_arg = p_args;
    arg.enc.p_enckey = p_key;
    arg.remote.dst_address.port = (u16) port;
    
    arg.len =0;
    arg.p_data = NULL;

    if( p_n->ioctl_session )
        p_s = (Session_T*) p_n->ioctl_session( M2M_NET_CMD_SESSION_CREAT, &arg,0);
    
    m2m_log_debug(" net <%p> creat session (%p).\n", (void*)net,p_s);
    return (size_t)p_s;
}
// 销毁 session
/***************************************************
** description: 销毁 session，并释放其占有的内存.
** args: 
**      p_m2m : 该 session 所在的 net，以及 要释放的 session.
****************************************************/
M2M_Return_T m2m_session_destory(M2M_T *p_m2m){

    Net_Args_T arg;
    
    mmemset( (u8*)&arg, 0, sizeof(Net_Args_T));

    _RETURN_EQUAL_0(p_m2m->session, M2M_ERR_INVALID);
    arg.p_net = (Net_T*) p_m2m->net;
    arg.p_s = (Session_T*) p_m2m->session;
    
    m2m_log_debug(" net <%p> session (%p) have been destory.\n", (void*)p_m2m->net, arg.p_s);
    if( arg.p_net->ioctl_session )
        return ( arg.p_net->ioctl_session(M2M_NET_CMD_SESSION_DESTORY,&arg,0) );
    else 
        return 0;
}
BOOL m2m_session_connted(M2M_T *p_m2m){

    Net_Args_T arg;
    if(!p_m2m)
    	return M2M_ERR_INVALID;
    
    mmemset((u8*)&arg,0,sizeof(Net_Args_T));
    
    arg.p_net = (Net_T*) p_m2m->net;
	arg.p_s = (Session_T*) p_m2m->session;
    
    if( arg.p_net->ioctl_session)
        return ( arg.p_net->ioctl_session( M2M_NET_CMD_SESSION_CONNT_CHECK,&arg,0) );
    else 
        return 0;

}

// 申请刷新 session token
/*****************************************************
** description: 向远端申请新的 token.用于更新本会话 token.
** args:
**      1. p_m2m - 发送该请求的 net/session。
**      2. p_user_func - 接收到对端 token 时触发的回调函数.
** return: 本地发送是否成功.
*****************************************************/
M2M_Return_T m2m_session_token_update(M2M_T *p_m2m,m2m_func func, void *p_args){
    Net_Args_T arg;
    
    mmemset( (u8*)&arg, 0, sizeof(Net_Args_T));
    _NET_ARG_CPY(arg,p_m2m,func,p_args);
    
    m2m_log_debug("session (%p) updateing remote token ...", (void*)p_m2m->session );
    if(arg.p_net->ioctl_session)
        return ( arg.p_net->ioctl_session(M2M_NET_CMD_SESSION_TOKEN_UPDATE,&arg,0) );
    else 
        return 0;
}
// 更新会话秘钥
/*****************************************************
** description: 设置对端 net 的秘钥.
** args:
**      1. p_m2m - 发送该请求的 net/session。
**      2. p_len - 秘钥的长度.  p_data - 秘钥.
**      2. p_user_func - 接收到对端响应时触发的回调函数.
** return: 本地发送是否成功.
*****************************************************/
M2M_Return_T m2m_session_secret_set(M2M_T *p_m2m,int len,u8 *p_data,m2m_func func, void *p_args){

    int ret=0;
    u8 *p = mmalloc(sizeof(Enc_T) + 17 );
    Enc_T *p_enc = NULL;
    Net_Args_T arg;

    mmemset( (u8*)&arg, 0, sizeof(Net_Args_T));
    _NET_ARG_CPY(arg,p_m2m,func,p_args);
    if( p == NULL){
        return M2M_ERR_NULL;
    }
    p_enc = (Enc_T*) p;
    p_enc->type = m2m_conf.def_enc_type;
    p_enc->keylen = M_MIN(len,16);
    mcpy((u8*)p_enc->key, (u8*)p_data,p_enc->keylen);

    
    m2m_log_debug("session (%p)updateing session secret key...", (void*)p_m2m->session);
    arg.len = (u16)(sizeof(Enc_T) + 17);
    arg.p_data = p;
    if(arg.p_net->ioctl_session)
        ret = ( arg.p_net->ioctl_session(M2M_NET_CMD_SESSION_SECRETKEY_SET,&arg,0) );
    mfree(p);
    
    return ret;
}

// 开启不断发送广播包.
#ifdef CONF_BROADCAST_ENABLE

/*****************************************************
** description: 向本地局域网发送广播包.
** args:
**      1. p_n: 指定发送广播包的 netm,其只需要使用到该 net 的 socket.
**      2. p_user_func - 接收到响应时触发的回调函数.
** return: 本地发送是否成功.
*****************************************************/
M2M_Return_T m2m_broadcast_data_start(size_t        p,int port,int len,u8 *p_data,m2m_func func, void *p_args){
    int ret = 0;
    if( !p || len ==0 || !p_data )
        return M2M_ERR_INVALID;
    
    Net_Args_T arg;
    Net_T *p_n = (Net_T*) p;
    m2m_log_debug("start broadcast...");
    mmemset( (u8*)&arg,0,sizeof(Net_Args_T));
    arg.p_net = p_n;
    arg.len = len;
    arg.p_data = p_data;
    arg.remote.dst_address.port = port;
    arg.callback.func = func;
    arg.callback.p_user_arg = p_args;
    arg.enc.type = M2M_ENC_TYPE_BROADCAST;
    if( p_n->ioctl_session )
        ret = p_n->ioctl_session( M2M_NET_CMD_BROADCAST_START, &arg,0);
    
    m2m_log_debug("net <%p> start to broadcast ...",p_n);
    return ret;
}

// 停止广播包的发送
/*****************************************************
** description: 停止广播包的发送.
** args:
**      1. p_n: 停止本地 net 的广播包发送.
** return: 停止是否出错.
*****************************************************/
M2M_Return_T m2m_broadcast_data_stop(size_t p){
    int ret = 0;
    if( !p)
        return M2M_ERR_INVALID;
    
    Net_T *p_n = (Net_T*)p;
    if( p_n->ioctl_session )
        ret = p_n->ioctl_session( M2M_NET_CMD_BROADCAST_STOP, p_n,0);
    
    m2m_log_debug("net <%p> broadcast stop.",p_n);
    return ret;
}

void m2m_broadcast_enable(size_t p){
    if(p){
        Net_T *p_n = (Net_T*) p;
        p_n->broadcast_en = 1;
    }
}
void m2m_broadcast_disable(size_t p){
    if(p){
        Net_T *p_n = (Net_T*) p;
        p_n->broadcast_en = 0;
    }
}

#endif // CONF_BROADCAST_ENABLE
// 发送数据 
/*****************************************************
** description: 发送数据.
** args:
**      1. p_m2m - 发送该请求的 net/session。
**      2. p_len - 数据的长度.  p_data - 数据.
**      2. p_user_func - 接收到对端响应时触发的回调函数.
** return: 本地发送是否成功.
*****************************************************/
M2M_Return_T m2m_session_data_send(M2M_T *p_m2m,int len,u8 *p_data,m2m_func func, void *p_args){
    Net_Args_T arg;

    
    mmemset((u8*)&arg,0,sizeof(Net_Args_T));
    _NET_ARG_CPY(arg,p_m2m,func,p_args);
    
    m2m_log_debug("session (%p) sending data to remote.", (void*)p_m2m->session);

    arg.len = len;
    arg.p_data = p_data;
    if(arg.p_net->ioctl_session)
        return ( arg.p_net->ioctl_session( M2M_NET_CMD_SESSION_DATA_SEND, &arg,0) );
    else 
        return 0;

}
// observer 数据发送 
/*****************************************************
** description: start observer
** args:
**      1. p_m2m - 发送 observer 请求的 net/session。
**      2. p_len - 数据的长度.  p_data - 数据.
**      2. p_user_func - 接收到对端响应时触发的回调函数.
** return: 本地发送是否成功.
*****************************************************/
size_t  m2m_session_observer_start(M2M_T *p_m2m,Pkt_ack_type_T ack_type,int len,u8 *p_data,m2m_func func, void *p_args){
    Net_Args_T arg;

    mmemset((u8*)&arg,0,sizeof(Net_Args_T));
    _NET_ARG_CPY(arg,p_m2m,func,p_args);
    
    m2m_log_debug("session (%p) start to observer.", (void*)p_m2m->session);

    arg.len = len;
    arg.p_data = p_data;
	arg.p_extra = (void*)&ack_type;
    if( arg.p_net->ioctl_session )
        return (size_t)( arg.p_net->ioctl_session( M2M_NET_CMD_SESSION_OBSERVER_START, &arg,0) );
    else 
        return 0;
}
/*****************************************************
** description: stop observer
** args:
**      1. p_m2m - 发送 observer 请求的 net/session。
**      2. p_obserindex: observer 节点的指针
**      2. p_user_func - 接收到对端响应时触发的回调函数.
** return: 本地发送是否成功.
*****************************************************/
M2M_Return_T m2m_session_observer_stop(M2M_T *p_m2m, void *p_obserindex){
    Net_Args_T arg;
	
	mmemset((u8*)&arg,0,sizeof(Net_Args_T));
	arg.p_net = (Net_T*)p_m2m->net;
	arg.p_s = (Session_T*)p_m2m->session;
	arg.p_extra = (void*)p_obserindex;

    m2m_log_debug("session (%p) stoping observer [%p].", (void*)p_m2m->session, p_obserindex);

	if(!p_obserindex){
		m2m_log_warn("Can't find observer index %p to stop !!",p_obserindex);
		return M2M_ERR_INVALID;
	}
	if(arg.p_net->ioctl_session)
        return ( arg.p_net->ioctl_session( M2M_NET_CMD_SESSION_OBSERVER_STOP, &arg,0) );
    else 
        return 0;
}
/*****************************************************
** description: push an notify to observer
** args:
**      1. p_m2m - 发送 observer 请求的 net/session。
**		2. len: 推送数据的长度； p_data: 推送的数据;
**      2. p_obserindex: observer 节点的指针
**      2. p_user_func - 接收到对端响应时触发的回调函数.
** return: 本地发送是否成功.
*****************************************************/
M2M_Return_T m2m_session_notify_push(M2M_T *p_m2m, void *p_obserindex,int len,u8 *p_data,m2m_func func, void *p_args){
    Net_Args_T arg;

	if(!p_obserindex){
		m2m_log_warn("Can't find observer index %p to stop !!",p_obserindex);
		return M2M_ERR_INVALID;
	}
	
	mmemset((u8*)&arg,0,sizeof(Net_Args_T));
	
	arg.len = len;
    arg.p_data = p_data;
	arg.p_extra = (void*)p_obserindex;
    _NET_ARG_CPY(arg,p_m2m,func,p_args);

	m2m_log_debug("node [%p] pushing notify", p_obserindex);
	if(arg.p_net->ioctl_session)
        return ( arg.p_net->ioctl_session( M2M_NET_CMD_SESSION_NOTIFY_PUSH, &arg,0) );
    else 
        return 0;
}
//  查询对应的设备是否在线
/*****************************************************
** description: 设备在线查询
** args:
**      1. p_m2m - 发送该请求的 net/session。
**      2. p_id -  要查询的设备 id.
**      2. p_user_func - 接收到对端响应时触发的回调函数.
** return: 本地发送是否成功.
*****************************************************/
M2M_Return_T m2m_dev_online_check(size_t p, u8 *p_remoteHost, int remote_port, M2M_id_T *p_id, m2m_func func, void *p_args){
    Net_Args_T arg;
    if(!p)
        return M2M_ERR_INVALID;
    
    Net_T *p_net = (Net_T*)p;
    mmemset((u8*)&arg,0,sizeof(Net_Args_T));
    
    arg.p_net = (Net_T*) p_net;        
    arg.callback.func = func;   
    arg.callback.p_user_arg = p_args; 
    arg.remote.p_host = p_remoteHost;
    arg.remote.dst_address.port = remote_port;
    arg.len = sizeof( M2M_id_T);
    arg.p_data = p_id;
    arg.enc.type = M2M_ENC_TYPE_NOENC;
    
    m2m_log_debug("net <%p> start to send device online check request.",p_net);


    if(arg.p_net->ioctl_session)
        return ( arg.p_net->ioctl_session( M2M_NET_CMD_ONLINE_CHECK,&arg,0) );
    else 
        return 0;

}
//  本地 net 是否有链接到 server host.
/*****************************************************
** description: 设备在线查询
** args:
**      1. p - 查询状态的 net。
** return: 1 net 链接 server host. 否则没有链接。
*****************************************************/
BOOL m2m_net_connted(size_t p){

    Net_Args_T arg;
    if(!p)
    	return M2M_ERR_INVALID;
    
    Net_T *p_net = (Net_T*)p;
    mmemset((u8*)&arg,0,sizeof(Net_Args_T));
    
    arg.p_net = (Net_T*) p_net;        
    
    if(arg.p_net->ioctl_session)
        return ( arg.p_net->ioctl_session( M2M_NET_CMD_CONNT_CHECK,&arg,0) );
    else 
        return 0;

}


// 重发，接收处理，连接维持
/*****************************************************
** description: 循环调用
**          1. 对每个 session 内部的 node 进行检查，并重发，超时则丢弃.
**          2. socket 接收处理，触发用户回调.
**          3. 维持与 host 以及每个 session 的连接。
**          4. 中转路由表的刷新。
** args:
**      1. net  - 本地net.
** return: NULL.
*****************************************************/
M2M_Return_T m2m_trysync(size_t net){
    Net_Args_T arg;
    Net_T *p_n = (Net_T*)net;
    arg.p_net = p_n;
    if(p_n->ioctl_session)
            return p_n->ioctl_session( M2M_NET_CMD_TRYSYNC, &arg,0);
    else 
        return 0;
}
/*****************************************************
** description: 系统配置。
** todo:  
**         1. 读取配置文件进行配置。
**         2. 创建多个 net 如何销毁
*****************************************************/
M2M_Return_T m2m_int(M2M_conf_T *p_conf){
/** todo you have to *************************/
/** read config file ***********/
    if( p_conf){
        mcpy( (u8*)&m2m_conf, (u8*)p_conf, sizeof(M2M_conf_T));
    }else{
        m2m_conf.def_enc_type = M2M_ENC_TYPE_AES128;
        m2m_conf.max_router_tm = 10*60*1000;
        m2m_conf.do_relay = 1;
    }
    return M2M_ERR_NOERR;
/** *************************/
}
/*****************************************************
** description: 注销整个 m2m，并退出
*****************************************************/
M2M_Return_T m2m_deint(void){
    return 0;
}

#ifdef __cplusplus
}
#endif



