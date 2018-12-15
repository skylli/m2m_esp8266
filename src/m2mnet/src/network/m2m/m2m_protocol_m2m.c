/*
 * Copyright (C) 2014-2016 m2m Technologies. All Rights Reserved. 
 */
#include "../../../include/m2m.h"
#include "../../../include/util.h"
#include "../../../config/config.h"
#include "../../../include/m2m_port.h"
#include "../../../include/m2m_log.h"
#include "../../crypt/m2m_crypt.h"

#include "pdu.h"
#include "option.h"
#include "m2m_router.h"
#include "m2m_protocol.h"

/*** define *************************/
#define _PDU_PKT_CREAT(p_pdu,cmd,code,msgid,token,pdu_size,ret) do{         \
            p_pdu = coap_pdu_init( cmd,code,msgid,pdu_size);                 \
            _RETURN_EQUAL_0(p_pdu, M2M_ERR_NULL);                       \
            ret = coap_add_token(p_pdu,sizeof(u32),(const u8*)&token);             \
            _RETURN_EQUAL_FREE(ret, 0, p_pdu, M2M_ERR_PROTO_PKT_BUILD); \
        }while(0)

#define _PDU_ACK_CREAT( p_pdu,p_ack,pdu_size,ret) \
            _PDU_PKT_CREAT(p_pdu,COAP_MESSAGE_ACK,(u8)p_ack->code,p_ack->msgid, p_ack->token,pdu_size,ret)

#define _PDU_GET_RQ_CREAT(p_pdu,p_args,ret,pdu_size) \
            _PDU_PKT_CREAT(p_pdu,COAP_MESSAGE_CON,COAP_REQUEST_GET,p_args->messageid, p_args->token,pdu_size,ret)

#define _PROTO_COAP_SIZE(oplen,pylen)    ( 4 + 4+ oplen + 4 + pylen)
#define _PROTO_ROUTER_HDR_LEN           ( sizeof(Router_hdr_T) ) 
#define _PROTO_SECRET_APPENDLEN   ( 16 )    // 加密部分最大的填充.
#define _PROTO_LEN(oplen,pylen)  (  _PROTO_ROUTER_HDR_LEN + _PROTO_SECRET_APPENDLEN + _PROTO_COAP_SIZE(oplen,pylen) + pylen )

#define _PROTO_ROUTER_SECRET_AES128(p_dst,p_src,src_len,p_enc,encdata_len,crc) do{                      \
            encdata_len = _proto_m2m_enc( (u8*)p_dst, (u8*)p_src,(int)src_len,p_enc); \
            crc = crc8_count( p_dst,encdata_len); \
        }while(0)

#define _COAP_SECRET_BUILD( p_router,p_enc, enc_len, p_src, src_len) do{      \
                    p_router->secret_type = p_enc->type;                                  \
                    p_router->payloadlen = src_len;                                       \
                        _PROTO_ROUTER_SECRET_AES128( p_router->p_payload,p_src, src_len,  \
                                                     p_enc, enc_len,p_router->crc8);      \
                    }while(0)


#define _PROTO_RQ_ROUTER_HDR( p_router,p_args ) do{ mcpy(  (u8*)&p_router->dst_id, (u8*)&p_args->dst_id,ID_LEN );\
                                                    mcpy( (u8*)&p_router->src_id, (u8*)&p_args->src_id,ID_LEN );\
                                                    p_router->version = PROTO_VERSION_HDR;      \
                                                    p_router->hops = M2M_MAX_HOPS;              \
                                                    p_router->stoken = p_args->stoken;          \
                                                    p_router->ctoken = p_args->ctoken;          \
                                                    p_router->msgid = p_args->messageid;        \
                                                }while(0)
                                                
#define _PROTO_ACK_ROUTER_HDR( p_router,p_ack ) do{    mcpy( (u8*)&p_router->dst_id, (u8*)&p_ack->dst_id,ID_LEN );  \
                                                       mcpy( (u8*)&p_router->src_id, (u8*)&p_ack->src_id,ID_LEN );  \
                                                       p_router->version = PROTO_VERSION_HDR;                       \
                                                       p_router->hops = M2M_MAX_HOPS;               \
                                                       p_router->stoken = p_ack->stoken;            \
													   p_router->ctoken = p_ack->ctoken;			 \
                                                       p_router->msgid = p_ack->msgid;              \
                                                    }while(0)
#define  COAP_CODE_GET(code)   ((code >> 5) * 100 + (code & 0x1F))


typedef enum{

    COAP_OPT_DATA_RQ = 0X01,
    COAP_OPT_DATA_ACK   = 0X02,
    COAP_OPT_TKT_RQ     = 0X03,
    COAP_OPT_TKT_ACK    = 0X04,
    COAP_OPT_PING_RQ    = 0X05,
    COAP_OPT_PING_ACK   = 0X06,
    COAP_OPT_SESSION_KEYSET_RQ  = 0X07,
    COAP_OPT_SESSION_KEYSET_ACK = 0X08,
    COAP_OPT_ERROR_ACK = 0X09,
    COAP_OPT_ONLINKCHECK_RQ  = 0X0A,
    COAP_OPT_ONLINKCHECK_ACK = 0X0B,
	COAP_OPT_NET_KETSET_RQ  = 0X0C,
    COAP_OPT_NET_KETSET_ACK = 0X0D,
    
    COAP_OPT_OBSERVER_RQ  = 0X0E,
    COAP_OPT_OBSERVER_ACK = 0X0F,
    
    COAP_OPT_BROADCAST_RQ  = 0X10,
    COAP_OPT_BROADCAST_ACK = 0X11,
    COAP_OPT_MAX

}COAP_OPTION_TYPE;

static M2M_Return_T _proto_m2m_opt_get(coap_pdu_t *p_pdu,u8 *opt_type,u8 **p_opt,u8 *opt_len);
static int _proto_m2m_ack_send( 
    M2M_proto_ack_T *p_ack,
    u8 opt_type, 
    u16 opt_len, 
    const u8 *p_opt_data,
    u16 payload_len,
    const u8 *p_payload );

int _proto_m2m_enc(u8 *p_dst, u8 *p_src, int src_len,Net_enc_T *p_enc){

    int ret = 0;
    
    //m2m_bytes_dump("befor encode data :", p_src,src_len);
    switch( p_enc->type){
        case M2M_ENC_TYPE_BROADCAST:
        case M2M_ENC_TYPE_NOENC:
            // 不加密
            mcpy( (u8*)p_dst, (u8*)p_src,src_len);
            ret = src_len;
            break;

        case M2M_ENC_TYPE_AES128:
            
            ret = data_enc( (const char*)p_src, (char*)p_dst,src_len,p_enc->keylen,p_enc->p_enckey);
            break;
        default:
            break;
    }
    //m2m_bytes_dump("after encode data :", p_dst, ret);
    return ret;
}
/*
* 建立 session.
* 1.p_args 提供 socket fd 和 远端地址 ip/port.
***
***/
int _proto_m2m_creat(M2M_Proto_Cmd_Arg_T *p_args,int flags){
    return 0;
}
int _proto_m2m_destory(M2M_Proto_Cmd_Arg_T *p_args,int flags){
    return 0;
}
/*********************************
** 1. 进行 coap 封包, coap header + option + payload.
** 2. 加密，计算 crc.
** 3. 释放 coap 包，并把整个的封包 发送出去.
** 4. 释放整个包.
*********************************/
static int router_package_creat(
        u8 **pp_out_pkt,
        int *output_len,
        M2M_Proto_Cmd_Arg_T *p_args,
        u8 type, 
        u16 opt_len, 
        const u8 *p_opt_data,
        u16 payload_len,
        const u8 *p_payload){

    int ret = 0,pdu_size = 0,pkt_len = 0,payload_dec_len = 0;
    coap_pdu_t *p_pdu = NULL;
    // 1. 组包.
    // 1.2 设置 stoken.
    pdu_size = _PROTO_COAP_SIZE(opt_len,payload_len);
    _PDU_GET_RQ_CREAT(p_pdu,p_args,ret,pdu_size);
     // 1.3 option 添加.
    coap_add_option(p_pdu,type, opt_len, p_opt_data);
    // 1.4 添加 payload.
    if( payload_len > 0 && p_payload ){
        ret = coap_add_data(p_pdu,payload_len,p_payload);
        _RETURN_EQUAL_FREE(ret , 0, p_pdu, M2M_ERR_NULL);
    }
    // 2 计算整包的大小.
    pkt_len = _PROTO_LEN( opt_len, payload_len);
    u8 *p_pkt = mmalloc( pkt_len + 1);
    _RETURN_EQUAL_FREE(p_pkt, 0, p_pdu, M2M_ERR_NULL);
    Router_hdr_T *p_router = (Router_hdr_T*)p_pkt;

    // 6. 填充路由头部.
    _PROTO_RQ_ROUTER_HDR( p_router,p_args );
    // 3. 加密.
    _COAP_SECRET_BUILD(p_router,p_args->p_enc,payload_dec_len,p_pdu->hdr, p_pdu->length);

    //m2m_bytes_dump("proto data pdu dump: ", p_pdu->hdr,p_pdu->length);
#if 0
   {
        u8 opt_type ,opt_len, *p_opt;
        _proto_m2m_opt_get(p_pdu,&opt_type,&p_opt,&opt_len);
         m2m_bytes_dump("opt  :", p_opt,opt_len);
    }
    coap_show_pdu(p_pdu);
#endif
    // 7. 释放 coap 
    coap_delete_pdu( p_pdu );

    *output_len = (sizeof(Router_hdr_T) + payload_dec_len);
    *pp_out_pkt = p_pkt;
    return M2M_ERR_NOERR;
}

/*********************************
** 1. 进行 coap 封包, coap header + option + payload.
** 2. 加密，计算 crc.
** 3. 释放 coap 包，并把整个的封包 发送出去.
** 4. 释放整个包.
*********************************/
static int _proto_m2m_request_send(
        M2M_Proto_Cmd_Arg_T *p_args,
        u8 type, 
        u16 opt_len, 
        const u8 *p_opt_data,
        u16 payload_len,
        const u8 *p_payload){

    int ret = 0,pdu_size = 0,pkt_len = 0,payload_dec_len = 0;
    coap_pdu_t *p_pdu = NULL;
    // 1. 组包.
    // 1.2 设置 stoken.
    pdu_size = _PROTO_COAP_SIZE(opt_len,payload_len);
    _PDU_GET_RQ_CREAT(p_pdu,p_args,ret,pdu_size);
     // 1.3 option 添加.
    coap_add_option(p_pdu,type, opt_len, p_opt_data);
    // 1.4 添加 payload.
    if( payload_len > 0 && p_payload ){
        ret = coap_add_data(p_pdu,payload_len,p_payload);
        _RETURN_EQUAL_FREE(ret , 0, p_pdu, M2M_ERR_PROTO_PKT_BUILD);
    }
    // 2 计算整包的大小.
    pkt_len = _PROTO_LEN( opt_len, payload_len);
    u8 *p_pkt = mmalloc( pkt_len + 1);
    _RETURN_EQUAL_FREE(p_pkt, 0, p_pdu, M2M_ERR_NULL);
    Router_hdr_T *p_router = (Router_hdr_T*)p_pkt;

    // 6. 填充路由头部.
    _PROTO_RQ_ROUTER_HDR( p_router,p_args );
    // 3. 加密.
    _COAP_SECRET_BUILD(p_router,p_args->p_enc,payload_dec_len,p_pdu->hdr, p_pdu->length);

    //m2m_bytes_dump("proto data pdu dump: ", p_pdu->hdr,p_pdu->length);
#if 0
   {
        u8 opt_type ,opt_len, *p_opt;
        _proto_m2m_opt_get(p_pdu,&opt_type,&p_opt,&opt_len);
         m2m_bytes_dump("opt  :", p_opt,opt_len);
    }
    coap_show_pdu(p_pdu);
#endif
    // 7. 释放 coap 
    coap_delete_pdu( p_pdu );
    
    //m2m_bytes_dump("encode proto data dump: ", p_router->p_payload,p_router->payloadlen);
    PKT_INFO_PRINT( M2M_LOG_DEBUG, p_args->messageid,0, p_args->ctoken,p_args->stoken,p_args->address,"sending package info:: ");
    DEV_ID_LOG_PRINT( M2M_LOG_DEBUG, p_router->src_id,"source id "," ---------->\n");
    DEV_ID_LOG_PRINT( M2M_LOG_DEBUG, p_router->dst_id,"--------->"," destion id\n");
    // 7.发送

    ret = m2m_send(p_args->socket_fd, &p_args->address, p_pkt, (sizeof(Router_hdr_T) + payload_dec_len) );
    
    mfree(p_pkt);
    return ret;
}

/*
* 刷新 会话 ctoken.同时清零 message id
*/
int token_rq(M2M_Proto_Cmd_Arg_T *p_args,int flags){

    return _proto_m2m_request_send(p_args, COAP_OPT_TKT_RQ, 0, NULL,0, NULL);
}
static int token_ack(M2M_proto_ack_T *p_ack,int flags){

    return _proto_m2m_ack_send(p_ack,COAP_OPT_TKT_ACK,p_ack->payload.len,p_ack->payload.p_data,0,NULL);
}

int session_keyset_rq(M2M_Proto_Cmd_Arg_T *p_args,int flags){

    if( p_args->p_payload == 0 || p_args->payloadlen <= 0)
        return M2M_ERR_PROTO_PKT_BUILD;

    return _proto_m2m_request_send(p_args, COAP_OPT_SESSION_KEYSET_RQ, p_args->payloadlen, p_args->p_payload,0, NULL);
}
static int session_keyset_ack(M2M_proto_ack_T *p_ack,int flags){

    return _proto_m2m_ack_send(p_ack,COAP_OPT_SESSION_KEYSET_ACK,p_ack->payload.len,p_ack->payload.p_data,0,NULL);
}

/*
* 刷新 会话 ctoken.同时清零 message id
*/
int data_rq(M2M_Proto_Cmd_Arg_T *p_args,int flags){

    return _proto_m2m_request_send(p_args, COAP_OPT_DATA_RQ,0, NULL,p_args->payloadlen, p_args->p_payload);
}
static int data_ack(M2M_proto_ack_T *p_ack,int flags){
    //u8 opt = 0;
    return _proto_m2m_ack_send(p_ack,COAP_OPT_DATA_ACK,0,NULL,p_ack->payload.len,p_ack->payload.p_data);
}

/*
** observer 
**/
int observer_rq(M2M_Proto_Cmd_Arg_T *p_args,int flags){

	M2M_observer_T *p_obs = (M2M_observer_T*)p_args->p_extra;
	u8 ack_index[3];
	
	_RETURN_EQUAL_0(p_obs, M2M_ERR_INVALID);

	ack_index[0] = p_obs->ack_type;
	mcpy( (u8*)&ack_index[1], (u8*)&p_obs->index, 2);
	
	
	return _proto_m2m_request_send(p_args, COAP_OPT_OBSERVER_RQ, 3, ack_index, p_args->payloadlen, p_args->p_payload);
}
static int observer_ack(M2M_proto_ack_T *p_ack,int flags){

	M2M_observer_T *p_obs = (M2M_observer_T*)p_ack->p_extra;
	u8 ack_index[3];

	_RETURN_EQUAL_0(p_obs, M2M_ERR_INVALID);
	ack_index[0] = p_obs->ack_type;
	mcpy(&ack_index[1], (u8*)&p_obs->index, 2);

    return _proto_m2m_ack_send(p_ack,COAP_OPT_OBSERVER_ACK, 3, ack_index,p_ack->payload.len,p_ack->payload.p_data);
}

/**
** ping 包
**/
static int ping_rq(M2M_Proto_Cmd_Arg_T *p_args,int flags){

    return _proto_m2m_request_send(p_args, COAP_OPT_PING_RQ, p_args->payloadlen, p_args->p_payload,0, NULL);
}
static int ping_ack(M2M_proto_ack_T *p_ack,int flags){

    return _proto_m2m_ack_send(p_ack,COAP_OPT_PING_ACK,p_ack->payload.len,p_ack->payload.p_data,0,NULL);
}

/**
** 应答， 不同类型的应答应该存放在 option 里。
** opt_type optiong type ; opt_len -- option's value len
****/
static int _proto_m2m_ack_send( 
    M2M_proto_ack_T *p_ack,
    u8 opt_type, 
    u16 opt_len, 
    const u8 *p_opt_data,
    u16 payload_len,
    const u8 *p_payload ){

   int ret = 0,pdu_size = 0,pkt_len = 0,payload_dec_len = 0;
   coap_pdu_t *p_pdu = NULL;
   // 1. 组包.
   // 1.2 设置 stoken.
   pdu_size = _PROTO_COAP_SIZE( opt_len, payload_len);
   
   _PDU_ACK_CREAT(p_pdu,p_ack,pdu_size,ret);
   // 1.3 option 添加.
   coap_add_option(p_pdu,opt_type, opt_len, p_opt_data);
   // 1.4 添加 payload.
   if( payload_len > 0 && p_payload ){
       ret = coap_add_data(p_pdu,payload_len, p_payload);
       _RETURN_EQUAL_FREE(ret , 0, p_pdu, M2M_ERR_PROTO_PKT_BUILD);
   }
   // 2 计算整包的大小.
   pkt_len = _PROTO_LEN( opt_len, payload_len);
   u8 *p_pkt = mmalloc( pkt_len + 1);
   _RETURN_EQUAL_FREE(p_pkt, 0, p_pdu, M2M_ERR_NULL);
   Router_hdr_T *p_router = (Router_hdr_T*)p_pkt;

   // 3. 填充路由头部.
   _PROTO_ACK_ROUTER_HDR( p_router, p_ack);
   // 4. 加密.
   _COAP_SECRET_BUILD(p_router,p_ack->p_enc, payload_dec_len, p_pdu->hdr, p_pdu->length);

   // 5. 释放 coap  
   coap_delete_pdu( p_pdu );
   // 6.发送
   ret =  m2m_send(p_ack->socket_fd, &p_ack->remote_addr,p_pkt,sizeof( Router_hdr_T ) + payload_dec_len);
   mfree(p_pkt);
   return ret;
}
#if 0
// 对 coap 包进行加密.
static int coap_pkt_enc( Router_hdr_T **pp_r,
                            coap_pdu_t **pp_pdu,
                            M2M_proto_ack_T *p_ack){
    
    int pkt_len = _PROTO_LEN( opt_len, payload_len);
  // 3. 填充路由头部.
  _PROTO_ACK_ROUTER_HDR( p_r, p_ack);
  // 4. 加密.
  _COAP_SECRET_BUILD(p_r,p_ack->p_enc, payload_dec_len, p_pdu->hdr, p_pdu->length);
}
#endif




static int error_ack(M2M_proto_ack_T *p_ack,int flags){
    return _proto_m2m_ack_send(p_ack,COAP_OPT_ERROR_ACK,0,NULL,p_ack->payload.len,p_ack->payload.p_data);
}
static int _recv_packet_illegal(Router_hdr_T *p_r){

    if( p_r->version != PROTO_VERSION_HDR  \
        || p_r->secret_type > M2M_ENC_TYPE_MAX \
        || p_r->payloadlen > M2M_PROTO_PKT_MAXSIZE ){
            return 1;
            }
    else return 0;
}
/**********  接收处理 ************************************************************************/
// socket 接收 目前只支持阻塞接收
// 解码 路由层
static int pkt_receive(M2M_proto_recv_rawpkt_T *p_rawpkt,int flags){

    int ret = 0;
    int tmp = _PROTO_LEN(0,0);
    ret = m2m_receive( p_rawpkt->socket_fd,&p_rawpkt->remote,p_rawpkt->payload.p_data,p_rawpkt->payload.len,M2M_SOCKET_RECV_TIMEOUT_MS);
    if(ret < 20 ){
        // haven't receive anything, or there is no data.
        return 0;
    }
    // version 
    p_rawpkt->payload.len = ret;
    Router_hdr_T *p_r = (Router_hdr_T*)p_rawpkt->payload.p_data;
    // id filter
    if(_recv_packet_illegal(p_r))
        return 0;
    mcpy( (u8*)&p_rawpkt->dst_id, (u8*)&p_r->dst_id, ID_LEN );
    mcpy( (u8*)&p_rawpkt->src_id, (u8*)&p_r->src_id, ID_LEN);

    p_rawpkt->enc_type = p_r->secret_type;
    p_rawpkt->msgid = p_r->msgid;
    p_rawpkt->stoken = p_r->stoken;
	p_rawpkt->ctoken = p_r->ctoken;
    if( p_r->stoken == 0 && p_rawpkt->ctoken == 0 && p_rawpkt->enc_type != M2M_ENC_TYPE_BROADCAST )
        m2m_log_warn("NO token stoken = %u !!", p_r->stoken);
    //m2m_bytes_dump("encoder pdu :", p_r->p_payload,p_r->payloadlen);

    DEV_ID_LOG_PRINT( M2M_LOG_DEBUG, p_rawpkt->src_id,"source id "," ---------->\n");
    DEV_ID_LOG_PRINT( M2M_LOG_DEBUG, p_rawpkt->dst_id,"--------->"," destion id\n");
    return ret;
}
static M2M_Return_T _proto_m2m_opt_get(coap_pdu_t *p_pdu,u8 *opt_type,u8 **p_opt,u8 *opt_len){
    
    coap_opt_t *option;
    coap_opt_iterator_t opt_iter;
    coap_option_iterator_init((coap_pdu_t *)p_pdu, &opt_iter, COAP_OPT_ALL);
    if((option = coap_option_next(&opt_iter))) 
     {
            *opt_type = opt_iter.type;
            *p_opt = COAP_OPT_VALUE(option);
            *opt_len = COAP_OPT_LENGTH(option);
     }
    return M2M_ERR_NOERR;
}
static M2M_Return_T _proto_m2m_cmd_parse(coap_pdu_t *p_pdu_recv,M2M_proto_dec_recv_pkt_T *p_dec){
    u8 opt_type,opt_len,opt_get = 0,payload_get = 0;
    size_t payload_len = 0;
    u8 *p_opt, *p_payload = NULL;
	u8 extra[3];
    _proto_m2m_opt_get(p_pdu_recv,&opt_type,&p_opt,&opt_len);
    switch( opt_type ){
		
		case COAP_OPT_DATA_RQ:
		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = data request");
		    p_dec->cmd = M2M_PROTO_CMD_DATA_RQ;
		    payload_get = 1;
		    break;
			
		case COAP_OPT_DATA_ACK:
		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = data ack");
		    p_dec->cmd = M2M_PROTO_CMD_DATA_ACK;
		    payload_get = 1;
		     break;
		case COAP_OPT_TKT_RQ:

		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = toke request");
		    p_dec->cmd = M2M_PROTO_CMD_TOKEN_RQ;
		    break;
		case COAP_OPT_TKT_ACK:
		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = token request");
		    p_dec->cmd = M2M_PROTO_CMD_TOKEN_ACK;
		    opt_get = 1;
		    // get ctoken to payload.
		    break; 
		case COAP_OPT_SESSION_KEYSET_RQ:
		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = session setkey request");
		    p_dec->cmd = M2M_PROTO_CMD_SESSION_SETKEY_SET_RQ;
		    opt_get = 1;
		    break;
		case COAP_OPT_SESSION_KEYSET_ACK:

		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = session setkey ack");
		    p_dec->cmd = M2M_PROTO_CMD_SESSION_SETKEY_SET_ACK;
		    break;
		case COAP_OPT_PING_RQ:

		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = ping request");
		    p_dec->cmd = M2M_PROTO_CMD_PING_RQ;
		    break;
		case COAP_OPT_PING_ACK:
		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = ping ack");
			opt_get = 1;
			p_dec->cmd = M2M_PROTO_CMD_PING_ACK;
		    break;
		case COAP_OPT_ERROR_ACK:
		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = error ack");
		    p_dec->cmd = M2M_PROTO_CMD_ERR_PKT_ACK;
		    break;
		case COAP_OPT_ONLINKCHECK_RQ:
		    opt_get = 1;
		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = Online check request");
		    p_dec->cmd = M2M_PROTO_CMD_ONLINK_CHECK_RQ;
		    break;
		case COAP_OPT_ONLINKCHECK_ACK:
		    opt_get = 1;
		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = Online check ack");
		    p_dec->cmd = M2M_PROTO_CMD_ONLINK_CHECK_ACK;
		    break;
			
		case COAP_OPT_NET_KETSET_RQ:
		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = net secretkey set request");
		    p_dec->cmd = M2M_PROTO_CMD_NET_SETKEY_RQ;
		    opt_get = 1;
		    // get ctoken to payload.
		    break; 
		case COAP_OPT_NET_KETSET_ACK:
		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = net secretkey set request");
		    p_dec->cmd = M2M_PROTO_CMD_NET_SETKEY_ACK;
		    opt_get = 1;
		    break;

#ifdef CONF_BROADCAST_ENABLE                
		case COAP_OPT_BROADCAST_RQ:
		    opt_get = 1;
		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = Broadcast request");
		    p_dec->cmd = M2M_PROTO_CMD_BROADCAST_RQ;
		    break;
		case COAP_OPT_BROADCAST_ACK:
		    opt_get = 1;
		    m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = broadcast request ack");
		    p_dec->cmd = M2M_PROTO_CMD_BROADCAST_ACK;
		    break;
#endif //CONF_BROADCAST_ENABLE

		case COAP_OPT_OBSERVER_RQ:
		  m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = observer request");
		  p_dec->cmd = M2M_PROTO_CMD_SESSION_OBSERVER_RQ;
		  payload_get = 1;
		  if( opt_len ==  3 && p_opt ){
			  M2M_observer_T *p_obs = (M2M_observer_T*)mmalloc(sizeof(M2M_observer_T));
			  _RETURN_EQUAL_0(p_obs, M2M_ERR_NULL);
		  	  mcpy(extra, p_opt, 3);
			  p_obs->ack_type = extra[0];
			  mcpy((u8*)&p_obs->index,  &extra[1], 2);
			  p_dec->p_extra = p_obs;

		  }
		  break;
		  
		case COAP_OPT_OBSERVER_ACK:
		  m2m_debug_level(M2M_LOG_DEBUG, "receive cmd = observer ack");
		  p_dec->cmd = M2M_PROTO_CMD_SESSION_OBSERVER_ACK;
		  payload_get = 1;
		  if( opt_len == 3 && p_opt ){
			  M2M_observer_T *p_obs = (M2M_observer_T*)mmalloc(sizeof(M2M_observer_T));
			  _RETURN_EQUAL_0(p_obs, M2M_ERR_NULL);
			  mcpy(extra, p_opt, 3);
			  p_obs->ack_type = extra[0];
			  mcpy((u8*)&p_obs->index,  (u8*)&extra[1], 2);
			  p_dec->p_extra = p_obs;

		  }
		  break;

    }
    // get payload.
    if( payload_get == 1){
        coap_get_data(p_pdu_recv,&payload_len, &p_payload);
        if( payload_len > 0 && p_payload ){
            p_dec->payload.p_data = (u8*)mmalloc(payload_len +1);
            _RETURN_EQUAL_0(p_dec->payload.p_data, M2M_ERR_NULL);
            mcpy( (u8*)p_dec->payload.p_data, (u8*)p_payload,payload_len);
            p_dec->payload.len = payload_len;
        }
    } else if( opt_get == 1 ){
        // get option data.
        if( opt_len > 0 && p_opt ){
              p_dec->payload.p_data = mmalloc(opt_len + 1);
              p_dec->payload.len = opt_len;
              _RETURN_EQUAL_0(p_dec->payload.p_data, M2M_ERR_NULL);
              mcpy( (u8*)p_dec->payload.p_data, (u8*)p_opt,opt_len);
          }
    }

    return M2M_ERR_NOERR;
}
// 对接收包进行解码
// 注意 该函数会 malloc p_dec->payload, 所以后面必须手动 free p_dec->payload.
// 返回长度
static int pkt_decode( M2M_dec_args_T *p_a,int flags){
    // crc 计算
    int ret_dec = 0,ret = 0;
    M2M_proto_dec_recv_pkt_T *p_dec = p_a->p_dec;
    M2M_proto_recv_rawpkt_T *p_rawpkt =p_a->p_rawpkt;
    Router_hdr_T *p_r = (Router_hdr_T*)p_rawpkt->payload.p_data;
    int payload_enc_len =  (p_rawpkt->payload.len - sizeof(Router_hdr_T));
    
    u8 crc8 = crc8_count(p_r->p_payload, payload_enc_len);
    if(p_r->crc8 != crc8 )
        return M2M_HTTP_SECRET_ERR;
    
    // 解码
    u8 *p_d = mmalloc( p_r->payloadlen +16 +1);
    _RETURN_EQUAL_0(p_d, M2M_ERR_NULL);
    // 不接码
    if( p_r->secret_type == M2M_ENC_TYPE_NOENC){
        mcpy((u8*)p_d, (u8*)p_r->p_payload,  p_r->payloadlen);
    }else if( p_r->secret_type == M2M_ENC_TYPE_BROADCAST ){
        m2m_debug_level(M2M_LOG_DEBUG,"receive package broad cast package");
        mcpy((u8*)p_d, (u8*)p_r->p_payload,  p_r->payloadlen);
        //p_dec->payload.p_data = p_d;
        // p_dec->payload.len = p_r->payloadlen;
		//return  M2M_ERR_NOERR;
    }else if( p_r->secret_type == p_dec->p_enc->type && payload_enc_len > 0 ){
        // 一致才解码
        m2m_debug_level(M2M_LOG_DEBUG,"receive encrypted package");
        ret_dec = data_dec( (const char*)p_r->p_payload,(char*)p_d, payload_enc_len, p_dec->p_enc->keylen,p_dec->p_enc->p_enckey);
        if( ret_dec <= 0 ){
            m2m_log_warn("Package decode failure !!");
			p_dec->payload.p_data = NULL;
            MFREE(p_d);
            return M2M_HTTP_SECRET_ERR;
            }  
    }
    
    coap_pdu_t *p_pdu = coap_new_pdu();
    _RETURN_EQUAL_FREE( p_pdu, NULL, p_d, M2M_ERR_NULL);
    if( 0 ==  coap_pdu_parse(p_d, p_r->payloadlen,p_pdu)){
        coap_delete_pdu(p_pdu);
		p_dec->payload.p_data = NULL;
        MFREE(p_d);
        return -1;
    }
    // free dec data 
    p_dec->payload.p_data = NULL;
    MFREE(p_d);
    // coap dispatch
    // get token
    if( p_pdu->hdr->token_length != sizeof(u32) ){
        return -1;
    }
    mcpy( (u8*)&p_dec->token,(u8*)p_pdu->hdr->token,p_pdu->hdr->token_length);

    // get  code.
    p_dec->code = p_pdu->hdr->code;// COAP_CODE_GET(p_pdu->hdr->code);
    // get message id.
    p_dec->msgid = p_pdu->hdr->id;
    // get cmd and payload.
    _proto_m2m_cmd_parse(p_pdu,p_dec);
    
    //m2m_bytes_dump("decode payload: ", p_dec->payload.p_data, p_dec->payload.len);
    // destory the pdu. 
    coap_delete_pdu(p_pdu);
    
    PKT_INFO_PRINT(M2M_LOG_DEBUG,p_dec->msgid,p_dec->cmd,p_rawpkt->ctoken, p_rawpkt->stoken, p_rawpkt->remote,"receive package info:: ");
    // return the length of decode data.
    return  M2M_ERR_NOERR;

}
#ifdef CONF_BROADCAST_ENABLE
static M2M_Return_T broadcast_rq(M2M_Proto_Cmd_Arg_T *p_args,int flags){
    int num,i,send_len = 0 ;
    u32 iplist[4];
    M2M_Address_T remote_addr;
    u8 *p_pkt = NULL;

    router_package_creat(&p_pkt,&send_len,p_args, COAP_OPT_BROADCAST_RQ, p_args->payloadlen, p_args->p_payload,0,NULL);

    // 使能 广播.
    broadcast_enable(p_args->socket_fd);
    // 获取子网掩码列表,每个子网发一次广播
    remote_addr.port = p_args->address.port;
    num = get_bcast_list(iplist, 4);
    for(i = 0; i < num; i++)
    {
        // 关于端口号: 此处的端口是客户端的端口
        mcpy( (u8*)remote_addr.ip, (u8*)&iplist[i], 4);
        remote_addr.len  = 4;
        m2m_send(p_args->socket_fd, &remote_addr, p_pkt,send_len);
    }

    MFREE(p_pkt);
    return M2M_ERR_NOERR;
}
// 广播包无需任何的 协议封装以及加密.
static M2M_Return_T broadcast_ack(M2M_proto_ack_T *p_ack, int flags){
    return _proto_m2m_ack_send(p_ack, COAP_OPT_BROADCAST_ACK, p_ack->payload.len,p_ack->payload.p_data,0, NULL);
}
#endif  //CONF_BROADCAST_ENABLE

int onlinkchek_rq(M2M_Proto_Cmd_Arg_T *p_args,int flags){

    return _proto_m2m_request_send(p_args, COAP_OPT_ONLINKCHECK_RQ,p_args->payloadlen, p_args->p_payload,0, NULL);
}
static M2M_Return_T onlinkchek_ack(M2M_proto_ack_T *p_ack, int flags){
    return _proto_m2m_ack_send(p_ack, COAP_OPT_ONLINKCHECK_ACK, p_ack->payload.len,p_ack->payload.p_data,0, NULL);
}

int net_secretsky_set_rq(M2M_Proto_Cmd_Arg_T *p_args,int flags){

    return _proto_m2m_request_send(p_args, COAP_OPT_NET_KETSET_RQ,p_args->payloadlen, p_args->p_payload,0, NULL);
}

static M2M_Return_T net_secretsky_set_ack(M2M_proto_ack_T *p_ack, int flags){
    return _proto_m2m_ack_send(p_ack, COAP_OPT_NET_KETSET_ACK, p_ack->payload.len,p_ack->payload.p_data,0, NULL);
}

static M2M_Return_T relay_package(M2M_protocol_relay_T *p_args,int flags){

    if(!p_args || !p_args->p_payload)
        return M2M_ERR_INVALID;

    return m2m_send(p_args->socket_fd, p_args->p_remote_addr, p_args->p_payload->p_data, p_args->p_payload->len);
}
/* protocol :: coap  interface */
m2m_func _m2m_protocol_funcTable[M2M_PROTO_CMD_MAX + 1] = 
{
    //M2M_PROTO_IOC_CMD_NONE  = 0,
    NULL,
    //M2M_PROTO_IOC_CMD_SESSION_CREAT_RQ = 1,
    NULL,
    //M2M_PROTO_IOC_CMD_SESSION_CREAT_ACK,
    NULL,
    //M2M_PROTO_IOC_CMD_TOKEN_RQ,
    (m2m_func)token_rq,
    //M2M_PROTO_IOC_CMD_TOKEN_ACK,
    (m2m_func)token_ack,
    //M2M_PROTO_IOC_CMD_SESSION_SETKEY_RQ,
    (m2m_func)session_keyset_rq, // 5
    //M2M_PROTO_IOC_CMD_SESSION_SETKEY_ACK,
    (m2m_func)session_keyset_ack,
    //M2M_PROTO_IOC_CMD_PING_RQ,
    (m2m_func)ping_rq,
    //M2M_PROTO_IOC_CMD_PING_ACK,
    (m2m_func)ping_ack,
    //M2M_PROTO_IOC_CMD_DATA_RQ,
    (m2m_func)data_rq,
    //M2M_PROTO_IOC_CMD_DATA_ACK,
    (m2m_func)data_ack,      // 10
    //M2M_PROTO_IOC_CMD_SESSION_DESTORY_RQ,
    NULL,
    //M2M_PROTO_IOC_CMD_SESSION_DESTORY_ACK,
    NULL,
    // M2M_PROTO_IOC_CMD_SESSION_OBSERVER_RQ,
	(m2m_func) observer_rq,
	// M2M_PROTO_IOC_CMD_SESSION_OBSERVER_ACK,
	(m2m_func) observer_ack,
	//M2M_PROTO_IOC_CMD_RECVPKT_RQ,
    (m2m_func)pkt_receive,
    //M2M_PROTO_IOC_CMD_DECODE_PKT_RQ,   //对接收包进行分拆。
    (m2m_func)pkt_decode,
    // M2M_PROTO_IOC_CMD_ERR_PKT_RQ,      // 包解析层面出错，秘钥、crc、protocol 错误
    (m2m_func)error_ack,       // 15
    // M2M_PROTO_IOC_CMD_ERR_PKT_ACK,
    (m2m_func)error_ack,
    
#ifdef CONF_BROADCAST_ENABLE 
    //M2M_PROTO_IOC_CMD_BROADCAST_SEND
    (m2m_func)broadcast_rq,               // 17
    // M2M_PROTO_IOC_CMD_BROADCAST_ACK
    (m2m_func)broadcast_ack,                // 18
#endif //CONF_BROADCAST_ENABLE   

    // M2M_PROTO_IOC_CMD_RELAY
    (m2m_func)relay_package,
   // M2M_PROTO_IOC_NET_SETKEY_RQ,
	 (m2m_func) net_secretsky_set_rq,
	// M2M_PROTO_IOC_NET_SETKEY_ACK,
	 (m2m_func) net_secretsky_set_ack,
    // M2M_PROTO_IOC_CMD_ONLINK_CHECK
    (m2m_func)onlinkchek_rq,
    // M2M_PROTO_IOC_CMD_ONLINK_CHECK_ACK
    (m2m_func)onlinkchek_ack,
    NULL
};
// 获取协议处理函数.
size_t _m2m_protocol_ioctl
    ( M2M_Proto_Cmd_T cmd,void *p_args,int flags)
{
    if( cmd >= M2M_PROTO_CMD_MAX ||
        cmd < 0)
        return M2M_ERR_INVALID;

    if(_m2m_protocol_funcTable[cmd]){
        return (_m2m_protocol_funcTable[cmd])(p_args,flags);
    }
    else{
        m2m_debug_level(M2M_LOG_WARN, "Cannot find function %d!",cmd);
        return 0;
    }
}
// 注册 protocol 处理 函数.
// 建立 socket.
M2M_Return_T m2m_protocol_init(M2M_Protocol_T *p_proto){
    int ret = -1;
    m2m_assert(p_proto,M2M_ERR_INVALID);

    p_proto->func_proto_ioctl = (m2m_func)_m2m_protocol_ioctl;
    
    // socket init 并没有设置 监听端口。
    ret = m2m_openSocket( &p_proto->socket_fd,p_proto->local_port);
    _RETURN_UNEQUAL_0(ret,M2M_ERR_SOCKETERR);
    
    return ret;
}
/****
**  1.关闭 socket.
**  2.
***********/
M2M_Return_T m2m_protocol_deInit(M2M_Protocol_T *p_proto){
	if(p_proto->socket_fd){
		m2m_closeSocket(p_proto->socket_fd);
		p_proto->socket_fd = 0;
	}
    return 0;
}
