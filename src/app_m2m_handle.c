/*********************************************************
** sample 
*********************************************************/
#include <string.h>
#include "m2mnet/include/m2m_type.h"
#include "m2mnet/include/m2m.h"
#include "m2mnet/include/m2m_api.h"
#include "m2mnet/include/m2m_log.h"
#include "m2mnet/config/config.h"
#include "m2mnet/include/app_implement.h"
#include "m2mnet/include/util.h"
#include "m2mnet/include/m2m_app.h"
#include "app_m2m_handle.h"
#include "app_config.h"




#include "system.h"
#include "application_cmd_handle.h"



extern char *getlocal_ip(void);
u16 id = 0; 

static M2M_id_T device_id;
static M2M_T m2m;
static BOOL destory_flag = 0;
void dev_callback(int code,M2M_packet_T **pp_ack_pkt, void *p_r,void *p_arg);


typedef struct DEV_OBS_T
{
	void *p_node;
	int obs_rq_cnt;
	int notify_cnt;
	int reobserver_cnt;
	BOOL reobserver_en;
	BOOL notify_push_en;
	BOOL exit;
} Dev_obs_T;
static Dev_obs_T obs;



int m2m_setup(void){
    M2M_conf_T conf;
    M2M_id_T hid;
	
    mmemset( (u8*)&hid, 0, sizeof(M2M_id_T));
    //device_id.id[0] = TST_DEV_LOCAL_ID; 
    conf.def_enc_type = M2M_ENC_TYPE_AES128;
	// config host id 
    getmac((u8*)&device_id.id[ ID_LEN - 6 ]);
	
	// creat entire id of the product.
	product_id_head_set( device_id.id, ID_VERSION, ID_TYPE_DEVICE, (s16)ID_CLASS_LED, (u32)ID_PRODUCT_LED_SHOWHOME, NULL);
	product_id_print( &device_id);

	string2hexarry((u8*)&hid, TST_SERVER_ID, strlen(TST_SERVER_ID));
    conf.max_router_tm = 10*60*1000;
    conf.do_relay = 0;
    m2m_int(&conf);

	SYS_Host_info_t *p_host = sys_host_creat();

	if(p_host){

		m2m.net = m2m_net_creat( &device_id,TST_DEV_LOCAL_PORT, strlen(TST_DEV_LOCAL_KEY),TST_DEV_LOCAL_KEY,\
	                             &hid,p_host->cname, p_host->port,(m2m_func)dev_callback, &obs);
		mfree(p_host);	
	}else{
		  m2m.net = m2m_net_creat( &device_id,TST_DEV_LOCAL_PORT, strlen(TST_DEV_LOCAL_KEY),TST_DEV_LOCAL_KEY,\
                             &hid,TST_SERVER_HOST, TST_SERVER_PORT,(m2m_func)dev_callback, &obs);
	}

    if( m2m.net == 0 ){
        m2m_printf(" creat network failt !!\n");
        return -1;
    }
	
    return 0;
}
int m2m_loop(void){
	static u32 old_tm = 0;
    static BOOL net_stat = 0;
    // 创建 net ，连接到远端服务器。
    // M2M_Return_T m2m_int(M2M_conf_T *p_conf);
		while(1){
			sys_connect_status_hanle( m2m.net );
			sys_factory_reset();
			m2m_trysync( m2m.net );
        if(DIFF_(old_tm, m2m_current_time_get()) > CHECK_ONLINE_TM){ 
            net_stat = m2m_event_host_offline( m2m.net);
            if(!net_stat){ 
                //printf("the server is  on the net !!\n");
                }
            else{
                //printf("the server is not on the net !!\n");
                //todo
                }
            old_tm = m2m_current_time_get();
            }
            
		#if 0	
			if(obs.p_node ){
				if(DIFF_(old_tm, m2m_current_time_get()) > NOTIFY_INTERVAL_TM){	
					m2m_session_notify_push( &m2m, obs.p_node, strlen(TCONF_NOTIFY_DATA1),TCONF_NOTIFY_DATA1, dev_callback, &obs);
					old_tm = m2m_current_time_get();
				}
			}	
		#endif
		}	
	return 1;
}
void dev_callback(int code, M2M_packet_T **pp_ack_data,void *p_r,void *p_arg){
	M2M_obs_payload_T *p_robs = NULL;
	Dev_obs_T *p_devobs = NULL;
	M2M_packet_T *p_recv_data = (M2M_packet_T*)p_r;
    m2m_log_warn("rcode %d", code);
    //m2m_printf(" application dump 1111 rcode %d\n",code);
    switch(code){
        case M2M_REQUEST_BROADCAST: 
            {
                 M2M_packet_T *p_ack = (M2M_packet_T*)mmalloc(sizeof(M2M_packet_T));
                 p_ack->p_data = (u8*)mmalloc( sizeof( M2M_id_T) + strlen(getlocal_ip()) + 1 );
                 p_ack->len = sizeof( M2M_id_T) + strlen(getlocal_ip());
                 mcpy( (u8*)p_ack->p_data, (u8*)device_id.id, sizeof(M2M_id_T) );
                 mcpy( (u8*)&p_ack->p_data[sizeof(M2M_id_T)], (u8*)getlocal_ip(),  strlen(getlocal_ip()));
                 m2m_log_debug("local ip %s\n", getlocal_ip());

                 m2m_bytes_dump("local ip dump : ", (u8*)getlocal_ip(),  strlen(getlocal_ip()) );
                 m2m_log_debug("server receive code = %d\n", code);
                 if( p_recv_data->len > 0 && p_recv_data->p_data){
                      m2m_log("server receive data : %s\n",p_recv_data->p_data);
                }
                *pp_ack_data = p_ack;
            }
            break;
	
		case M2M_REQUEST_OBSERVER_RQ:
	
			if(!p_arg || !p_r)
				break;
			
			p_devobs = (Dev_obs_T*) p_arg;	
			p_robs = (M2M_obs_payload_T*) p_r;
			p_devobs->p_node = p_robs->p_obs_node;
			p_devobs->notify_push_en = 1;
			p_devobs->obs_rq_cnt++;
			m2m_debug("receive an observer request.");
			if(p_robs->p_payload->len && p_robs->p_payload->p_data){
				m2m_log("request data: %s", p_robs->p_payload->p_data);
			}
			break;
		case M2M_ERR_OBSERVER_DISCARD:
			m2m_debug("observer have been destory.");
			if(!p_arg || !p_r )
				break;
			p_devobs = (Dev_obs_T*) p_arg;	
			p_robs = (M2M_obs_payload_T*) p_r;
			p_devobs->p_node = p_robs->p_obs_node;			
			p_devobs->exit = 1;
			break;
		case M2M_REQUEST_DATA:
			//todo data Lm2m_data_T
            if( p_recv_data && p_recv_data->len > 0 && p_recv_data->p_data){
                u8 *p_data=NULL, cmd =0;
                    m2m_bytes_dump((u8*)"application dump : ", p_recv_data->p_data, p_recv_data->len);
         //to divice the pack
                    int recv_len = wifi_decode1( &p_data, &cmd, p_recv_data->len, p_recv_data->p_data);

					 m2m_bytes_dump((u8*)"p_data dump : ",p_data , recv_len);
					 
					 if(cmd < WIFI_CMD_APP_UART_SEND_RQ )
						sys_cmd_handle(cmd, p_data, recv_len);  // only  handle system command.
					 else
					 	app_cmd_handle(cmd, p_data, recv_len); // handle application command.
               }
			break;
        default:
            if( p_recv_data && p_recv_data->len > 0 && p_recv_data->p_data){
                M2M_packet_T *p_ack = (M2M_packet_T*)mmalloc(sizeof(M2M_packet_T));
                p_ack->p_data = (u8*)mmalloc( p_recv_data->len + 1 );
                p_ack->len = p_recv_data->len;
                
                mcpy((u8*) p_ack->p_data, p_recv_data->p_data, p_ack->len);
                
                m2m_log("receive data : %s\n",p_recv_data->p_data);
                m2m_bytes_dump((u8*)"recv dump : ", p_recv_data->p_data, p_recv_data->len);

                 if(p_arg ) {
                        *((int*) p_arg) = *((int*) p_arg) - 1;
                    }
                 *pp_ack_data = p_ack;
                }
            break;
    }

 }

/** 以下函数无需修改，只需声明即可.****************************************************************/
/**********************************************
** description: 读取秘钥.
** args:    
**          addr: 保存秘钥的地址.
** output:
**          p_key;p_keylen;
********/
u32 m2m_secretKey_read(size_t addr,u8 *p_key,u16 *p_keylen){ return 0;}
/** router 路由*******************************************/
/**********************************************
** description: 创建路由列表用于保存：id -- address --- alive time 键值对.
** args:   NULL
** output:
**          指向该 路由表的索引.
********/
void *m2m_relay_list_creat(){ return 0;}
void m2m_relay_list_destory(void **pp_list_hd){

    return ;
}

// 若  id 存在则更新时间.
/**********************************************
** description: 添加路由设备.
** function:    1.没有该 id 则添加，存在该 id 则更新 address 和时间.
** args:  
**          p_r_list: 路由表的索引.
**          p_id：id，p_addr: 对应的地址。
** output: < 0 则不成功.
********/
int m2m_relay_list_add( void **pp,M2M_id_T *p_id,M2M_Address_T *p_addr){ return 0;}
/** 删除****/
int m2m_relay_list_dele( void *p_r_list,M2M_id_T *p_id){ return 0;}
// 更新列表，当 id 超时没有刷新则直接删除该节点.
/**********************************************
** description: 更新路由列表.
** function:    1.sdk 会定时调用该函数，函数需要在每次调用是遍寻每一个 id 的注册时间，一旦超时则清理掉.
** args:  
**          p_r_list: 路由表的索引.
**          p_r_list: 最大的存活时间.
** output:  NULL.
********/
int m2m_relay_list_update(void **pp,u32 max_tm){  return 0;}
int m2m_relay_id_find(M2M_Address_T *p_addr, void *p_r_list,M2M_id_T *p_id){ return 0;}


