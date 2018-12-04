/*
 * protocol_m2m.h
 * description: m2m protocol declaration file.
 *	Created on: 2018-1-13
 *  	Author: skylli
*/
// 每一个 net 都有一个 上层的 ip，当接收的包不是发给自身，且查询转发列表没有对应的 id 时往 host 转发。
#include "../../../include/m2m.h"
#include "../../../include/util.h"
#include "../../../include/utlist.h"
#include "../../../include/m2m_port.h"

#include "../../../include/m2m_log.h"
#include <string.h>

// #define _RETURNNONE_PP_IS_NULL(pp)   do{ if( !pp || *pp) return ;}while(0)
// #define _RETURN_PP_IS_NULL(pp,r)   do{ if( !pp || *pp) return r;}while(0)
/** relay 中转管理*******************************************/
typedef struct RELAY_NODE_T{
    struct RELAY_NODE_T *next;
    u32 alive_time;
    
    M2M_id_T id;
    M2M_Address_T addr;
}Relay_node_T;
/**********************************************
** description: 创建路由列表用于保存：id -- address --- alive time 键值对.
** args:   NULL
** output:
**          指向该 路由表的索引.
********/

void *relay_list_creat(){
    
    return NULL;
}
// pp_list_hd 为 指针的指针的指针
void relay_list_destory(void **pp){

    Relay_node_T *p_hd,*p_el=NULL,*p_tmp = NULL;
    _RETURN_VOID_EQUAL_0(pp);

    p_hd = (Relay_node_T*)*pp; 
    LL_FOREACH_SAFE(p_hd, p_el, p_tmp){
        LL_DELETE(p_hd,p_el);
        mfree(p_el);
    }
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
int list_add( Relay_node_T **pp,M2M_id_T *p_id,M2M_Address_T *p_addr){ 

    Relay_node_T *p_hd = *pp;
    Relay_node_T *p_new = mmalloc( sizeof(Relay_node_T));
    _RETURN_EQUAL_0(p_new, -1);

    p_new->alive_time = m2m_current_time_get();
    mcpy( (u8*)&p_new->id,  (u8*)p_id, sizeof(M2M_id_T));
    mcpy( (u8*)&p_new->addr, (u8*)p_addr, sizeof(M2M_Address_T));

    LL_APPEND(p_hd, p_new);
    *pp = p_hd;
    
    m2m_debug_level(M2M_LOG,"devices online list ip is %d.%d.%d.%d \n", p_addr->ip[0], p_addr->ip[1], p_addr->ip[2], p_addr->ip[3]);
    m2m_bytes_dump((u8*)"list device add: ", (u8*)p_id, sizeof(M2M_id_T));
    return 0;
}
Relay_node_T *list_node_find(Relay_node_T *p_hd,M2M_id_T *p_id){
    Relay_node_T *p_el = NULL, *p_tmp = NULL;

    _RETURN_EQUAL_0(p_hd, NULL);
    LL_FOREACH_SAFE(p_hd,p_el, p_tmp){
        if( memcmp((void*)&p_el->id, (void*)p_id, sizeof(M2M_id_T)) == 0)
            return p_el;
    }
    return NULL;
}
int list_addr_find(M2M_Address_T       *p_addr,void *p,M2M_id_T *p_id){

    Relay_node_T *p_hd = (Relay_node_T*)p, *p_el = NULL, *p_tmp = NULL;
    
    LL_FOREACH_SAFE(p_hd,p_el, p_tmp){
        if( memcmp(&p_el->id, p_id->id,  ID_LEN) == 0){
			mcpy( (u8*)p_addr, (u8*)&p_el->addr, sizeof(M2M_Address_T));
		}
            return 0;
    }
    return -1;

}

int relay_list_add( void **pp,M2M_id_T *p_id,M2M_Address_T *p_addr){ 
    int ret = 0;
    
    Relay_node_T *p_hd = (Relay_node_T*)*pp;
    Relay_node_T *p_find = list_node_find(p_hd, p_id);
    if(p_find ){
        
        m2m_debug_level(M2M_LOG,"devices online update \n");
        m2m_bytes_dump((u8*)"update device id is: ", (u8*)p_id, sizeof(M2M_id_T));
        mcpy( (u8*)&p_find->addr, (u8*)p_addr,sizeof(M2M_Address_T));
        p_find->alive_time = m2m_current_time_get();
    }
    else {
        m2m_debug_level(M2M_LOG,"new devices add to online list\n");
        ret = list_add((Relay_node_T**)pp, p_id, p_addr);
    }
    
    return ret;
}

// 更新列表，当 id 超时没有刷新则直接删除该节点.
/**********************************************
** description: 更新路由列表.
** function:    1.sdk 会定时调用该函数，函数需要在每次调用是遍寻每一个 id 的注册时间，一旦超时则清理掉.
** args:  
**          p_r_list: 路由表的索引.
**          p_r_list: 最大的存活时间.
** output:  NULL.
********/
int relay_list_update(void **pp,u32 max_tm){
    Relay_node_T  *p_hd = NULL,*p_el = NULL, *p_tmp = NULL;
    u32 curr_tm =  m2m_current_time_get();

    _RETURN_EQUAL_0(pp, M2M_ERR_NULL);
    
    p_hd = (Relay_node_T*)*pp;
    _RETURN_EQUAL_0(p_hd,M2M_ERR_NULL);
    
    LL_FOREACH_SAFE(p_hd, p_el, p_tmp){
        if( A_BIGER_U32(curr_tm, (p_el->alive_time + max_tm ) ) ){
            m2m_bytes_dump((u8*)"device have been time out delete it:", (u8*)&p_el->id, sizeof(M2M_id_T));
            LL_DELETE(p_hd,p_el);
            mfree(p_el);
        }
    }
    *pp = p_hd;
    return M2M_ERR_NOERR;
}
// 每个设备 检查对应的 host list，并吧超时的id 清理掉。

/** util test.
****************************************************/
//#define ROUTER_UTIL_TST
#ifdef ROUTER_UTIL_TST
#define TST_PRINT_RECORD(p_add, id) do{ \
        if(p_add){    \
        m2m_bytes_dump("id: ", &id,sizeof(M2M_id_T)); \
        m2m_printf("\n\tip is %d.%d.%d.%d \n", p_add->ip[0],p_add->ip[1],p_add->ip[2],p_add->ip[3]);\
        }}while(0)

enum{
    UTST_RELAY_ADD = 0,
    UTST_RELAY_FIND,
    UTST_RELAY_UPDATE,
    UTST_RELAY_TIMEOUT,
    UTST_RELAY_MAX
}UTEST_RELAY;
int utst_relay_ret[UTST_RELAY_MAX];
char *utst_relay_item_name[UTST_RELAY_MAX] = {
    "relay info add",
    "relay info find",
    "relay info update"
    "relay info time out "
};
int utst_relay_result(int *p_ret,u8 **p_name, int items){
    int i =0,test_result = 0;
    for(i=0;i<items;i++){
        if( p_ret[i] == 1){
            test_result++;
            m2m_printf(">>>>\t %s test successfully !\n",p_name[i]);
            }
        else
            m2m_printf(">>>>\t %s test have failt \n",p_name[i]);
    }
    if(test_result == items){
        
        m2m_printf(">> function test is totaly success \n");
        return 0;
        }
    else{
        m2m_printf(">> function test is failt. plasese have a check. \n");
        return -1;
        } 
}

int tst_relay_list(void){

    int ret = 0;
    M2M_id_T id1,id2,id3 , a_find;
    M2M_Address_T addr1,addr2,addr3, addr4, *p_find_addr = &a_find;

    mmemset( (u8*)&id1, 0, sizeof(M2M_id_T));
    mmemset( (u8*)&id2, 0, sizeof(M2M_id_T));
    mmemset( (u8*)&id3, 0, sizeof(M2M_id_T));

    mmemset( (u8*)&addr1, 0, sizeof(M2M_Address_T));
    mmemset( (u8*)&addr2, 0, sizeof(M2M_Address_T));
    mmemset( (u8*)&addr3, 0, sizeof(M2M_Address_T));  
	
    mmemset( (u8*)&p_find_addr, 0, sizeof(M2M_Address_T));  
    /** 初始化设备***/ 
    id1.id[sizeof(M2M_id_T)-1] = 1;
    id2.id[sizeof(M2M_id_T)-1] = 2;
    id3.id[sizeof(M2M_id_T)-1] = 3;

    m2m_gethostbyname(&addr1, "192.168.0.1");
    m2m_gethostbyname(&addr2, "192.168.0.2");
    m2m_gethostbyname(&addr3, "192.168.0.3");
    m2m_gethostbyname(&addr4, "192.168.0.4");
    void *p_hd = (void*)relay_list_creat();
    /**添加多个设备****/
    
    relay_list_add( &p_hd, &id1, &addr1);
    relay_list_add( &p_hd, &id2, &addr2);
    relay_list_add( &p_hd, &id3, &addr3);
    
    /** 查找设备 **/ 
    ret = list_addr_find(p_find_addr,p_hd, &id2);
    TST_PRINT_RECORD(p_find_addr,id2);
    p_find_addr = list_addr_find(p_hd, &id3);
    TST_PRINT_RECORD(p_find_addr,id3);
    if( memcmp(p_find_addr, &addr3,sizeof(M2M_Address_T) ) == 0)
        utst_relay_ret[UTST_RELAY_ADD] = 1;
    /** 更新多个设备 ***/
    relay_list_add( &p_hd, &id3, &addr4);
    list_addr_find(p_find_addr,p_hd, &id3);
    TST_PRINT_RECORD(p_find_addr,id3);
    if( memcmp(p_find_addr, &addr4,sizeof(M2M_Address_T) ) == 0){
        utst_relay_ret[UTST_RELAY_FIND] = 1;
        utst_relay_ret[UTST_RELAY_UPDATE] = 1;
    }
    /** 设备过期，更新*/
    sleep(3);
    
    relay_list_add( &p_hd, &id2, &addr2);
    relay_list_update(&p_hd, 1000);
    list_addr_find(p_find_addr,p_hd, &id3);
    if(p_find_addr == NULL){
        utst_relay_ret[UTST_RELAY_TIMEOUT] = 1;
    }
    /** 清空设备列表*/
    relay_list_destory(&p_hd);
    p_hd = NULL;
    utst_relay_result(utst_relay_ret,utst_relay_item_name,UTST_RELAY_MAX -1 );

    return 0;
}

#endif // ROUTER_UTIL_TST
