/*******************************************************************************

    This file is part of the app_implement.h
    All right reserved.

    File:    app_implement.h

    Description : 
        第三方应用层实现的接口，提供路由表的缓存，维护以及删除更新。

    TIME LIST:
    CREATE  skyli   2017-05-06 13:47:55

*******************************************************************************/
#ifndef _APP_IMPLEMENT_H
#define _APP_IMPLEMENT_H

#ifdef __cplusplus
extern "C"{
#endif

/**********************************************
** description: 读取秘钥.
** args:    
**          addr: 保存秘钥的地址.
** output:
**          p_key;p_keylen;
********/
u32 m2m_secretKey_read(size_t addr,u8 *p_key,u16 *p_keylen);
/** router 路由*******************************************/
/**********************************************
** description: 创建路由列表用于保存：id -- address --- alive time 键值对.
** args:   NULL
** output:
**          指向该 路由表的索引.
********/
void *m2m_relay_list_creat();
// 若  id 存在则更新时间.
/**********************************************
** description: 添加路由设备.
** function:    1.没有该 id 则添加，存在该 id 则更新 address 和时间.
** args:  
**          p_r_list: 路由表的索引.
**          p_id：id，p_addr: 对应的地址。
** output: < 0 则不成功.
********/
int m2m_relay_list_add( void **pp,M2M_id_T *p_id,M2M_Address_T *p_addr);
/**
** 查询 id 是否在 list 里，有则说明设备在线并返回
**************/ 
M2M_Address_T *m2m_relay_id_find( void *p_r_list,M2M_id_T *p_id);

// 更新列表，当 id 超时没有刷新则直接删除该节点.
/**********************************************
** description: 更新路由列表.
** function:    1.sdk 会定时调用该函数，函数需要在每次调用是遍寻每一个 id 的注册时间，一旦超时则清理掉.
** args:  
**          p_r_list: 路由表的索引.
**          p_r_list: 最大的存活时间.
** output:  NULL.
********/
int m2m_relay_list_update(void **pp,u32 max_tm);
void m2m_relay_list_destory(void **pp_list_hd);

#ifdef __cplusplus
}
#endif

#endif //_APP_IMPLEMENT_H
