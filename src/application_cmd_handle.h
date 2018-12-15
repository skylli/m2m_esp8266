/*********************************************************
** 功能测试： token, key 设置,广播测试.
*********************************************************/
#ifndef  _APPLICATION_CMD_HANDLE_H
#define _APPLICATION_CMD_HANDLE_H

#ifdef __cplusplus
extern "C"{
#endif

int app_cmd_handle(u8 cmd,u8*p_data,int recv_len,M2M_packet_T **pp_ack_data);


#ifdef __cplusplus
}
#endif

#endif //_APPLICATION_CMD_HANDLE_H

