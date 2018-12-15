/*******************************************************************************

    This file is part of the debug.c.
    Copyright m2m.com
    All right reserved.

    File:    util.c

    No description

    TIME LIST:
    CREATE  skyli   2017-05-06 13:47:55

*******************************************************************************/
#include <stdlib.h>
#include <string.h>
#include "../../include/util.h"
#include "../../include/m2m_type.h"
#include "../../include/m2m.h"
#include "../../include/m2m_log.h"

int ascii_to_2u32(const char *devid, u32 *dev0, u32 *dev1)
{
    char tmp0[32];
    char tmp1[32];
    int i;

    if(!devid  || !dev0 || !dev1 || strlen(devid) != 16)
        return -1;

    memset(tmp0, 0, sizeof(tmp0));
    memset(tmp1, 0, sizeof(tmp1));

    strncpy(tmp0, devid, 8);
    strncpy(tmp1, devid + 8, 8);

    sscanf(tmp0, "%08x", dev0);
    sscanf(tmp1, "%08x", dev1);

    return 0;
}

void *mmalloc(size_t size){
    void *p_ret = NULL;
    if( size == 0 )
        return 0;
    
    p_ret = malloc(size);
    if(p_ret )
        memset(p_ret,0,size);
    return p_ret;
}

int mmemset(u8 *dst,u8 c,size_t n){
    int i;
    for(i=0;i<n;i++){
        dst[i] = c;
    }
    return 0;
}
void mfree(void *ptr){
    if( !ptr)
        return ;
    free(ptr);
}
void mcpy(u8 *d,u8 *s,int len){
    memcpy((void*)d,(void*)s,(size_t)len);
}
int string2hexarry(u8 *p_dst, const u8 *p_st, int nlen){

	int ret = 0;
	u8 format[10];
	mmemset(format, 0, 10);

	if(!p_dst || !p_st || nlen == 0)
		return -1;
	int l;
	u8 *p_s = p_st + nlen, *p_d = p_dst;
		
	for(l=nlen;l>0;l -=8){
		if(l>=8){
			p_s -=8; 
			sscanf(p_s, "%08x", p_d);
			p_d +=4;
			ret +=4;
		}else{
			p_s -=l;
			mcpy(format, "\%02x", strlen("\%08x"));
			format[2] = l + '0';
			sscanf(p_s, format, p_d);
			ret  += l/2;
			break;
		}
	}		
		
	return ret;	
}

int product_id_pid_metch(u8 *p_id,   u32 pid){
	u32 src = 0;
	mcpy(&src, &p_id[ID_LEN - 6 - sizeof(u32)],  sizeof(u32));
	if(src == pid)
		return TRUE;
	else 
		return FALSE;
}

int product_id_head_set(u8 *p_id,char ver, char type, s16 class, u32 pid, u8 *p_mac){
	int position = 0;
	if(p_mac)
		mcpy( &p_id[ ID_LEN - 6 ],  p_mac, 6);
	position = ID_LEN - 6 - sizeof(u32);
	mcpy(&p_id[position], &pid, sizeof(u32));
	
	position -= sizeof(s16);
	mcpy(&p_id[position], &class, sizeof(s16));
	
	position -= ( 2 + 1 );
	p_id[position] = type;
	position -= 1;
	p_id[position] = ver;	

	//m2m_bytes_dump( "ID : ", p_id,  ID_LEN );
}
void product_id_print(u8 *p_id){

	m2m_printf("ID version: %0x \n", p_id[ 0]);
	m2m_printf("Id type: %0x \n (0-devices, 1-app, 2-servers)", p_id[ 1 ]);
	m2m_printf("ID factory: [%0x %0x]\n", p_id[ 2 ], p_id[ 3] );
	m2m_printf("ID class: [%0x %0x] \n", p_id[ 4 ], p_id[ 5 ] );
	m2m_bytes_dump( "ID product: ",&p_id[  6 + sizeof(u32)], sizeof(u32) );
	m2m_bytes_dump( "ID mac: ",&p_id[ ID_LEN - 6  ], 6 );
}
void byte_printf(u8 *p_had,u8 *p_byte, int len){
	int i = 0;
	if(p_had){
		m2m_printf("%s: ", p_had);
	}
	for(i=0; i< len; i++){
		m2m_printf("%02x", p_byte[i]);
	}
	m2m_printf("\n");
}
