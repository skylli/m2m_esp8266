/*********************************************************
** 对接收过来的数据解析和执行 
*********************************************************/
#include <string.h>
#include "m2mnet/include/m2m_type.h"
#include "m2mnet/include/m2m.h"
#include "m2mnet/include/m2m_api.h"
#include "m2mnet/src/util/m2m_log.h"
#include "m2mnet/config/config.h"
#include "m2mnet/include/app_implement.h"
#include "m2mnet/include/util.h"
#include "m2mnet/three_party/hadc_protocol/hadc.h"
#include "app_m2m_handle.h"
#include "user_interface.h"

int cmd_handle(u8 cmd, u16 slen, u8 *p_data){
    int ret = 0;
    switch(cmd){
        case HADC_TYPE_UART:
        serial_write(slen,p_data);
        m2m_log("receive cmd %d data : %s\n", cmd,p_data);
        break;
        
    }
}

