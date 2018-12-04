	/*********************************************************
** sample 
*********************************************************/
#include <string.h>
#include "Arduino.h"

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

/****** C++ to c declear*******************************************************/

extern "C" int app_cmd_handle(u8 cmd,u8*p_data,int recv_len);

int app_cmd_handle(u8 cmd,u8*p_data,int recv_len){
	int ret = 0;
	Lm2m_ota_data putota;
	Lm2m_ota_data getota;

	switch (cmd){	
		
		case WIFI_CMD_APP_UART_SEND_RQ:
			if(p_data && recv_len)
				ret = Serial.write(p_data,recv_len);
			break;
	}
	
	return ret;
}

