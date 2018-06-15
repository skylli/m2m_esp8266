/*
 * port_esp.c
 * description: esp socket
 *  Created on: 2018-6-9
 *      Author: skylli
 * Time list:
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Arduino.h"
#include <ArduinoOTA.h>
#include "osapi.h"
#include "ets_sys.h"
#include "lwip/inet.h"

#include <stdbool.h>
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>

#include "../../include/m2m_type.h"
#include "config_hardware.h"
#ifndef _FUNCTION_H
#define _FUNCTION_H




#ifdef __cplusplus
extern "C"{
#endif

void hardware_init(void);
void factory_reset(void);
bool wp2p_autoConfig(void);
void wp2p_smartconnect(void);
int io_write(u8 pin,u8 val);
void local_ip_save(void);
int serial_write(u16 slen, u8 *p_data);


#ifdef __cplusplus
}
#endif


#endif // _FUNCTION_H

