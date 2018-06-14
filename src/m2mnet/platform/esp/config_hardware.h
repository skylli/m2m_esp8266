/*
 * port_esp.c
 * description: esp socket
 *  Created on: 2018-6-9
 *      Author: skylli
 * Time list:
 */
#ifndef _CONFIG_HARDWARE_H
#define _CONFIG_HARDWARE_H


#ifdef __cplusplus
extern "C"{
#endif

/* board define ***/
#define BOARD_ESP_8266
// led
#define LED_WIFI_CONN_PIN  5//16//5
// factory rest key.
#define REST_PIN	16// 5

#ifdef __cplusplus
}
#endif


#endif // _CONFIG_HARDWARE_H

