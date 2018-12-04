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

// product config

/* board define ***/
#define BOARD_ESP_8266
// led
#define LED_WIFI_CONN_PIN  10//16//5
// factory rest key.
#define REST_PIN	5// 5
#define TEST_PIN	4

#define SOFTAP_SSID_	"Evalogik_"
#define EEPROM_CONF_SIZE_MX (2*512)
#define EEPROM_CONF_ADDRESS (32)

#define RESTADDR  (400)
#define SMARTADDR  (350)
#define AUTOADDR  (300)
#ifdef __cplusplus
}
#endif


#endif // _CONFIG_HARDWARE_H

