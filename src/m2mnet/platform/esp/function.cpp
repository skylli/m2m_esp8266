/*
 * esp_function.c
 * description: esp8266 function.
 *  Created on: 2018-6-13
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
#include "../../include/util.h"
#include "../../src/util/m2m_log.h"
#include "config_hardware.h"
#include "user_interface.h"

/* c interface */
extern "C" void hardware_init(void);
extern "C" void  factory_reset(void);
extern "C" bool wp2p_autoConfig(void);
extern "C" void wp2p_smartconnect(void);
extern "C" int io_write(u8 pin,u8 val);

// function

void hardware_init(void){
	pinMode(REST_PIN, OUTPUT);
	analogWrite(REST_PIN, 0);
	pinMode(REST_PIN, INPUT);

}
void  factory_reset(void){
#if 1

	if(1 == digitalRead(REST_PIN)){
		delay(10);
		if(0 == digitalRead(REST_PIN)){		
			m2m_log_debug(">>>>>>>>>> factory rest !!");
			//Serial.println(ESP.eraseConfig());
			WiFi.disconnect();
			WiFi.setAutoConnect(false);
			delay(5000);
			m2m_log_debug(">>>>>>>>>>  syste restart !!");
			//ESP.reset();
			system_restart();
		}
	}
#endif
}

/*wifi specti*/
/*
*  Calling it will instruct module to switch to the station mode 
*  and connect to the last used access point basing on configuration saved in flash memory.
*/
bool wp2p_autoConfig(void)
{
  // set to sta
  u8 flag = 0;
  u32 last_tm = 0; 
  
  WiFi.mode(WIFI_STA);
  WiFi.begin();
  
  for (int i = 0; i < 1000; i++)
  do{
    int wstatus = WiFi.status();
    if (wstatus == WL_CONNECTED)
    {
      Serial.println("AutoConfig Success");
      Serial.printf("SSID:%s\r\n", WiFi.SSID().c_str());
      Serial.printf("PSW:%s\r\n", WiFi.psk().c_str());
      WiFi.printDiag(Serial);
      return true;
      //break;
    }
    else
    {
      Serial.print("AutoConfig Waiting...");
      Serial.println(wstatus);
      delay(10);
    }
    // key rest 
    factory_reset();
    
     if(DIFF_(millis(),last_tm ) > 500){
        flag = flag ==0 ? 1:0; 
        digitalWrite(LED_WIFI_CONN_PIN,flag);
        last_tm = millis();
    }
  }while(1);
  Serial.println("AutoConfig Faild!" );
  return true;
  //WiFi.printDiag(Serial);
}
/*
* Start smart configuration mode by sniffing for special packets 
*  that contain SSID and password of desired Access Point. Depending on result either true or 
*  false is returned.
*/
void wp2p_smartconnect(void) {
  u8 flag = 0;
  u32 last_tm; 
  int ret = 0;
  // config in output mode   
  pinMode(LED_WIFI_CONN_PIN, OUTPUT);
  digitalWrite(LED_WIFI_CONN_PIN,0);
  
  //Init WiFi as Station, start SmartConfig
  WiFi.mode(WIFI_STA);
  WiFi.beginSmartConfig();
  //Wait for SmartConfig packet from mobile
  Serial.println("Waiting for SmartConfig.");
  while (!WiFi.smartConfigDone()) {
    delay(50);
    if(DIFF_(millis(),last_tm ) > 1000){
        flag = flag ==0 ? 1:0; 
        digitalWrite(LED_WIFI_CONN_PIN,flag);
        last_tm = millis();
    }
        // key rest 
    //factory_reset();
    Serial.print("+");
  }
  //Configure module to automatically connect on power on to the last used access point.
  ret = WiFi.setAutoConnect(true);
  m2m_log_debug("auto connect %d",ret);  
  Serial.println("");
  Serial.println("SmartConfig received.");

  //Wait for WiFi to connect to AP
  Serial.println("Waiting for WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(10);
    Serial.print(".");
  }
  // light up led.
  digitalWrite(LED_WIFI_CONN_PIN,1);

  Serial.println("WiFi Connected.");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
}
/********************* cmd support *******************************/
int io_mode_int(u8 pin,u8 mode){
	//printf(">>>>>>>>>>>>>> pin setting pin  = %d,mode = %d \n",pin,mode);

	pinMode(pin,mode);
	return 0;
}

int io_write(u8 pin,u8 val){

	m2m_log_debug(">>>>>>>>>>>>>> pin setting pin = %d,value = %d \n",pin,val);
	//digitalWrite(pin,val);
    digitalWrite(LED_WIFI_CONN_PIN,val);
	return 0;
}

