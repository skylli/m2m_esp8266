/*
 * Blink
 * Turns on an LED on for one second,
 * then off for one second, repeatedly.
 */

#include "Arduino.h"
#include "app_m2m_handle.h"

#include "m2mnet/include/m2m.h"
#include "m2mnet/include/m2m_api.h"
#include "m2mnet/include/m2m_port.h"

#include "m2mnet/config/config.h"
#include "m2mnet/platform/esp/function.h"
void setup()
{
    bool autoconnect = false;
    int ret = 0;
    hardware_init();
    Serial.begin(115200);
    randomSeed(analogRead(0));

#if 1
    autoconnect = WiFi.getAutoConnect();
    if(autoconnect){
		
		Serial.println("wp2p_autoConfig: ");
		wp2p_autoConfig();
		}
	else {
		
		Serial.println("wp2p_smartconnect");
		wp2p_smartconnect();
		}
#endif
	Serial.println("m2m working ..IP address: ");
	Serial.println(WiFi.localIP());
    local_ip_save();
    ret = m2m_setup();

}

void loop()
{
    factory_reset();
    m2m_loop();
    
}

