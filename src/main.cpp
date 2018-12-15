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
#include "system.h"
#include <EEPROM.h>
void setup()
{
	sys_setup();
    m2m_setup();
}


void loop()
{		
	m2m_loop();
	system_loop();
}

