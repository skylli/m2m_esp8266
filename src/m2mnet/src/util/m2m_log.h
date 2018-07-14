/*
 * m2m projuct
 *
 * FileName: m2m_log.h
 *
 * Description: log function
 *      1.provide log function.
 *      2.log information can write to both file and screen.
 *                                                                                                                                                                                                 
 * Author: skylli
 */
 #include <stdio.h>
 #include <string.h>
#include "../../include/m2m.h"
#include "../../config/config.h"


#ifndef M2M_LOG_H
#define M2M_LOG_H
/** config ************************/
#define LOG_VERBOSE
/** config end***************************/
static const char *s_debug[] = {
        "[ ALL ]",
        "[DEBUG]",
        "[ LOG ]",
        "[WARN ]",
        "[ERROR]",
    };

extern u8 g_log_level;


#define __FILENAME__ (strrchr(__FILE__, '/')? strrchr(__FILE__, '/') + 1 : __FILE__) 
#ifdef LOG_VERBOSE

#ifdef CONF_LOG_TIME 
void current_time_printf();
#define m2m_debug_level(level, format,...) do{ if( level >= g_log_level ){ \
		current_time_printf();\
        m2m_printf("%s: %s func:%s LINE: %d: " format "\r\n",s_debug[level],__FILENAME__,__func__, __LINE__, ##__VA_ARGS__); \
        }}while(0)
#define m2m_debug_level_noend(level, format,...) do{ if( level >= g_log_level ){ \
				current_time_printf();\
                m2m_printf("%s: %s func:%s LINE: %d: " format,s_debug[level],__FILENAME__,__func__, __LINE__, ##__VA_ARGS__); \
                }}while(0)


#else //CONF_LOG_TIME
#define m2m_debug_level(level, format,...) do{ if( level >= g_log_level ){ \
        m2m_printf("%s: %s func:%s LINE: %d: " format "\r\n",s_debug[level],__FILENAME__,__func__, __LINE__, ##__VA_ARGS__); \
        }}while(0)
#define m2m_debug_level_noend(level, format,...) do{ if( level >= g_log_level ){ \
                m2m_printf("%s: %s func:%s LINE: %d: " format,s_debug[level],__FILENAME__,__func__, __LINE__, ##__VA_ARGS__); \
                }}while(0)
#endif  //CONF_LOG_TIME
#else
#define m2m_debug_level(level, format,...) do{ if( level >= g_log_level ){ \
            m2m_printf("%s:" format "\r\n",s_debug[level], ##__VA_ARGS__); \
            }}while(0)
#define m2m_debug_level_noend(level, format,...) do{ if( level >= g_log_level ){ \
                m2m_printf("%s:" format,s_debug[level], ##__VA_ARGS__); \
                }}while(0)
#endif


#define m2m_byte_print(p,n) do{int i=0;for( i=0; p && i<n;i++){ m2m_printf("[%x]",p[i]);}}while(0)
#ifdef C_HAS_FILE
#define m2m_log_init(l)     do{ m2m_record_level_set(l); m2m_record_init(l); }while(0)
#define m2m_log_uninit()    do{ m2m_record_uninit(); }while(0)

#define m2m_log(format,...) do{ m2m_debug_level(M2M_LOG, format, ##__VA_ARGS__); \
                                m2m_record_info(format,##__VA_ARGS__); }while(0)
#define m2m_log_debug(format,...) do{ m2m_debug_level( M2M_LOG_DEBUG, format,##__VA_ARGS__); \
                                       m2m_record_info(format,##__VA_ARGS__); }while(0)
#define m2m_log_warn(format,...) do{ m2m_debug_level( M2M_LOG_WARN, format,##__VA_ARGS__); \
                                     m2m_record_info(format,##__VA_ARGS__);}while(0)
#define m2m_log_error(format,...) do{ m2m_debug_level( M2M_LOG_ERROR, format,##__VA_ARGS__); \
                                      m2m_record_info(format,##__VA_ARGS__);}while(0)
#define m2m_debug(format,...) do{ m2m_debug_level( M2M_LOG_DEBUG, format,##__VA_ARGS__); \
                                  m2m_record_info(format,##__VA_ARGS__);}while(0)
#else
#define m2m_log_init(l)     m2m_record_level_set(l)
#define m2m_log_uninit()    

#define m2m_log(format,...)         m2m_debug_level(M2M_LOG, format, ##__VA_ARGS__)
#define m2m_log_debug(format,...)   m2m_debug_level(M2M_LOG_DEBUG, format, ##__VA_ARGS__)
#define m2m_log_warn(format,...)    m2m_debug_level(M2M_LOG_WARN, format, ##__VA_ARGS__)
#define m2m_log_error(format,...)   m2m_debug_level(M2M_LOG_ERROR, format, ##__VA_ARGS__)
#define m2m_debug(format,...)       m2m_debug_level(M2M_LOG_DEBUG, format, ##__VA_ARGS__)


#endif

void m2m_bytes_dump(u8 *p_shd,u8 *p,int len);
void m2m_record_level_set(int level);
u8 m2m_record_level_get();


#define m2m_assert(_arg, _return) do{if((_arg)==0) \
        {m2m_printf("%s %d, assert failed!\r\n",__func__, __LINE__); \
            return (_return);}}while(0)

/* log api provided */
void m2m_record_init(int level);
void m2m_record_info(const char *fmt, ...);
void m2m_record_debug(const char *fmt, ...);
void m2m_record_warn(const char *fmt, ...);
void m2m_record_error(const char *fmt, ...);
void m2m_record_uninit(void);

#endif
