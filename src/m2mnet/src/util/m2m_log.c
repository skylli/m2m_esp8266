/*************
 * m2m projuct
 * description: 创建或者打开日志文件，把所有的 log 输出并保存到日志目录里.
 * FileName: m2m.h   
 *
 * Description: debug function
 *
 * Author: skylli
 ********/
#include <stdio.h>
#include <time.h>
#include "../../include/m2m_type.h"
#include "m2m_log.h"

u8 g_log_level = 0;

#ifdef C_HAS_FILE

#include <stdarg.h>
#define _LOG_MAXBYTE_LINE   (1024)


typedef struct LOG_T{

    FILE *fp;
    u16 warn_cnt;
    u16 err_cnt;
    u8 level;
}Log_T;
static Log_T log;
char *time_str()
{
	time_t rawtime;
	struct tm* timeinfo;
	static char time_s[256];
	time(&rawtime);
	timeinfo=localtime(&rawtime);
	strftime(time_s, sizeof(time_s), "%Y-%m-%d %I:%M:%S ",timeinfo);
	return time_s;
}

static void m2m_file_print(int level,const char *fmt, ...){

    char buffer[_LOG_MAXBYTE_LINE];
    //screen print
    va_list args;
    
    mmemset((u8*)buffer,0,_LOG_MAXBYTE_LINE);
    va_start(args, format);
    vprintf(format, args);
    vsprintf(buffer,fmt,args);
    va_end(args);

    if(log.fp &&  level > log.level){
        char *time_s = time_str();

        fputs(s_debug[level],log.fp);
		fputs(time_s, log.fp);
		fputs(buffer, log.fp);
		fflush(log.fp);                 // flush new
    }
}
/*
** 1. set log level.
** 2. set log file.
*/
void m2m_record_init(int level){

    g_log_level = level;
      if(log.fp){
        log.fp = fopen(p_file, "w");
        }
    log.err_cnt = 0;
    log.warn_cnt = 0;
    log.level = level;
}
void m2m_record_info(const char *fmt, ...){
    m2m_file_print(M2M_LOG,fmt, ##__VA_ARGS__);
}
void m2m_record_debug(const char *fmt, ...){
    m2m_file_print(M2M_LOG_DEBUG,fmt,##__VA_ARGS__);
}
void m2m_record_warn(const char *fmt, ...){
    m2m_file_print(M2M_LOG_WARN,fmt,##__VA_ARGS__);
    log.warn_cnt++;

}
void m2m_record_error(const char *fmt, ...){
    m2m_file_print(M2M_LOG_ERROR,fmt,##__VA_ARGS__);
    log.err_cnt++;
}
/*
** 1.close log file,if no log file then do nothing.
*/
void m2m_record_uninit(void){
    if(log.fp)
        fclose(log.fp);
    mmemset( (u8*)&log,0,sizeof(Log_T));
}
#endif // C_HAS_FILE

void m2m_record_level_set(int level){
    g_log_level = level;
}
u8 m2m_record_level_get(){
    
    return g_log_level;
}
void m2m_bytes_dump(u8 *p_shd,u8 *p,int len){

    int i ;
    m2m_printf("%s ",p_shd);
    for(i=0;i<len;i++)
        m2m_printf("[%x]",p[i]);
    m2m_printf(" >>end\n");
}
