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
#include "../../config/config.h"
#include "../../include/m2m_log.h"

u8 g_log_level = M2M_LOG_ALL;

#ifdef CONF_LOG_TIME
void current_time_printf(void){
    time_t timep;
    struct tm *p;
    time(&timep);
    p = localtime(&timep); //取得当地时间
    m2m_printf ("%d%02d%02d ", (1900+p->tm_year), (1+p->tm_mon), p->tm_mday);
    m2m_printf("%02d:%02d:%02d  ", p->tm_hour, p->tm_min, p->tm_sec);
}
#endif //CONF_LOG_TIME

#ifdef C_HAS_FILE

#include <stdarg.h>
#define _LOG_MAXBYTE_LINE   (1024)



Log_T g_mlog;
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
static void _log_filename_update(){
	char path[256];

	mmemset(path, 0, 256);
	time_t timep;
	struct tm *p_tm;
	time(&timep);
	p_tm = localtime(&timep); //取得当地时间
	if( g_mlog.p_log_path &&  ( !g_mlog.fp || 	g_mlog.file_index != p_tm->tm_mday ) ){
		char *p = path + strlen(g_mlog.p_log_path); 
		if(g_mlog.fp)
			fclose(g_mlog.fp);
		mcpy(path, g_mlog.p_log_path, strlen(g_mlog.p_log_path));
		sprintf(p, "%d%02d%02d.log",(1900+p_tm->tm_year), (1+p_tm->tm_mon), p_tm->tm_mday);
		m2m_printf("creat an new file %s\n", path);
		g_mlog.file_index = p_tm->tm_mday;
		g_mlog.fp = fopen(path, "a");
	}

	return ;
}
void m2m_file_print(int level,const char *fmt, ...){

	int n = 0;
    char buffer[_LOG_MAXBYTE_LINE];
	char *p = buffer;
	time_t timep;
    struct tm *p_tm;
    time(&timep);
    p_tm = localtime(&timep); //取得当地时间

    //screen print
    va_list args;
    mmemset((u8*)buffer,0,_LOG_MAXBYTE_LINE);
    va_start(args, fmt);
    n = sprintf(p,"%s %d%02d%02d %02d:%02d:%02d ",s_debug[level], (1900+p_tm->tm_year), (1+p_tm->tm_mon), p_tm->tm_mday,p_tm->tm_hour, p_tm->tm_min, p_tm->tm_sec);
	p = (n>0)?(p+n):p;
	n = vsprintf( p,fmt,args);
	p = (n>0)?(p+n):p;
	*p = '\n';
    va_end(args);
	_log_filename_update();
  	if(level >= g_mlog.level){
#ifndef NOSTDOUTPUT
		m2m_printf("%s",buffer);
#endif
		if(g_mlog.fp ){
			fputs(buffer, g_mlog.fp);
			fflush(g_mlog.fp); // flush new
		}
   	}
}
/*
** 1. set log level.
** 2. set log file.
*/
void m2m_record_init(int level, const char *p_file){

	char path[256];

	mmemset(path, 0, 256);
	if(p_file){
		time_t timep;
	    struct tm *p_tm;
	    time(&timep);
	    p_tm = localtime(&timep); //取得当地时间
		char *p = path + strlen(p_file); 
		mcpy(path, p_file, strlen(p_file));
		sprintf(p, "%d%02d%02d.log",(1900+p_tm->tm_year), (1+p_tm->tm_mon), p_tm->tm_mday);
		g_mlog.file_index = p_tm->tm_mday;		
		g_mlog.fp = fopen(path, "a");
	}
	
    g_log_level = level;	
	g_mlog.err_cnt = 0;
    g_mlog.warn_cnt = 0;
    g_mlog.level = level;
	g_mlog.p_log_path = mmalloc(strlen(p_file) +1);
	if(g_mlog.p_log_path ){
		mcpy(g_mlog.p_log_path, p_file, strlen(p_file));
	}
}
#if 0
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
#endif
/*
** 1.close log file,if no log file then do nothing.
*/
void m2m_record_uninit(void){
    if(g_mlog.fp)
        fclose(g_mlog.fp);
	mfree(g_mlog.p_log_path);
    mmemset( (u8*)&g_mlog,0,sizeof(Log_T));
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
    if(g_log_level <= M2M_LOG_DEBUG){
	//if(1){	
		m2m_printf("%s ",p_shd);
	    for(i=0;i<len;i++)
	        m2m_printf("[%x]",p[i]);
	    m2m_printf(" >>end\n");
	}
}
