
#ifndef MYLOG_H
#define MYLOG_H
#pragma once

/*
 * MYLOG library
 * 
 * STRUCTURES
 *  struct log_file     used to store files to output in linked list style
 *  struct log_control  used to store information about logging settings
 * 
 * FUNCTIONS
 *  startMyLog(flags, filters, identity)    Starts new log. if not called before logging
 *                                          default log is started with output to syslog.
 *  closeMyLog(void)                        Cleans open logs. Automaticly called at exit.
 *  addFileToLog(path)                      Adds to file to logs ouput. If there log
 *                                          was not started with flag OUT_FILE throws error.
 * 
 *  LOG(level, msg, ...)                      Macro simplifying logging.
 * 
 * FLAGS
 *  OUT_STDERR      Allows output to standard error output
 *  OUT_FILE        Allows output to files
 *  OUT_SYSLOG      Allows output to syslog. Only Linux
 *
 * FILTERS
 *  FILTER_ERROR    Allows only errors to be logged.
 *  FILTER_WARN     Allows only warnings and higher priority messages to be logged. 
 *  FILTER_INFO     Allows only informative and higher priority messages to be logged.
 *  FILTER_DEBUG    Allows all messages with valid level to be logged
 * 
 * LEVELS
 *  ERR         Level error - Highest priority message
 *  WARN        Level warning
 *  INFO        Level information
 *  DEBUG       Level debug - message only for debuging purposes (logs filename
 *                            and line in which was logged)
 */

#ifdef  __linux__
#define OUT_SYSLOG 0b10000
#endif

#define OUT_FILE 0b100000
#define OUT_STDERR 0b1000000

#define FILETR_NONE 0b1111
#define FILTER_ERROR 0b111
#define FILTER_WARN 0b11
#define FILTER_INFO 0b1
#define FILTER_DEBUG 0

#define MY_ERR 0b1000
#define MY_WARN 0b100
#define MY_INFO 0b10
#define MY_DEBUG 0b1

#ifdef __linux__
#define LOG(level, msg, ...)                                       \
    do                                                             \
    {                                                              \
        mySyslog(level, __FILE__, __LINE__, msg  ,##__VA_ARGS__);   \
        logMessage(level, __FILE__, __LINE__, msg ,##__VA_ARGS__); \
    } while (0)
#else
#define LOG(level, msg, ...) logMessage(level, __FILE__, __LINE__ , msg ,##__VA_ARGS__)
#endif


#ifdef __cplusplus
extern "C" {
#endif
struct log_file;
struct log_control;

void startMyLog(int flags,int filters, const char *identity);
void closeMyLog(void);
struct log_file *addFileToLog(const char *path);
void logMessage(int level, const char *file, int line, const char *msg, ...);

#ifdef __linux__
void mySyslog(int logLvl, const char *file, int line, const char *msg, ...);
#endif

#ifdef __cplusplus
}
#endif

#endif // MYLOG_H
