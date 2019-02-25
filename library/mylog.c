#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#ifdef __linux__
#include <syslog.h>
#else
#define LOG_DEBUG 0
#define LOG_ERR 0
#define LOG_WARNING 0
#define LOG_INFO 0

#define error(return_code, errno, msg, ...) do { \
	fprintf(stderr, msg, ##__VA_ARGS__);	\
	perror(errno);	\
	if(return_code)	\
		exit(return_code);	\
	} while(0);
#endif
#include <string.h>
#include <stdarg.h>

#include "mylog.h"

struct log_file
{
	FILE *f;
	struct log_file *next;
};

struct log_control
{
    int flags;
    char *identity;
    struct log_file *files;
};

const struct mapLogLvl
{
	int mylog, syslog;
	const char str[32];
} Levels[] = {{DEBUG, LOG_DEBUG,   "DEBUG"},
			  {ERR,   LOG_ERR,     "\033[31mERROR\033[0m"},
			  {WARN,  LOG_WARNING, "\033[31mWARNING\033[0m"},
			  {INFO,  LOG_INFO,    "INFO"},
			  {0}};

struct log_control *MainLog = NULL;

// Gets level which is syslog using equivalent to one mylog is using
int myLvlToSyslog(int lvl)
{
	for (int i = 0; Levels[i].mylog != 0; i++)
	{
		if (Levels[i].mylog == lvl)
			return Levels[i].syslog;
	}
	return -1;
}

// Gets string version of lvl
const char *myLvlToString(int lvl)
{
	for (int i = 0; Levels[i].mylog != 0; i++)
	{
		if (Levels[i].mylog == lvl)
			return Levels[i].str;
	}
	return NULL;
}

// Cleans after my log
void closeMyLog(void)
{
	if (MainLog == NULL)
		return;
	if (OUT_FILE & MainLog->flags)
	{
		struct log_file *current = MainLog->files;
		struct log_file *prev = NULL;
		while (current != NULL)
		{
			if (current->f != stderr && current->f != NULL)
				fclose(current->f);
			prev = current;
			current = current->next;
			free(prev);
		}
	}
	if (MainLog != NULL)
		free(MainLog);
#ifdef __linux__
	if (OUT_SYSLOG & MainLog->flags)
		closelog();
#endif
	MainLog = NULL;
}

// In case log wasn't started by user starts default log
void startDefaultLog(void)
{
	if ((MainLog = (struct log_control *) malloc(sizeof(struct log_control))) == NULL)
		error(1, 0, "Failed to allocate memory");
	MainLog->flags = OUT_STDERR | (~FILTER_INFO & 0b1111);
	MainLog->identity = NULL;
	MainLog->files = NULL;
	atexit(closeMyLog);
}

// Adds file as output file
struct log_file *addFileToLog(const char *path)
{
	if (!(MainLog->flags & OUT_FILE))
		error(1, 0, "Output to file was not initialized");
	struct log_file *newFile = (struct log_file *) malloc(sizeof(struct log_file));
	if (newFile == NULL)
		error(1, 0, "Failed to allocate memory");
	newFile->next = MainLog->files;
	MainLog->files = newFile;
	if (!(newFile->f = fopen(path, "a")))
		error(1, 0, "Failed to open file");

	return newFile;
}

// Starts new log with
void startMyLog(int flags,int filters, const char *identity)
{
	if (flags == 0)
		error(1, 0, "Must have atleast one output");

	if(MainLog)
		error(1, 0, "Please start only one log per session");

	if ((MainLog = (struct log_control *) malloc(sizeof(struct log_control))) == NULL)
		error(1, 0, "Failed to allocate memory");

	// Stores flags and filters
	// Filters are stored inverted, so after & operation with level result is
	// non-zero value if this level is allowed to be logged
	MainLog->flags = flags | (~filters & 0b1111); 
	
	if (!identity)
	{
		MainLog->identity = NULL;
	}
	else
	{
		MainLog->identity = (char *) malloc(strlen(identity) + 1);
		strcpy(MainLog->identity, identity);
	}
	MainLog->files = NULL;

#ifdef  __linux__
	if (OUT_SYSLOG & flags)
		openlog(identity, 0, LOG_USER);
#endif

	// If flag OUT_STDERR is set then adds stderr to ouput
	if (OUT_STDERR & flags)
	{
		struct log_file *logerr = (struct log_file *) malloc(sizeof(struct log_file));
		if (logerr == NULL)
			error(1, 0, "Failed to allocate memory");
		logerr->next = NULL;
		logerr->f = stderr;
		MainLog->files = logerr;
	}

	atexit(closeMyLog);
}

// Counts digits of number x
int numberOfDigits(int x)
{
	int c = 0;
	while (x > 0)
	{
		c++;
		x /= 10;
	}
	return c;
}

void logMessage(int level, const char *filename, int line, const char *msg, ...)
{
	if (MainLog == NULL)
		startDefaultLog();

	if ((MainLog->flags & (OUT_FILE | OUT_STDERR)) && (level & MainLog->flags))
	{
		const char *lvlStr;
		if ((lvlStr = myLvlToString(level)) == NULL)
			error(1, 0, "Wrong log level");
		
		va_list argptr;
		va_start(argptr, msg); 
		
		if (level == DEBUG)
		{
			// Creates format string from message and logging information
			size_t lengthOfFormat;
			if (!MainLog->identity)
				lengthOfFormat = strlen(filename) + strlen(lvlStr) + numberOfDigits(line) + strlen(msg) + 5;
			else
				lengthOfFormat = strlen(filename) + strlen(lvlStr) + strlen(MainLog->identity) + numberOfDigits(line) + strlen(msg) + 4;
			char format[lengthOfFormat];
			if (!MainLog->identity)
				sprintf(format, "%s:%s:%d: %s\n", lvlStr, filename, line, msg);
			else
				sprintf(format, "%s:%s:%s:%d: %s\n", MainLog->identity, lvlStr, filename, line, msg);

			// Prints message to all adde files
			struct log_file *current = MainLog->files;
			while (current != NULL)
			{
				vfprintf(current->f, format, argptr);
				current = current->next;
			}
		}
		else
		{
			// Creates format string from message and logging information
			size_t lengthOfFormat;
			if (!MainLog->identity)
				lengthOfFormat = strlen(lvlStr) + strlen(msg) + 5;
			else
				lengthOfFormat = strlen(lvlStr) + strlen(MainLog->identity) + strlen(msg) + 5;
			char format[lengthOfFormat];
			if (!MainLog->identity)
				sprintf(format, "%s: %s\n", lvlStr, msg);
			else
				sprintf(format, "%s:%s: %s\n", MainLog->identity, lvlStr, msg);

			// Prints message to all adde files
			struct log_file *current = MainLog->files;
			while (current != NULL)
			{
				vfprintf(current->f, format, argptr);
				current = current->next;
			}
		}

		va_end(argptr);
	}
}

#ifdef __linux__
void mySyslog(int logLvl, const char *filename, int line, const char *msg, ...)
{
	if (MainLog == NULL)
		startDefaultLog();

	if (MainLog->flags & OUT_SYSLOG)
	{
		int syslogLvl;
		if ((syslogLvl = myLvlToSyslog(logLvl)) == -1)
			error(1, 0, "Wrong log level");

		va_list argptr;
		va_start(argptr, msg);

		if (logLvl == LOG_DEBUG)
		{
			size_t lengthOfFormat;
			lengthOfFormat = strlen(filename) + numberOfDigits(line) + strlen(msg) + 6;
			char format[lengthOfFormat];
			sprintf(format, "%s:%d: %s\n", filename, line, msg);
			vsyslog(syslogLvl, format, argptr);
		}
		else
		{
			vsyslog(syslogLvl, msg, argptr);
		}

		va_end(argptr);
	}
}

#else
void mySyslog(int logLvl, const char *filename, int line, const char *msg, ...) {
    (void) logLvl;
    (void) filename;
    (void) line;
    (void) msg;
}

#endif