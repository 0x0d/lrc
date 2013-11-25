#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <ctype.h>
#include "logger.h"

static FILE *logfd;

extern int debugged;

int logger_init(const char *filename) {
	FILE *fd;

	if(filename) {
		if((fd = fopen(filename, "a"))) {
			logfd = fd;	
			return(1);
		}
	} else {
        logfd = stdout;
        return(1);
    }
    return(0);
}

void logger(int type, const char *fmt, ...) {

    va_list ap;
    time_t now;
    struct tm *current;

    time(&now);
    current = localtime(&now);

    if(type == DBG && !debugged) {
        return;
    }

    va_start(ap, fmt);
    switch(type) {
        case WARN:
            (void)fprintf(logfd, "[!] ");
            break;
        case FATAL:
            (void)fprintf(logfd, "[-] ");
            break;
    }
	(void)fprintf(logfd, "[%04d/%02d/%02d %02d:%02d:%02d] ",current->tm_year+1900, current->tm_mon+1, current->tm_mday, current->tm_hour, current->tm_min, current->tm_sec);
    if (fmt != NULL) {
        (void)vfprintf(logfd, fmt, ap);
	}
    (void)fprintf(logfd, "\n");
    fflush(logfd);
    va_end(ap);
}
