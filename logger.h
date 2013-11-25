#ifndef _LOGGER_H__
#define _LOGGER_H__

int logger_init(const char *);
void logger_warn(const char *, ...);
void logger_info(const char *, ...);
void logger_fatal(const char *, ...);

#endif
