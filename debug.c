#define _BSD_SOURCE
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include "antispam-plugin.h"

static void _debug(const char *format, va_list ap)
{
	const char *fmt;

	t_push();

	fmt = t_strconcat(stringify(PLUGINNAME), ": ", format, NULL);

#if defined(DEBUG_SYSLOG)
	vsyslog(LOG_DEBUG, fmt, ap);
#elif defined(DEBUG_STDERR)
	vfprintf(stderr, fmt, ap);
	fflush(stderr);
#else
#error no logging method
#endif
	t_pop();
}

void debug(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	_debug(fmt, args);
	va_end(args);
}
