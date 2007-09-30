#ifndef _ANTISPAM_PLUGIN_H
#define _ANTISPAM_PLUGIN_H

#include <unistd.h>  
#include "mempool.h"

struct signature {
	struct signature *next;
	char *sig;
};

#ifdef CONFIG_PLUGIN_WANT_SIGNATURE
/*
 * Call backend giving
 *  - pool: dovecot memory pool, will be freed afterwards
 *  - spam: whether mail comes from spam folder or not
 *  - sigs: signatures, next == NULL terminates list
 *  - 
 */
int backend(pool_t pool, int spam, struct signature *sigs);
#elif CONFIG_PLUGIN_WANT_MAIL
#error TODO: no support for pristine training yet
#else
#error BUILD SYSTEM ERROR
#endif

#ifdef CONFIG_DEBUG
void debug(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
#else
static inline void
debug(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)))
{
}
#endif

#endif /* _ANTISPAM_PLUGIN_H */
