#ifndef _ANTISPAM_PLUGIN_H
#define _ANTISPAM_PLUGIN_H

#include <unistd.h>  
#include "lib.h"
#include "mempool.h"

struct strlist {
	struct strlist *next;
	const char *str;
};

#ifdef BACKEND_WANT_SIGNATURE
/*
 * Call backend giving
 *  - pool: dovecot memory pool, will be freed afterwards
 *  - spam: whether mail comes from spam folder or not
 *  - sigs: signatures, next == NULL terminates list
 *  - 
 */
bool backend(pool_t pool, bool spam, struct strlist *sigs);
#elif CONFIG_PLUGIN_WANT_MAIL
#error TODO: no support for pristine training yet
#else
#error BUILD SYSTEM ERROR
#endif

void backend_init(pool_t pool);
void backend_exit(void);

#ifdef CONFIG_DEBUG
void debug(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
#else
static void debug(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
static inline void debug(const char *fmt, ...)
{
}
#endif

#endif /* _ANTISPAM_PLUGIN_H */
