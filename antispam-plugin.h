#ifndef _ANTISPAM_PLUGIN_H
#define _ANTISPAM_PLUGIN_H

#include "lib.h"
#include "str.h"
#include "client.h"
#include "ostream.h"
#include "imap-search.h"

#define __stringify_1(x)	#x
#define stringify(x)		__stringify_1(x)

#define __PLUGIN_FUNCTION(name, ioe) \
	name ## _plugin_ ## ioe
#define _PLUGIN_FUNCTION(name, ioe) \
	__PLUGIN_FUNCTION(name, ioe)
#define PLUGIN_FUNCTION(ioe)	\
	_PLUGIN_FUNCTION(PLUGINNAME, ioe)

extern uint32_t PLUGIN_FUNCTION(id);

struct antispam_transaction_context;

enum classification {
	CLASS_NOTSPAM,
	CLASS_SPAM,
};

void backend_init(pool_t pool);
void backend_exit(void);
/*
 * Handle mail; parameters are
 *  - t: transaction context
 *  - ast: transaction context from backend_start()
 *  - mail: the message
 *  - wanted: the wanted classification determined by the user
 */
int backend_handle_mail(struct mailbox_transaction_context *t,
			struct antispam_transaction_context *ast,
			struct mail *mail, enum classification wanted);
struct antispam_transaction_context *backend_start(struct mailbox *box);
void backend_rollback(struct antispam_transaction_context *ast);
int backend_commit(struct mailbox_transaction_context *ctx,
		   struct antispam_transaction_context *ast);

#ifdef CONFIG_DEBUG
void debug(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
#else
static void debug(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
static inline void debug(const char *fmt __attribute__((unused)), ...)
{
}
#endif

#if defined(CONFIG_DEBUG) && defined(CONFIG_DEBUG_VERBOSE)
/* bit of an ugly short-cut */
#define debug_verbose	debug
#else
static void debug_verbose(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
static inline void debug_verbose(const char *fmt __attribute__((unused)), ...)
{
}
#endif

void antispam_mail_storage_created(struct mail_storage *storage);
void (*antispam_next_hook_mail_storage_created)(struct mail_storage *storage);
bool mailbox_is_spam(struct mailbox *box);
bool mailbox_is_trash(struct mailbox *box);
bool mailbox_is_unsure(struct mailbox *box);
const char *get_setting(const char *name);
bool antispam_can_append_to_spam;
bool keyword_is_spam(const char *keyword);

extern bool need_keyword_hook;
extern bool need_folder_hook;

#if defined(CONFIG_DOVECOT_11)
#define __attr_unused__		ATTR_UNUSED
#define ME(err)			MAIL_ERROR_ ##err,
#define mempool_unref(x)	pool_unref(x)
#elif defined(CONFIG_DOVECOT_10)
#define ME(err)
#define str_array_length(x)	strarray_length(x)
#define mempool_unref(x)	pool_unref(*(x))
#else
#error "Building against this dovecot version is not supported"
#endif
        
#endif /* _ANTISPAM_PLUGIN_H */
