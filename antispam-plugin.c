/*
 * antispam plugin for dovecot
 *
 * Copyright (C) 2004-2007  Johannes Berg <johannes@sipsolutions.net>
 *                    2006  Frank Cusack
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 * based on the original framework http://www.dovecot.org/patches/1.0/copy_plugin.c
 *
 * Please see http://johannes.sipsolutions.net/wiki/Projects/dovecot-dspam-integration
 * for more information on this code.
 *
 * Install the plugin in the usual dovecot module location.
 */

#include <stdlib.h>

/* dovecot headers we need */
#include "lib.h"
#include "str.h"
#include "client.h"
#include "mail-storage-private.h"


/* defined by imap, pop3, lda */
extern void (*hook_mail_storage_created)(struct mail_storage *storage);

/* internal stuff we need */
#include "antispam-plugin.h"

static pool_t global_pool;
static char **trash_folders = NULL;
static char *default_spam_folders[] = {
	"SPAM",
	NULL
};
static char **spam_folders = default_spam_folders;
static char **unsure_folders = NULL;
bool antispam_can_append_to_spam = FALSE;
static char **spam_keywords = NULL;

bool need_keyword_hook;
bool need_folder_hook;


static bool mailbox_in_list(struct mailbox *box, char **list)
{
	if (!list)
		return FALSE;

	while (*list) {
		if (mailbox_equals(box, box->storage, *list))
			return TRUE;
		list++;
	}

	return FALSE;
}

bool mailbox_is_spam(struct mailbox *box)
{
	debug_verbose("mailbox_is_spam(%s)\n", mailbox_get_name(box));
	return mailbox_in_list(box, spam_folders);
}

bool mailbox_is_trash(struct mailbox *box)
{
	debug_verbose("mailbox_is_trash(%s)\n", mailbox_get_name(box));
	return mailbox_in_list(box, trash_folders);
}

bool mailbox_is_unsure(struct mailbox *box)
{
	debug_verbose("mailbox_is_unsure(%s)\n", mailbox_get_name(box));
	return mailbox_in_list(box, unsure_folders);
}

bool keyword_is_spam(const char *keyword)
{
	char **k = spam_keywords;

	if (!spam_keywords)
		return FALSE;

	while (*k) {
		if (strcmp(*k, keyword) == 0)
			return TRUE;
		k++;
	}

	return FALSE;
}

const char *get_setting(const char *name)
{
	const char *env;

	t_push();
	env = t_strconcat(t_str_ucase(stringify(PLUGINNAME)),
			  "_",
			  name,
			  NULL);
	env = getenv(env);
	t_pop();

	return env;
}

#define __PLUGIN_FUNCTION(name, ioe) \
	name ## _plugin_ ## ioe
#define _PLUGIN_FUNCTION(name, ioe) \
	__PLUGIN_FUNCTION(name, ioe)
#define PLUGIN_FUNCTION(ioe)	\
	_PLUGIN_FUNCTION(PLUGINNAME, ioe)

void PLUGIN_FUNCTION(init)(void)
{
	const char *tmp;
	char * const *iter;
	int spam_folder_count = 0;

	debug("plugin initialising\n");

	global_pool = pool_alloconly_create("antispam-pool", 1024);

	tmp = get_setting("TRASH");
	if (tmp)
		trash_folders = p_strsplit(global_pool, tmp, ";");

	if (trash_folders) {
		iter = trash_folders;
		while (*iter) {
			debug("\"%s\" is trash folder\n", *iter);
			iter++;
		}
	} else
		debug("no trash folders\n");

	tmp = get_setting("SPAM");
	if (tmp)
		spam_folders = p_strsplit(global_pool, tmp, ";");

	if (spam_folders) {
		iter = spam_folders;
		while (*iter) {
			debug("\"%s\" is spam folder\n", *iter);
			iter++;
			spam_folder_count++;
		}
	} else
		debug("no spam folders\n");

	tmp = get_setting("UNSURE");
	if (tmp)
		unsure_folders = p_strsplit(global_pool, tmp, ";");

	if (unsure_folders) {
		iter = unsure_folders;
		while (*iter) {
			debug("\"%s\" is unsure folder\n", *iter);
			iter++;
		}
	} else
		debug("no unsure folders\n");

	tmp = get_setting("ALLOW_APPEND_TO_SPAM");
	if (tmp && strcasecmp(tmp, "yes") == 0) {
		antispam_can_append_to_spam = TRUE;
		debug("allowing APPEND to spam folders");
	}

	tmp = get_setting("SPAM_KEYWORDS");
	if (tmp)
		spam_keywords = p_strsplit(global_pool, tmp, ";");

	if (spam_keywords) {
		iter = spam_keywords;
		while (*iter) {
			debug("\"%s\" is spam keyword\n", *iter);
			iter++;
		}
	}

	/* set spam_folders to empty to only allow keywords */
	need_folder_hook = spam_folder_count > 0;
	need_keyword_hook = !!spam_keywords;

	backend_init(global_pool);

	antispam_next_hook_mail_storage_created = hook_mail_storage_created;
	hook_mail_storage_created = antispam_mail_storage_created;
}

void PLUGIN_FUNCTION(deinit)(void)
{
	hook_mail_storage_created = antispam_next_hook_mail_storage_created;
	backend_exit();
	mempool_unref(&global_pool);
}

/* put dovecot version we built against into plugin for checking */
const char *PLUGIN_FUNCTION(version) = PACKAGE_VERSION;
