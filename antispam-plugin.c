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
#include "ostream.h"
#include "imap-search.h"

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

static bool mailbox_in_list(struct mail_storage *storage, struct mailbox *box,
			    char **list)
{
	if (!list)
		return FALSE;

	while (*list) {
		if (mailbox_equals(box, storage, *list))
			return TRUE;
		list++;
	}

	return FALSE;
}

bool mailbox_is_spam(struct mail_storage *storage, struct mailbox *box)
{
	return mailbox_in_list(storage, box, spam_folders);
}

bool mailbox_is_trash(struct mail_storage *storage, struct mailbox *box)
{
	return mailbox_in_list(storage, box, trash_folders);
}

void antispam_init(void)
{
	char *tmp, **iter;

	debug("antispam plugin intialising\n");

	global_pool = pool_alloconly_create("antispam-pool", 1024);

	tmp = getenv("ANTISPAM_TRASH");
	if (tmp)
		trash_folders = p_strsplit(global_pool, tmp, ";");

	if (trash_folders) {
		iter = trash_folders;
		while (*iter) {
			debug("antispam: \"%s\" is trash folder\n", *iter);
			iter++;
		}
	} else
		debug("antispam: no trash folders\n");

	tmp = getenv("ANTISPAM_SPAM");
	if (tmp)
		spam_folders = p_strsplit(global_pool, tmp, ";");

	if (spam_folders) {
		iter = spam_folders;
		while (*iter) {
			debug("antispam: \"%s\" is spam folder\n", *iter);
			iter++;
		}
	} else
		debug("antispam: no spam folders\n");

	backend_init(global_pool);

	antispam_next_hook_mail_storage_created = hook_mail_storage_created;
	hook_mail_storage_created = antispam_mail_storage_created;
}

void antispam_deinit(void)
{
	hook_mail_storage_created = antispam_next_hook_mail_storage_created;
	backend_exit();
	mempool_unref(&global_pool);
}

/* put dovecot version we built against into plugin for checking */
const char *antispam_version = PACKAGE_VERSION;
