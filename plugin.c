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
#include "client.h"
#include "ostream.h"
#include "imap-search.h"

/* internal stuff we need */
#include "plugin.h"

static pool_t global_pool;
static char **trash_folders = NULL;
static char *default_spam_folders[] = {
	"SPAM",
	NULL
};
static char **spam_folders = default_spam_folders;
#ifdef BACKEND_WANTS_SIGNATURE
static char *signature_hdr = "X-DSPAM-Signature";
#endif

static struct strlist *list_add(pool_t pool, struct strlist *list)
{
	struct strlist *n;

	n = p_malloc(pool, sizeof(struct strlist));
	n->next = list;
	n->str = NULL;

	return n;
}

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

static void client_send_sendalive_if_needed(struct client *client)
{
	time_t now, last_io;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	now = time(NULL);
	last_io = I_MAX(client->last_input, client->last_output);
	if (now - last_io > MAIL_STORAGE_STAYALIVE_SECS) {
		o_stream_send_str(client->output, "* OK Hang in there..\r\n");
		o_stream_flush(client->output);
		client->last_output = now;
	}
}

#define GENERIC_ERROR		-1
#define SIGNATURE_MISSING	-2
#define BACKEND_FAILURE		-3

/* mostly copied from cmd-copy.c (notes added where changed) */
/* MODIFIED: prototype to include "src_spam" */
static int fetch_and_copy(struct client *client,
			  struct mailbox_transaction_context *t,
			  struct mail_search_arg *search_args,
			  bool src_spam)
{
	struct mail_search_context *search_ctx;
        struct mailbox_transaction_context *src_trans;
	struct mail_keywords *keywords;
	const char *const *keywords_list;
	struct mail *mail;
	unsigned int copy_count = 0;
	int ret;
	/* MODIFIED: new variables */
	pool_t pool = pool_alloconly_create("antispam-copy-pool", 1024);
#ifdef BACKEND_WANTS_SIGNATURE
	const char *signature;
	struct strlist *siglist = NULL;
#else
#error Not implemented
#endif

	src_trans = mailbox_transaction_begin(client->mailbox, 0);
	search_ctx = mailbox_search_init(src_trans, NULL, search_args, NULL);

	mail = mail_alloc(src_trans, MAIL_FETCH_STREAM_HEADER |
			  MAIL_FETCH_STREAM_BODY, NULL);
	ret = 1;
	while (mailbox_search_next(search_ctx, mail) > 0 && ret > 0) {
		if (mail->expunged) {
			ret = 0;
			break;
		}

		if ((++copy_count % COPY_CHECK_INTERVAL) == 0)
			client_send_sendalive_if_needed(client);

		/* MODIFIED: keep track of mail as we copy */
#ifdef BACKEND_WANTS_SIGNATURE
		signature = mail_get_first_header(mail, signature_hdr);
		if (is_empty_str(signature)) {
			ret = SIGNATURE_MISSING;
			break;
		}
		siglist = list_add(pool, siglist);
		siglist->str = p_strdup(pool, signature);
#else
#error Not implemented
#endif

		keywords_list = mail_get_keywords(mail);
		keywords = strarray_length(keywords_list) == 0 ? NULL :
			mailbox_keywords_create(t, keywords_list);
		if (mailbox_copy(t, mail, mail_get_flags(mail),
				 keywords, NULL) < 0)
			ret = mail->expunged ? 0 : -1;
		mailbox_keywords_free(t, &keywords);
	}
	mail_free(&mail);

	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;

	if (mailbox_transaction_commit(&src_trans, 0) < 0)
		ret = -1;

	/* MODIFIED: pass to backend */
#ifdef BACKEND_WANTS_SIGNATURE
	/* got all signatures now, pass them to backend if no errors */
	if (ret == 0) {
		ret = backend(pool, src_spam, siglist);
		if (ret)
			ret = BACKEND_FAILURE;
	}
#else
#error Not implemented
#endif
	/* MODIFIED: kill pool */
	pool_unref(pool);

	return ret;
}


/* mostly copied from cmd-copy.c (notes added where changed) */
static bool cmd_copy_antispam(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mail_storage *storage;
	struct mailbox *destbox;
	struct mailbox_transaction_context *t;
        struct mail_search_arg *search_arg;
	const char *messageset, *mailbox;
        enum mailbox_sync_flags sync_flags = 0;
	int ret;
	/* MODIFIED: added variables */
	bool dst_spam, src_spam;

	/* <message set> <mailbox> */
	if (!client_read_string_args(cmd, 2, &messageset, &mailbox))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	/* open the destination mailbox */
	if (!client_verify_mailbox_name(cmd, mailbox, TRUE, FALSE))
		return TRUE;

	search_arg = imap_search_get_arg(cmd, messageset, cmd->uid);
	if (search_arg == NULL)
		return TRUE;

	storage = client_find_storage(cmd, &mailbox);
	if (storage == NULL)
		return TRUE;

	if (mailbox_equals(client->mailbox, storage, mailbox)) {
		destbox = client->mailbox;
		/* MODIFIED: don't try to reclassify on copy within folder */
		return cmd_copy(cmd);
	} else {
		destbox = mailbox_open(storage, mailbox, NULL,
				       MAILBOX_OPEN_SAVEONLY |
				       MAILBOX_OPEN_FAST |
				       MAILBOX_OPEN_KEEP_RECENT);
		if (destbox == NULL) {
			client_send_storage_error(cmd, storage);
			return TRUE;
		}
	}

	/* MODIFIED: Trash detection */
	if (mailbox_in_list(storage, client->mailbox, trash_folders) ||
	    mailbox_in_list(storage, destbox, trash_folders)) {
		mailbox_close(&destbox);
		return cmd_copy(cmd);
	}

	/* MODIFIED: from/to-SPAM detection */
	src_spam = mailbox_in_list(storage, client->mailbox, spam_folders);
	dst_spam = mailbox_in_list(storage, destbox, spam_folders);
	/*
	 * "both spam" can happen with multiple spam folders,
	 * "none spam" is the common case where spam folders are not involved
	 */
	if ((src_spam && dst_spam) ||
	    (!src_spam && !dst_spam)) {
		mailbox_close(&destbox);
		return cmd_copy(cmd);
	}

	t = mailbox_transaction_begin(destbox,
				      MAILBOX_TRANSACTION_FLAG_EXTERNAL);
	ret = fetch_and_copy(client, t, search_arg, src_spam);

	if (ret <= 0)
		mailbox_transaction_rollback(&t);
	else {
		if (mailbox_transaction_commit(&t, 0) < 0)
			ret = -1;
	}

	if (destbox != client->mailbox) {
		sync_flags |= MAILBOX_SYNC_FLAG_FAST;
		mailbox_close(&destbox);
	}

	if (ret > 0)
		return cmd_sync(cmd, sync_flags, 0, "OK Copy completed.");
	else if (ret == 0) {
		/* some messages were expunged, sync them */
		return cmd_sync(cmd, 0, 0,
			"NO Some of the requested messages no longer exist.");
	} else {
		client_send_storage_error(cmd, storage);
		return TRUE;
	}
}


static bool cmd_append_antispam(struct client_command_context *cmd)
{
	const char *mailbox;
	struct mail_storage *storage;
	struct mailbox *box;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	storage = client_find_storage(cmd, &mailbox);
	if (!storage)
		return FALSE;

	box = mailbox_open(storage, mailbox, NULL,
			   MAILBOX_OPEN_FAST | MAILBOX_OPEN_KEEP_RECENT);
	if (box) {
		if (mailbox_in_list(storage, box, spam_folders)) {
			mailbox_close(&box);
			return cmd_sync(cmd, 0, 0,
					"NO Cannot APPEND to spam folder.");
		}

		mailbox_close(&box);
	}

	return cmd_append(cmd);
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

#ifdef BACKEND_WANTS_SIGNATURE
	tmp = getenv("ANTISPAM_SIGNATURE");
	if (tmp)
		signature_hdr = tmp;
	debug("antispam: signature header line is \"%s\"\n", signature_hdr);
#endif

	backend_init(global_pool);

	command_unregister("COPY");
	command_unregister("APPEND");
	command_unregister("UID COPY");
	/*
	 * i_strdup() here is a kludge to avoid crashing in commands_deinit()
	 * since modules are unloaded before it's called, this "COPY" string
	 * would otherwise point to nonexisting memory.
	 */
	command_register(i_strdup("COPY"), cmd_copy_antispam);
	command_register(i_strdup("UID COPY"), cmd_copy_antispam);
	command_register(i_strdup("APPEND"), cmd_append_antispam);
}

void antispam_deinit(void)
{
	backend_exit();
	pool_unref(global_pool);
}
