#format CPLUSPLUS
/*
  dspam plugin for dovecot

  Copyright (C) 2004-2006  Johannes Berg <johannes@sipsolutions.net>
                     2006  Frank Cusack

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License Version 2 as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA

  based on the original framework http://www.dovecot.org/patches/1.0/copy_plugin.c

  Please see http://johannes.sipsolutions.net/wiki/Projects/dovecot-dspam-integration
  for more information on this code.

  To compile:
  make "plugins" directory right beside "src" in the dovecot source tree,
  copy this into there and run

  cc -fPIC -shared -Wall \
    -I../src/ \
    -I../src/lib \
    -I.. \
    -I../src/lib-storage \
    -I../src/lib-mail \
    -I../src/lib-imap \
    -I../src/imap/ \
    -DHAVE_CONFIG_H \
    -DDSPAM=\"/path/to/dspam\" \
    dspam.c -o lib_dspam.so

  (if you leave out -DDSPAM=... then /usr/bin/dspam is taken as default)

  Install the plugin in the usual dovecot module location.
*/

/*
 * If you need to ignore a trash folder, define a trash folder
 * name as follows, or alternatively give -DIGNORE_TRASH_NAME=\"Trash\" on
 * the cc command line.
 */
/*#define IGNORE_TRASH_NAME "Trash"*/

#include "common.h"
#include "str.h"
#include "strfuncs.h"
#include "commands.h"
#include "imap-search.h"
#include "lib-storage/mail-storage.h"
#include "lib/mempool.h"
#include "mail-storage.h"
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#ifdef DEBUG
#include <syslog.h>
#endif

#define SIGHEADERLINE "X-DSPAM-Signature"
#define MAXSIGLEN 100

#ifndef DSPAM
#define DSPAM "/usr/bin/dspam"
#endif				/* DSPAM */

static int call_dspam(const char *signature, int is_spam)
{
	pid_t pid;
	int s;
	char class_arg[16 + 2];
	char sign_arg[MAXSIGLEN + 2];
	int pipes[2];

	s = snprintf(sign_arg, 101, "--signature=%s", signature);
	if (s > MAXSIGLEN || s <= 0)
		return -1;

	snprintf(class_arg, 17, "--class=%s", is_spam ? "spam" : "innocent");

	pipe(pipes);		/* for dspam stderr */

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid) {
		int status;
		/* well. dspam doesn't report an error if it has an error,
		   but instead only prints stuff to stderr. Usually, it
		   won't print anything, so we treat it having output as
		   an error condition */

		char buf[1024];
		int readsize;
		close(pipes[1]);

		do {
			readsize = read(pipes[0], buf, 1024);
			if (readsize < 0) {
				readsize = -1;
				if (errno == EINTR)
					readsize = -2;
			}
		} while (readsize == -2);

		if (readsize != 0) {
			close(pipes[0]);
			return -1;
		}

		waitpid(pid, &status, 0);
		if (!WIFEXITED(status)) {
			close(pipes[0]);
			return -1;
		}

		readsize = read(pipes[0], buf, 1024);
		if (readsize != 0) {
			close(pipes[0]);
			return -1;
		}

		close(pipes[0]);
		return WEXITSTATUS(status);
	} else {
		int fd = open("/dev/null", O_RDONLY);
		close(0);
		close(1);
		close(2);
		/* see above */
		close(pipes[0]);

		if (dup2(pipes[1], 2) != 2) {
			exit(1);
		}
		if (dup2(pipes[1], 1) != 1) {
			exit(1);
		}
		close(pipes[1]);

		if (dup2(fd, 0) != 0) {
			exit(1);
		}
		close(fd);

#ifdef DEBUG
		syslog(LOG_INFO, DSPAM " --source=error --stdout %s %s",
		       class_arg, sign_arg);
#endif
		execl(DSPAM, DSPAM, "--source=error", "--stdout", class_arg,
		      sign_arg, NULL);
		exit(127);	/* fall through if dspam can't be found */
		return -1;	/* never executed */
	}
}

struct dspam_signature_list {
	struct dspam_signature_list *next;
	char *sig;
};
typedef struct dspam_signature_list *siglist_t;

static siglist_t list_append(pool_t pool, siglist_t * list)
{
	siglist_t l = *list;
	siglist_t p = NULL;
	siglist_t n;

	while (l != NULL) {
		p = l;
		l = l->next;
	}
	n = p_malloc(pool, sizeof(struct dspam_signature_list));
	n->next = NULL;
	n->sig = NULL;
	if (p == NULL) {
		*list = n;
	} else {
		p->next = n;
	}
	return n;
}

static int
fetch_and_copy_reclassified(struct mailbox_transaction_context *t,
			    struct mailbox *srcbox,
			    struct mail_search_arg *search_args,
			    int is_spam, int *enh_error)
{
	struct mail_search_context *search_ctx;
	struct mailbox_transaction_context *src_trans;
	struct mail_keywords *keywords;
	const char *const *keywords_list;
	struct mail *mail;
	int ret;

	const char *signature;
	struct dspam_signature_list *siglist = NULL;
	pool_t listpool = pool_alloconly_create("dspam-siglist-pool", 1024);

	*enh_error = 0;

	src_trans = mailbox_transaction_begin(srcbox, 0);
	search_ctx = mailbox_search_init(src_trans, NULL, search_args, NULL);

	mail = mail_alloc(src_trans, MAIL_FETCH_STREAM_HEADER |
			  MAIL_FETCH_STREAM_BODY, NULL);
	ret = 1;
	while (mailbox_search_next(search_ctx, mail) > 0 && ret > 0) {
		if (mail->expunged) {
			ret = 0;
			break;
		}

		signature = mail_get_first_header(mail, SIGHEADERLINE);
		if (is_empty_str(signature)) {
			ret = -1;
			*enh_error = -2;
			break;
		}
		list_append(listpool, &siglist)->sig =
		    p_strdup(listpool, signature);

		keywords_list = mail_get_keywords(mail);
		keywords = strarray_length(keywords_list) == 0 ? NULL :
		    mailbox_keywords_create(t, keywords_list);
		if (mailbox_copy(t, mail, mail_get_flags(mail),
				 keywords, NULL) < 0)
			ret = -1;
		mailbox_keywords_free(t, &keywords);
	}
	mail_free(&mail);

	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;

	/* got all signatures now, walk them passing to dspam */
	while (siglist) {
		if ((*enh_error = call_dspam(siglist->sig, is_spam))) {
			ret = -1;
			break;
		}
		siglist = siglist->next;
	}

	pool_unref(listpool);

	if (*enh_error) {
		mailbox_transaction_rollback(&src_trans);
	} else {
		if (mailbox_transaction_commit(&src_trans, 0) < 0)
			ret = -1;
	}

	return ret;
}

static bool cmd_append_spam_plugin(struct client_command_context *cmd)
{
	const char *mailbox;
	struct mail_storage *storage;
	struct mailbox *box;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	storage = client_find_storage(cmd, &mailbox);
	if (storage == NULL)
		return FALSE;
	/* TODO: is this really the best way to handle this? maybe more logic could be provided */
	box =
	    mailbox_open(storage, mailbox, NULL,
			 MAILBOX_OPEN_FAST | MAILBOX_OPEN_KEEP_RECENT);
	if (box != NULL) {

		if (mailbox_equals(box, storage, "SPAM")) {
			mailbox_close(&box);
			return cmd_sync(cmd, 0, 0,
					"NO Cannot APPEND to SPAM box, sorry.");
		}

		mailbox_close(&box);
	}

	return cmd_append(cmd);
}

static bool cmd_copy_spam_plugin(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mail_storage *storage;
	struct mailbox *destbox;
	struct mailbox_transaction_context *t;
	struct mail_search_arg *search_arg;
	const char *messageset, *mailbox;
	enum mailbox_sync_flags sync_flags = 0;
	int ret;
	int spam_folder = 0;
	int enh_error = 0, is_spam;
#ifdef IGNORE_TRASH_NAME
	int is_trash;
	int trash_folder = 0;
#endif
	struct mailbox *box;

	/* <message set> <mailbox> */
	if (!client_read_string_args(cmd, 2, &messageset, &mailbox))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	storage = client_find_storage(cmd, &mailbox);
	if (storage == NULL)
		return FALSE;
	box =
	    mailbox_open(storage, mailbox, NULL,
			 MAILBOX_OPEN_FAST | MAILBOX_OPEN_KEEP_RECENT);
	if (!box) {
		client_send_storage_error(cmd, storage);
		return TRUE;
	}

	is_spam = mailbox_equals(box, storage, "SPAM");
	spam_folder = is_spam
	    || mailbox_equals(cmd->client->mailbox, storage, "SPAM");
#ifdef IGNORE_TRASH_NAME
	is_trash = mailbox_equals(box, storage, IGNORE_TRASH_NAME);
	trash_folder = is_trash
	    || mailbox_equals(cmd->client->mailbox, storage, IGNORE_TRASH_NAME);
#endif

	mailbox_close(&box);

	/* only act on spam */
	if (!spam_folder)
		return cmd_copy(cmd);
#ifdef IGNORE_TRASH_NAME
	/* ignore any mail going into or out of trash
	 * This means users can circumvent re-classification
	 * by moving into trash and then out again...
	 * All in all, it may be a better idea to not use
	 * a Trash folder at all :) */
	if (trash_folder)
		return cmd_copy(cmd);
#endif

	/* otherwise, do (almost) everything the copy would have done */
	/* open the destination mailbox */
	if (!client_verify_mailbox_name(cmd, mailbox, TRUE, FALSE))
		return TRUE;

	search_arg = imap_search_get_arg(cmd, messageset, cmd->uid);
	if (search_arg == NULL)
		return TRUE;

	storage = client_find_storage(cmd, &mailbox);
	if (storage == NULL)
		return TRUE;

	if (mailbox_equals(client->mailbox, storage, mailbox))
		destbox = client->mailbox;
	else {
		destbox = mailbox_open(storage, mailbox, NULL,
				       MAILBOX_OPEN_FAST |
				       MAILBOX_OPEN_KEEP_RECENT);
		if (destbox == NULL) {
			client_send_storage_error(cmd, storage);
			return TRUE;
		}
	}

	t = mailbox_transaction_begin(destbox,
				      MAILBOX_TRANSACTION_FLAG_EXTERNAL);
	ret =
	    fetch_and_copy_reclassified(t, client->mailbox, search_arg, is_spam,
					&enh_error);

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
		switch (enh_error) {
		case -2:
			return cmd_sync(cmd, 0, 0,
					"NO Some messages did not have "
					SIGHEADERLINE " header line");
			break;
		case -3:
			return cmd_sync(cmd, 0, 0, "NO Failed to call dspam");
			break;
		case 0:
			client_send_storage_error(cmd, storage);
			return TRUE;
			break;
		default:
			return cmd_sync(cmd, 0, 0, "NO dspam failed");
			break;
		}
	}

	return TRUE;
}

void dspam_init(void)
{
	command_unregister("COPY");
	command_unregister("APPEND");
	command_unregister("UID COPY");
	/* i_strdup() here is a kludge to avoid crashing in commands_deinit()
	 * since modules are unloaded before it's called, this "COPY" string
	 * would otherwise point to nonexisting memory. */
	command_register(i_strdup("COPY"), cmd_copy_spam_plugin);
	command_register(i_strdup("UID COPY"), cmd_copy_spam_plugin);
	command_register(i_strdup("APPEND"), cmd_append_spam_plugin);
}

void dspam_deinit(void)
{
}
