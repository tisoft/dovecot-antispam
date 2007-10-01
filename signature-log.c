/*
 * signature logging backend for dovecot antispam plugin
 *
 * Copyright (C) 2007       Johannes Berg <johannes@sipsolutions.net>
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
 */

/*
 * A training implementation must still be written, it needs, to be atomic,
 * use transactions to get a list of all values and delete them at the same
 * time, or use a temporary table that is copied from the original while the
 * original is emptied (again, atomically)
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "lib.h"
#include "dict.h"
#include "mail-storage-private.h"

#include "antispam-plugin.h"
#include "signature.h"

static const char *dict_uri = NULL;
static const char *dict_user = NULL;

struct antispam_transaction_context {
	struct dict *dict;
	struct dict_transaction_context *dict_ctx;
};

struct antispam_transaction_context *backend_start(struct mailbox *box)
{
	struct antispam_transaction_context *ast;

	ast = i_new(struct antispam_transaction_context, 1);

	ast->dict = dict_init(dict_uri, dict_user);

	/* see comment below */
//	if (ast->dict)
//		ast->dict_ctx = dict_transaction_begin(ast->dict);
	return ast;
}

void backend_rollback(struct antispam_transaction_context *ast)
{
	if (ast->dict) {
//		dict_transaction_rollback(ast->dict_ctx);
		dict_deinit(&ast->dict);
	}

	i_free(ast);
}

int backend_commit(struct mailbox_transaction_context *ctx,
		   struct antispam_transaction_context *ast)
{
	int ret = 0;

	if (ast->dict) {
		ret = 0;
//		ret = dict_transaction_commit(ast->dict_ctx);
		dict_deinit(&ast->dict);
	}
	i_free(ast);

	return ret;
}

int backend_handle_mail(struct mailbox_transaction_context *t,
			struct antispam_transaction_context *ast,
			struct mail *mail, enum classification wanted)
{
	const char *signature;
	int ret;
	int inc;

	if (!ast->dict) {
		mail_storage_set_error(t->box->storage,
				       "Failed to initialise dict connection");
		return -1;
	}

	signature = signature_extract(t, mail);

	switch (wanted) {
	case CLASS_SPAM:
		inc = 1;
		break;
	case CLASS_NOTSPAM:
		inc = -1;
		break;
	}

	/*
	 * We really should have a global transaction as implemented
	 * by the code that is commented out with C99 comments (//).
	 * However, this breaks because
	 * (1) sqlite cannot nest transactions
	 * (2) the dict proxy keeps only a single connection open
	 * (3) we here have a transaction per mailbox which makes two
	 *     when moving messages (we might be able to hack around
	 *     this but it's not trivial)
	 */
	ast->dict_ctx = dict_transaction_begin(ast->dict);
	signature = t_strconcat("priv/", signature, NULL);
	dict_atomic_inc(ast->dict_ctx, signature, inc);
	ret = dict_transaction_commit(ast->dict_ctx);
	if (ret)
		mail_storage_set_error(t->box->storage,
				       "Failed to count signature");

	return ret;
}

void backend_init(pool_t pool)
{
	char *tmp;

	tmp = getenv("ANTISPAM_SIGLOG_DICT_URI");
	if (tmp) {
		dict_uri = tmp;
		debug("antispam: signature logger dict URI set to %s\n", tmp);
	}

	tmp = getenv("ANTISPAM_SIGLOG_DICT_USER");
	if (tmp) {
		dict_user = tmp;
		debug("antispam: signature logger dict user set to %s\n", tmp);
	}

	signature_init();
}

void backend_exit(void)
{
}
