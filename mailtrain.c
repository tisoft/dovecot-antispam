/*
 * mailing backend for dovecot antispam plugin
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

#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "lib.h"
#include "dict.h"
#include "mail-storage-private.h"
#include "ostream.h"
#include "istream.h"

#include "antispam-plugin.h"

static const char *spamaddr = NULL;
static const char *hamaddr = NULL;
static const char *sendmail_binary = "/usr/sbin/sendmail";
static const char *tmpdir = "/tmp";

static int run_sendmail(int mailfd, bool from_spam)
{
	const char *dest = from_spam ? hamaddr : spamaddr;
	pid_t pid;
	int status;

	if (!dest)
		return -1;

	pid = fork();

	switch (pid) {
	case -1:
		return -1;
	case 0:
		dup2(mailfd, 0);
		close(1);
		close(2);
		execl(sendmail_binary, sendmail_binary, dest, NULL);
		_exit(1);
	default:
		if (waitpid(pid, &status, 0) == -1)
			return -1;
		if (!WIFEXITED(status))
			return -1;
		return WEXITSTATUS(status);
	}
}

struct antispam_transaction_context {
	char *tmpdir;
	int count;
	int tmplen;
};

struct antispam_transaction_context *backend_start(struct mailbox *box)
{
	struct antispam_transaction_context *ast;
	char *tmp;

	ast = i_new(struct antispam_transaction_context, 1);

	ast->count = 0;

	tmp = i_strconcat(tmpdir, "/antispam-mail-XXXXXX", NULL);

	ast->tmpdir = mkdtemp(tmp);
	if (!ast->tmpdir)
		i_free(tmp);
	else
		ast->tmplen = strlen(ast->tmpdir);

	return ast;
}

static int process_tmpdir(struct mailbox_transaction_context *ctx,
			  struct antispam_transaction_context *ast)
{
	int cnt = ast->count;
	int fd;
	char *buf;
	bool from_spam;

	t_push();

	buf = t_malloc(20 + ast->tmplen);

	while (cnt > 0) {
		cnt--;
		i_snprintf(buf, 20 + ast->tmplen - 1, "%s/%d",
			   ast->tmpdir, cnt);

		fd = open(buf, O_RDONLY);
		read(fd, &from_spam, sizeof(bool));

		if (run_sendmail(fd, from_spam)) {
			mail_storage_set_error(ctx->box->storage,
					       "failed to send mail");
			return -1;
		}
	}

	t_pop();

	return 0;
}

static void clear_tmpdir(struct antispam_transaction_context *ast)
{
	char *buf;

	t_push();

	buf = t_malloc(20 + ast->tmplen);

	while (ast->count > 0) {
		ast->count--;
		i_snprintf(buf, 20 + ast->tmplen - 1, "%s/%d",
			   ast->tmpdir, ast->count);
		unlink(buf);
	}
	rmdir(ast->tmpdir);

	t_pop();
}

void backend_rollback(struct antispam_transaction_context *ast)
{
	if (ast->tmpdir) {
		/* clear it! */
		clear_tmpdir(ast);
		i_free(ast->tmpdir);
	}

	i_free(ast);
}

int backend_commit(struct mailbox_transaction_context *ctx,
		   struct antispam_transaction_context *ast)
{
	int ret;

	if (!ast->tmpdir) {
		i_free(ast);
		return 0;
	}

	ret = process_tmpdir(ctx, ast);

	clear_tmpdir(ast);

	i_free(ast->tmpdir);
	i_free(ast);

	return ret;
}

int backend_handle_mail(struct mailbox_transaction_context *t,
			struct antispam_transaction_context *ast,
			struct mail *mail, bool from_spam)
{
	struct istream *mailstream;
	struct ostream *outstream;
	int ret;
	char *buf, *firstline;
	int fd;

	if (!ast->tmpdir) {
		mail_storage_set_error(t->box->storage,
				       "Failed to initialise temporary dir");
		return -1;
	}

	if (!hamaddr || !spamaddr) {
		mail_storage_set_error(t->box->storage,
				       "antispam plugin not configured");
		return -1;
	}

	mailstream = mail_get_stream(mail, NULL, NULL);
	if (!mailstream) {
		mail_storage_set_error(t->box->storage,
				       "Failed to get mail contents");
		return -1;
	}

	t_push();

	buf = t_malloc(20 + ast->tmplen);
	i_snprintf(buf, 20 + ast->tmplen - 1, "%s/%d", ast->tmpdir, ast->count);

	fd = creat(buf, 0600);
	if (fd < 0) {
		mail_storage_set_error(t->box->storage,
				       "Failed to create temporary file");
		ret = -1;
		goto out;
	}

	ast->count++;

	outstream = o_stream_create_file(fd, t->box->pool, 0, TRUE);
	if (!outstream) {
		ret = -1;
		mail_storage_set_error(t->box->storage,
				       "Failed to stream temporary file");
		goto out_close;
	}

	if (o_stream_send(outstream, &from_spam, sizeof(from_spam))
			!= sizeof(from_spam)) {
		ret = -1;
		mail_storage_set_error(t->box->storage,
				       "Failed to write marker to temp file");
		goto failed_to_copy;
	}

	firstline = i_stream_read_next_line(mailstream);

	if (strncmp(firstline, "From ", 5) != 0)
		if (o_stream_send_str(outstream, firstline) < 0) {
			ret = -1;
			mail_storage_set_error(t->box->storage,
					       "Failed to write line to temp");
			goto failed_to_copy;
		}

	if (o_stream_send_istream(outstream, mailstream) < 0) {
		ret = -1;
		mail_storage_set_error(t->box->storage,
				       "Failed to copy to temporary file");
		goto failed_to_copy;
	}

	ret = 0;

 failed_to_copy:
	o_stream_destroy(&outstream);
 out_close:
	close(fd);
 out:
	t_pop();

	return ret;
}

void backend_init(pool_t pool)
{
	char *tmp;

	tmp = getenv("ANTISPAM_MAIL_SPAM");
	if (tmp) {
		spamaddr = tmp;
		debug("antispam: mail backend spam address %s\n", tmp);
	}

	tmp = getenv("ANTISPAM_MAIL_NOTSPAM");
	if (tmp) {
		hamaddr = tmp;
		debug("antispam: mail backend not-spam address %s\n", tmp);
	}

	tmp = getenv("ANTISPAM_MAIL_SENDMAIL");
	if (tmp) {
		sendmail_binary = tmp;
		debug("antispam: mail backend sendmail %s\n", tmp);
	}

	tmp = getenv("ANTISPAM_MAIL_TMPDIR");
	if (tmp)
		tmpdir = tmp;
	debug("antispam: mail backend tmpdir %s\n", tmpdir);
}

void backend_exit(void)
{
}
