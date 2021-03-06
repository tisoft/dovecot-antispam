/*
 * dspam backend for dovecot antispam plugin
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
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "lib.h"
#include "mail-storage-private.h"

#include "antispam-plugin.h"
#include "signature.h"

static const char *dspam_binary = "/usr/bin/dspam";
static const char *dspam_result_header = NULL;
static char **dspam_result_bl = NULL;
static int dspam_result_bl_num = 0;
static char **extra_args = NULL;
static int extra_args_num = 0;

static int call_dspam(const char *signature, enum classification wanted)
{
	pid_t pid;
	const char *class_arg;
	const char *sign_arg;
	int pipes[2];

	sign_arg = t_strconcat("--signature=", signature, NULL);
	switch (wanted) {
	case CLASS_NOTSPAM:
		class_arg = t_strconcat("--class=", "innocent", NULL);
		break;
	case CLASS_SPAM:
		class_arg = t_strconcat("--class=", "spam", NULL);
		break;
	}

	/*
	 * For dspam stderr; dspam seems to not always exit with a
	 * non-zero exit code on errors so we treat it as an error
	 * if it logged anything to stderr.
	 */
	pipe(pipes);

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid) {
		int status;
		char buf[1025];
		int readsize;
		bool error = FALSE;

		close(pipes[1]);

		do {
			readsize = read(pipes[0], buf, sizeof(buf) - 1);
			if (readsize < 0) {
				readsize = -1;
				if (errno == EINTR)
					readsize = -2;
			}

			/*
			 * readsize > 0 means that we read a message from
			 * dspam, -1 means we failed to read for some odd
			 * reason
			 */
			if (readsize > 0 || readsize == -1)
				error = TRUE;

			if (readsize > 0) {
				buf[readsize] = '\0';
				debug("dspam error: %s\n", buf);
			}
		} while (readsize == -2 || readsize > 0);

		/*
		 * Wait for dspam, should return instantly since we've
		 * already waited above (waiting for stderr to close)
		 */
		waitpid(pid, &status, 0);
		if (!WIFEXITED(status))
			error = TRUE;

		close(pipes[0]);
		if (error)
			return 1;
		return WEXITSTATUS(status);
	} else {
		int fd = open("/dev/null", O_RDONLY);
		char **argv;
		/* 4 fixed args, extra args, terminating NULL */
		int sz = sizeof(char *) * (4 + extra_args_num + 1);
		int i;

		argv = i_malloc(sz);
		memset(argv, 0, sz);

		close(0);
		close(1);
		close(2);
		/* see above */
		close(pipes[0]);

		if (dup2(pipes[1], 2) != 2)
			exit(1);
		if (dup2(pipes[1], 1) != 1)
			exit(1);
		close(pipes[1]);

		if (dup2(fd, 0) != 0)
			exit(1);
		close(fd);

		argv[0] = (char *)dspam_binary;
		argv[1] = "--source=error";
		argv[2] = (char *)class_arg;
		argv[3] = (char *)sign_arg;

		for (i = 0; i < extra_args_num; i++)
			argv[i + 4] = (char *)extra_args[i];

#ifdef DEBUG_SYSLOG
		/*
		 * not good with stderr debuggin since we then write to
		 * stderr which our parent takes as a bug
		 */
		debugv(argv);
#endif

		execv(dspam_binary, argv);
		debug("executing %s failed: %d (uid=%d, gid=%d)",
			dspam_binary, errno, getuid(), getgid());
		/* fall through if dspam can't be found */
		exit(127);
		/* not reached */
		return -1;
	}
}

struct antispam_transaction_context {
	struct siglist *siglist;
};

struct antispam_transaction_context *
backend_start(struct mailbox *box __attr_unused__)
{
	struct antispam_transaction_context *ast;

	ast = i_new(struct antispam_transaction_context, 1);
	ast->siglist = NULL;
	return ast;
}

void backend_rollback(struct antispam_transaction_context *ast)
{
	signature_list_free(&ast->siglist);
	i_free(ast);
}

int backend_commit(struct mailbox_transaction_context *ctx,
		   struct antispam_transaction_context *ast)
{
	struct siglist *item = ast->siglist;
	int ret = 0;

	while (item) {
		if (call_dspam(item->sig, item->wanted)) {
			ret = -1;
			mail_storage_set_error(ctx->box->storage,
					       ME(NOTPOSSIBLE)
					       "Failed to call dspam");
			break;
		}
		item = item->next;
	}

	signature_list_free(&ast->siglist);
	i_free(ast);
	return ret;
}

int backend_handle_mail(struct mailbox_transaction_context *t,
			struct antispam_transaction_context *ast,
			struct mail *mail, enum classification want)
{
	const char *const *result = NULL;
	int i;

	/*
	 * Check for whitelisted classifications that should
	 * be ignored when moving a mail. eg. virus.
	 */
	if (dspam_result_header)
		result = get_mail_headers(mail, dspam_result_header);
	if (result && result[0]) {
		for (i = 0; i < dspam_result_bl_num; i++) {
			if (strcasecmp(result[0], dspam_result_bl[i]) == 0)
				return 0;
		}
	}

	return signature_extract_to_list(t, mail, &ast->siglist, want);
}

void backend_init(pool_t pool)
{
	const char *tmp;
	int i;

	tmp = get_setting("DSPAM_BINARY");
	if (tmp)
		dspam_binary = tmp;
	debug("dspam binary set to %s\n", dspam_binary);

	tmp = get_setting("DSPAM_RESULT_HEADER");
	if (tmp) {
		dspam_result_header = tmp;
		debug("dspam result set to %s\n", dspam_result_header);

		tmp = get_setting("DSPAM_RESULT_BLACKLIST");
		if (tmp) {
			dspam_result_bl = p_strsplit(pool, tmp, ";");
			dspam_result_bl_num = str_array_length(
					(const char *const *)dspam_result_bl);
			for (i = 0; i < dspam_result_bl_num; i++)
				debug("dspam result blacklist %s\n",
						dspam_result_bl[i]);
		}
	}

	tmp = get_setting("DSPAM_ARGS");
	if (tmp) {
		extra_args = p_strsplit(pool, tmp, ";");
		extra_args_num = str_array_length(
					(const char *const *)extra_args);
		for (i = 0; i < extra_args_num; i++)
			debug("dspam extra arg %s\n",
			      extra_args[i]);
	}

	signature_init();
}

void backend_exit(void)
{
}
