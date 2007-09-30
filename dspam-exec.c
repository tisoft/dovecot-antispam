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

#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "lib.h"

#include "plugin.h"
#include "api-compat.h"

static const char *dspam_binary = "/usr/bin/dspam";
static char **extra_args = NULL;
static int extra_args_num = 0;

#define FIXED_ARGS_NUM 6

static int call_dspam(pool_t pool, const char *signature, bool is_spam)
{
	pid_t pid;
	const char *class_arg;
	const char *sign_arg;
	int pipes[2];

	sign_arg = t_strconcat("--signature=", signature, NULL);
	if (is_spam)
		class_arg = t_strconcat("--class=", "spam", NULL);
	else
		class_arg = t_strconcat("--class=", "innocent", NULL);

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
		char **argv;
		int sz = sizeof(char *) * (FIXED_ARGS_NUM + extra_args_num);
		int i;

		argv = p_malloc(pool, sz);
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
		argv[2] = "--stdout";
		argv[3] = (char *)class_arg;
		argv[4] = (char *)sign_arg;

		debug("antispam: %s --source=error --stdout %s %s ...",
		      dspam_binary, class_arg, sign_arg);

		for (i = 0; i < extra_args_num; i++)
			argv[i + 5] = (char *)extra_args[i];

		execv(dspam_binary, argv);
		/* fall through if dspam can't be found */
		exit(127);
		/* not reached */
		return -1;
	}
}

bool backend(pool_t pool, bool spam, struct strlist *sigs)
{
	int ret;

	/* got all signatures now, walk them passing to dspam */
	while (sigs) {
		ret = call_dspam(pool, sigs->str, spam);
		if (ret)
			return FALSE;
		sigs = sigs->next;
	}

	return TRUE;
}

void backend_init(pool_t pool)
{
	char *tmp;
	int i;

	tmp = getenv("ANTISPAM_DSPAM_BINARY");
	if (tmp) {
		dspam_binary = tmp;
		debug("dspam binary set to %s\n", tmp);
	}

	tmp = getenv("ANTISPAM_DSPAM_ARGS");
	if (tmp) {
		extra_args = p_strsplit(pool, tmp, ";");
		extra_args_num = str_array_length(
					(const char *const *)extra_args);
		for (i = 0; i < extra_args_num; i++)
			debug("antispam: dspam extra arg %s\n",
			      extra_args[i]);
	}
}

void backend_exit(void)
{
}
