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

static const char *dspam_binary = "/usr/bin/dspam";

static bool call_dspam(pool_t pool, const char *signature, bool is_spam)
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

		debug("antispam: %s --source=error --stdout %s %s",
		       dspam_binary, class_arg, sign_arg);
		execl(dspam_binary, dspam_binary,
		      "--source=error", "--stdout", class_arg,
		      sign_arg, NULL);
		exit(127);	/* fall through if dspam can't be found */
		return -1;	/* never executed */
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

	tmp = getenv("ANTISPAM_DSPAM_BINARY");
	if (tmp) {
		dspam_binary = tmp;
		debug("dspam binary set to %s\n", tmp);
	}
}

void backend_exit(void)
{
}
