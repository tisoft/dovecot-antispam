#!/bin/sh

if head=`git rev-parse --verify HEAD 2>/dev/null`; then
	git update-index --refresh --unmerged > /dev/null
	printf "#define ANTISPAM_GIT_VERSION \"git %.8s" "$head"
	if git diff-index --name-only HEAD | read dummy ; then
		printf ", dirty"
	fi
	echo '"'
else
	echo '#define ANTISPAM_GIT_VERSION "unknown"'
fi
