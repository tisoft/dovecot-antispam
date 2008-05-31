#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"

int main(int argc, char **argv)
{
	char *v = PACKAGE_STRING, *e;
	int maj = 0, min = 0;

	if (strncmp(v, "dovecot ", 8))
		return 1;

	/* skip "dovecot " */
	v += 8;

	maj = strtol(v, &e, 10);
	if (v == e)
		return 1;

	v = e + 1;

	min = strtol(v, &e, 10);
	if (v == e)
		return 1;

	printf("/* Auto-generated file, do not edit */\n\n");
	printf("#define DOVECOT_VERSION_CODE(maj, min)	((maj)<<8 | (min))\n\n");
	
	printf("#define DOVECOT_VERSION			0x%.2x%.2x\n", maj, min);
	printf("#define ANTISPAM_STORAGE		\"antispam-storage-%d.%d.c\"\n", maj, min);

	return 0;
}
