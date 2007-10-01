#ifndef _ANTISPAM_SIGNATURE_H
#define _ANTISPAM_SIGNATURE_H

#include "lib.h"
#include "client.h"

struct siglist {
	struct siglist *next;
	char *sig;
};

void signature_init(void);
int signature_extract(struct mailbox_transaction_context *t,
		      struct mail *mail, struct siglist **list);
void signature_list_free(struct siglist **list);

#endif /* _ANTISPAM_SIGNATURE_H */
