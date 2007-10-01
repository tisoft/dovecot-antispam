
#include <stdlib.h>
#include "antispam-plugin.h"
#include "signature.h"
#include "mail-storage-private.h"

static char *signature_hdr = "X-DSPAM-Signature";

void signature_init(void)
{
	char *tmp = getenv("ANTISPAM_SIGNATURE");
	if (tmp)
		signature_hdr = tmp;
	debug("antispam: signature header line is \"%s\"\n", signature_hdr);
}

int signature_extract(struct mailbox_transaction_context *t,
		      struct mail *mail, struct siglist **list)
{
	const char *signature;
	struct siglist *item;

	signature = mail_get_first_header(mail, signature_hdr);
	if (!signature || !signature[0]) {
		mail_storage_set_error(t->box->storage,
				       "antispam signature not found");
		return -1;
	}

	item = i_new(struct siglist, 1);
	item->next = *list;
	*list = item;
	item->sig = i_strdup(signature);
	return 0;
}

void signature_list_free(struct siglist **list)
{
	struct siglist *item, *next;

	i_assert(list);

	item = *list;

	while (item) {
		next = item->next;
		i_free(item->sig);
		i_free(item);
		item = next;
		if (item)
			next = item->next;
	}
}
