
#include <stdlib.h>
#include "antispam-plugin.h"
#include "signature.h"
#include "mail-storage-private.h"

const char *signature_hdr = "X-DSPAM-Signature";

void signature_init(void)
{
	const char *tmp = get_setting("SIGNATURE");
	if (tmp)
		signature_hdr = tmp;
	debug("signature header line is \"%s\"\n", signature_hdr);
}

int signature_extract_to_list(struct mailbox_transaction_context *t,
			      struct mail *mail, struct siglist **list,
			      enum classification wanted)
{
	const char *const *signatures;
	struct siglist *item;

#ifdef CONFIG_DOVECOT_11
	if (mail_get_headers(mail, signature_hdr, &signatures) < 0)
		signatures = NULL;
#else
	signatures = mail_get_headers(mail, signature_hdr);
#endif
	if (!signatures || !signatures[0]) {
		mail_storage_set_error(t->box->storage,
				       ME(NOTPOSSIBLE)
				       "antispam signature not found");
		return -1;
	}

	while (signatures[1])
		signatures++;

	item = i_new(struct siglist, 1);
	item->next = *list;
	item->wanted = wanted;
	item->sig = i_strdup(signatures[0]);

	*list = item;

	return 0;
}

const char *signature_extract(struct mailbox_transaction_context *t,
			      struct mail *mail)
{
	const char *const *signatures;

#ifdef CONFIG_DOVECOT_11
	if (mail_get_headers(mail, signature_hdr, &signatures) < 0)
		signatures = NULL;
#else
	signatures = mail_get_headers(mail, signature_hdr);
#endif
	if (!signatures || !signatures[0]) {
		mail_storage_set_error(t->box->storage,
				       ME(NOTPOSSIBLE)
				       "antispam signature not found");
		return NULL;
	}

	while (signatures[1])
		signatures++;

	return signatures[0];
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
