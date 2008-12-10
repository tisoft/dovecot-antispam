
#include <stdlib.h>
#include "antispam-plugin.h"
#include "signature.h"
#include "mail-storage-private.h"

const char *signature_hdr = "X-DSPAM-Signature";
static int signature_nosig_ignore = 0;

void signature_init(void)
{
	const char *tmp = get_setting("SIGNATURE");
	if (tmp)
		signature_hdr = tmp;
	debug("signature header line is \"%s\"\n", signature_hdr);

	tmp = get_setting("SIGNATURE_MISSING");
	if (!tmp)
		tmp = "error";
	if (strcmp(tmp, "move") == 0) {
		signature_nosig_ignore = 1;
		debug("will silently move mails with missing signature\n");
	} else if (strcmp(tmp, "error") != 0) {
		debug("invalid signature_missing setting '%s', ignoring\n", tmp);
	}
}

int signature_extract_to_list(struct mailbox_transaction_context *t,
			      struct mail *mail, struct siglist **list,
			      enum classification wanted)
{
	const char *const *signatures;
	struct siglist *item;

	signatures = get_mail_headers(mail, signature_hdr);
	if (!signatures || !signatures[0]) {
		if (!signature_nosig_ignore) {
			mail_storage_set_error(t->box->storage,
					       ME(NOTPOSSIBLE)
					       "antispam signature not found");
			return -1;
		} else {
			return 0;
		}
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

int signature_extract(struct mailbox_transaction_context *t,
		      struct mail *mail, const char **signature)
{
	const char *const *signatures;

	signatures = get_mail_headers(mail, signature_hdr);
	if (!signatures || !signatures[0]) {
		if (!signature_nosig_ignore) {
			mail_storage_set_error(t->box->storage,
					       ME(NOTPOSSIBLE)
					       "antispam signature not found");
			return -1;
		} else {
			*signature = NULL;
			return 0;
		}
	}

	while (signatures[1])
		signatures++;

	*signature = signatures[0];

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
