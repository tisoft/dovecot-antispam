/*
 * Storage implementation for antispam plugin
 * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
 *
 * Derived from Quota plugin:
 * Copyright (C) 2005 Timo Sirainen
 */

#include <sys/stat.h>

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "mail-search.h"
#include "mail-storage-private.h"

#include "antispam-plugin.h"

#define ANTISPAM_CONTEXT(obj) \
	*((void **)array_idx_modifyable(&(obj)->module_contexts, \
					antispam_storage_module_id))

struct antispam_mail_storage {
	struct mail_storage_vfuncs super;
	struct antispam *antispam;
};

enum mailbox_move_type {
	MMT_APPEND,
	MMT_UNINTERESTING,
	MMT_TO_CLEAN,
	MMT_TO_SPAM,
};

enum classification move_to_class(enum mailbox_move_type tp)
{
	switch (tp) {
	case MMT_TO_CLEAN:
		return CLASS_NOTSPAM;
	case MMT_TO_SPAM:
		return CLASS_SPAM;
	default:
		i_assert(0);
	}
}

struct antispam_mailbox {
	struct mailbox_vfuncs super;

	enum mailbox_move_type movetype;

	/* used to check if copy was implemented with save */
	unsigned int save_hack:1;
};

static unsigned int antispam_storage_module_id = 0;
static bool antispam_storage_module_id_set = FALSE;

static int
antispam_copy(struct mailbox_transaction_context *t, struct mail *mail,
	      enum mail_flags flags, struct mail_keywords *keywords,
	      struct mail *dest_mail)
{
	struct antispam_mailbox *asbox = ANTISPAM_CONTEXT(t->box);
	struct antispam_transaction_context *ast =
		ANTISPAM_CONTEXT(t);
	struct mail *copy_dest_mail;
	int ret;

	if (dest_mail != NULL)
		copy_dest_mail = dest_mail;
	else
		copy_dest_mail = mail_alloc(t, MAIL_FETCH_PHYSICAL_SIZE, NULL);

	i_assert(mail->box);

	asbox->save_hack = FALSE;
	asbox->movetype = MMT_UNINTERESTING;

	if (mailbox_is_unsure(t->box)) {
		mail_storage_set_error(t->box->storage,
				       "Cannot copy to unsure folder");
		return -1;
	}

	if (!mailbox_is_trash(mail->box) &&
	    !mailbox_is_trash(t->box)) {
		bool src_spam = mailbox_is_spam(mail->box);
		bool dst_spam = mailbox_is_spam(t->box);
		bool src_unsu = mailbox_is_unsure(mail->box);

		if ((src_spam || src_unsu) && !dst_spam)
			asbox->movetype = MMT_TO_CLEAN;
		else if ((!src_spam || src_unsu) && dst_spam)
			asbox->movetype = MMT_TO_SPAM;
	}

	if (asbox->super.copy(t, mail, flags, keywords, copy_dest_mail) < 0)
		return -1;

	/*
	 * If copying used saving internally, we already have treated the mail
	 */
	if (asbox->save_hack || asbox->movetype == MMT_UNINTERESTING)
		ret = 0;
	else
		ret = backend_handle_mail(t, ast, copy_dest_mail,
					  move_to_class(asbox->movetype));

	/*
	 * Both save_hack and movetype are only valid within a copy operation,
	 * i.e. they are now invalid. Because, in theory, another operation
	 * could be done after mailbox_open(), we need to reset the movetype
	 * variable here. save_hack doesn't need to be reset because it is
	 * only ever set within the save function and tested within this copy
	 * function after being reset at the beginning of the copy, movetype
	 * however is tested within the save_finish() function and a subsequent
	 * save to the mailbox should not invoke the backend.
	 */
	asbox->movetype = MMT_APPEND;

	if (copy_dest_mail != dest_mail)
		mail_free(&copy_dest_mail);
	return ret;
}

static int antispam_save_init(struct mailbox_transaction_context *t,
			      enum mail_flags flags,
			      struct mail_keywords *keywords,
			      time_t received_date, int timezone_offset,
			      const char *from_envelope, struct istream *input,
			      bool want_mail, struct mail_save_context **ctx_r)
{
	struct antispam_mailbox *asbox = ANTISPAM_CONTEXT(t->box);

	want_mail = TRUE;
	return asbox->super.save_init(t, flags, keywords, received_date,
				      timezone_offset, from_envelope,
				      input, want_mail, ctx_r);
}

static int antispam_save_finish(struct mail_save_context *ctx,
				struct mail *dest_mail)
{
	struct antispam_mailbox *asbox =
		ANTISPAM_CONTEXT(ctx->transaction->box);
	struct antispam_transaction_context *ast =
		ANTISPAM_CONTEXT(ctx->transaction);
	struct mail *save_dest_mail;
	int ret;

	if (dest_mail != NULL)
		save_dest_mail = dest_mail;
	else
		save_dest_mail = mail_alloc(ctx->transaction,
					    MAIL_FETCH_PHYSICAL_SIZE, NULL);

	if (asbox->super.save_finish(ctx, save_dest_mail) < 0)
		return -1;

	asbox->save_hack = TRUE;

	ret = 0;

	switch (asbox->movetype) {
	case MMT_UNINTERESTING:
		break;
	case MMT_APPEND:
		/* Disallow APPENDs to SPAM/UNSURE folders. */
		if (mailbox_is_spam(save_dest_mail->box) ||
		    mailbox_is_unsure(save_dest_mail->box)) {
			ret = -1;
			mail_storage_set_error(save_dest_mail->box->storage,
					"Cannot APPEND to this folder.");
		}
		break;
	default:
		ret = backend_handle_mail(ctx->transaction, ast, save_dest_mail,
					  move_to_class(asbox->movetype));
	}

	if (save_dest_mail != dest_mail)
		mail_free(&save_dest_mail);
	return ret;
}

static struct antispam_transaction_context *
antispam_transaction_begin(struct mailbox *box)
{
	struct antispam_transaction_context *ast;

	ast = backend_start(box);
	i_assert(ast != NULL);

	return ast;
}

static void
antispam_transaction_rollback(struct antispam_transaction_context **_ast)
{
	struct antispam_transaction_context *ast = *_ast;

	backend_rollback(ast);
	*_ast = NULL;
}

static int
antispam_transaction_commit(struct mailbox_transaction_context *ctx,
			    struct antispam_transaction_context **_ast)
{
	struct antispam_transaction_context *ast = *_ast;
	int ret;

	ret = backend_commit(ctx, ast);
	*_ast = NULL;
	return ret;
}

static struct mailbox_transaction_context *
antispam_mailbox_transaction_begin(struct mailbox *box,
				   enum mailbox_transaction_flags flags)
{
	struct antispam_mailbox *asbox = ANTISPAM_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct antispam_transaction_context *ast;

	t = asbox->super.transaction_begin(box, flags);
	ast = antispam_transaction_begin(box);

	array_idx_set(&t->module_contexts, antispam_storage_module_id, &ast);
	return t;
}

static int
antispam_mailbox_transaction_commit(struct mailbox_transaction_context *ctx,
				    enum mailbox_sync_flags flags)
{
	struct antispam_mailbox *asbox = ANTISPAM_CONTEXT(ctx->box);
	struct antispam_transaction_context *ast = ANTISPAM_CONTEXT(ctx);

	if (antispam_transaction_commit(ctx, &ast) < 0) {
		asbox->super.transaction_rollback(ctx);
		return -1;
	} else
		return asbox->super.transaction_commit(ctx, flags);
}

static void
antispam_mailbox_transaction_rollback(struct mailbox_transaction_context *ctx)
{
	struct antispam_mailbox *asbox = ANTISPAM_CONTEXT(ctx->box);
	struct antispam_transaction_context *ast = ANTISPAM_CONTEXT(ctx);

	antispam_transaction_rollback(&ast);
	asbox->super.transaction_rollback(ctx);
}

static struct mailbox *antispam_mailbox_open(struct mail_storage *storage,
					     const char *name,
					     struct istream *input,
					     enum mailbox_open_flags flags)
{
	struct antispam_mail_storage *as_storage = ANTISPAM_CONTEXT(storage);
	struct mailbox *box;
	struct antispam_mailbox *asbox;

	box = as_storage->super.mailbox_open(storage, name, input, flags);
	if (box == NULL)
		return NULL;

	asbox = p_new(box->pool, struct antispam_mailbox, 1);
	asbox->super = box->v;
	asbox->save_hack = FALSE;
	asbox->movetype = MMT_APPEND;

	/* override save_init to override want_mail, we need that */
	box->v.save_init = antispam_save_init;
	box->v.save_finish = antispam_save_finish;
	box->v.transaction_begin = antispam_mailbox_transaction_begin;
	box->v.transaction_commit = antispam_mailbox_transaction_commit;
	box->v.transaction_rollback = antispam_mailbox_transaction_rollback;
	box->v.copy = antispam_copy;
	array_idx_set(&box->module_contexts, antispam_storage_module_id,
		      &asbox);
	return box;
}

void antispam_mail_storage_created(struct mail_storage *storage)
{
	struct antispam_mail_storage *as_storage;

	if (antispam_next_hook_mail_storage_created != NULL)
		antispam_next_hook_mail_storage_created(storage);

	as_storage = p_new(storage->pool, struct antispam_mail_storage, 1);
	as_storage->super = storage->v;
	storage->v.mailbox_open = antispam_mailbox_open;

	if (!antispam_storage_module_id_set) {
		antispam_storage_module_id = mail_storage_module_id++;
		antispam_storage_module_id_set = TRUE;
	}

	array_idx_set(&storage->module_contexts,
		      antispam_storage_module_id, &as_storage);
}
