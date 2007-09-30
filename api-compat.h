#ifndef _ANTISPAM_API_COMPAT_H
#define _ANTISPAM_API_COMPAT_H

#if DOVECOT_VER==10000
#define MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS	0
#define str_array_length strarray_length
#define IMAP_SYNC_FLAG_SAFE	0
#define mailbox_transaction_commit(arg) mailbox_transaction_commit(arg, 0)
#define mempool_unref(poolptr) pool_unref((*poolptr))
#define command_register(str, func, flags) command_register(str, func)
#else
#define mempool_unref(poolptr) pool_unref(poolptr)
#endif

#endif /* _ANTISPAM_API_COMPAT_H */
