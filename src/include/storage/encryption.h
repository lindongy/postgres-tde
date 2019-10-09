/*-------------------------------------------------------------------------
 *
 * encryption.h
 *	  Full database encryption support
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/encryption.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "access/xlogdefs.h"
#include "common/encryption.h"
#include "miscadmin.h"
#include "storage/block.h"
#include "storage/relfilenode.h"
#include "port/pg_crc32c.h"

/*
 * Common error message issued when particular code path cannot be executed
 * due to absence of the OpenSSL library.
 */
#define ENCRYPTION_NOT_SUPPORTED_MSG \
	"compile postgres with --with-openssl to use encryption."

/*
 * Cipher used to encrypt data. This value is stored in the control file.
 *
 * Due to very specific requirements, the ciphers are not likely to change,
 * but we should be somewhat flexible.
 *
 * XXX If we have more than one cipher someday, have pg_controldata report the
 * cipher kind (in textual form) instead of merely saying "on".
 */
typedef enum CipherKind
{
	/* The cluster is not encrypted. */
	PG_CIPHER_NONE = 0,

	/*
	 * AES (Rijndael) in CTR mode of operation. Only key length 128 bits is
	 * supported now, so the constant name does not contain the key length.
	 *
	 * TODO Get rid of the CBC mode that we use for buffile.c before we use
	 * buffile.c to encrypt any file that needs to be handled by
	 * pg_upgrade. (As long as no file encrypted by buffile.c needs
	 * pg_upgrade, the control file does not have to be aware of the CBC
	 * mode.)
	 */
	PG_CIPHER_AES_CTR_128
}			CipherKind;

/*
 * TODO Tune these values.
 */
#define ENCRYPTION_PWD_MIN_LENGTH	8
#define ENCRYPTION_PWD_MAX_LENGTH	16

#ifndef FRONTEND
/*
 * Space for the encryption key in shared memory. Backend that receives the
 * key during startup stores it here so postmaster can eventually take a local
 * copy.
 *
 * Although postmaster should not do anything else with shared memory beyond
 * its setup, mere reading of this structure should not be a problem. The
 * worst thing that shared memory corruption can cause is wrong or missing
 * key, both of which will be detected later during the startup. (Failed
 * startup is not a real crash.) However we don't dare to use spinlock here
 * because that way shared memory corruption could cause postmaster to end up
 * in an infinite loop. See processEncryptionKey() for more comments on
 * synchronization.
 */
typedef struct ShmemEncryptionKey
{
	char	data[ENCRYPTION_KEY_LENGTH]; /* the key */
	bool	received;				/* received the key message? */
	bool	empty;					/* was the key message empty? */
} ShmemEncryptionKey;

/*
 * Encryption key in the shared memory.
 */
extern ShmemEncryptionKey *encryption_key_shmem;
#endif							/* FRONTEND */

#define TWEAK_SIZE 16

/* Is the cluster encrypted? */
extern PGDLLIMPORT bool data_encrypted;

/*
 * Number of bytes reserved to store encryption sample in ControlFileData.
 */
#define ENCRYPTION_SAMPLE_SIZE 16

#ifndef FRONTEND
/* Copy of the same field of ControlFileData. */
extern char encryption_verification[];
#endif							/* FRONTEND */

/* Do we have encryption_key and the encryption library initialized? */
extern bool	encryption_setup_done;

/*
 * In some cases we need a separate copy of the data because encryption
 * in-place (typically in the shared buffers) would make the data unusable for
 * backends.
 */
extern PGAlignedBlock encrypt_buf;

/*
 * The same for XLOG. This buffer spans multiple pages, in order to reduce the
 * number of syscalls when doing I/O.
 *
 * XXX Fine tune the buffer size.
 */
extern char *encrypt_buf_xlog;
#define	XLOG_ENCRYPT_BUF_PAGES	8
#define ENCRYPT_BUF_XLOG_SIZE	(XLOG_ENCRYPT_BUF_PAGES * XLOG_BLCKSZ)

#ifndef FRONTEND
extern Size EncryptionShmemSize(void);
extern void EncryptionShmemInit(void);

typedef int (*read_encryption_key_cb) (void);
extern void read_encryption_key(read_encryption_key_cb read_char);
#endif							/* FRONTEND */

extern void setup_encryption(void);
extern void sample_encryption(char *buf);
extern void encrypt_block(const char *input, char *output, Size size,
						  char *tweak, bool buffile);
extern void decrypt_block(const char *input, char *output, Size size,
						  char *tweak, bool buffile);
extern void encryption_error(bool fatal, char *message);

extern void XLogEncryptionTweak(char *tweak, TimeLineID timeline,
					XLogSegNo segment, uint32 offset);
extern void mdtweak(char *tweak, RelFileNode *relnode, ForkNumber forknum,
		BlockNumber blocknum);

#ifndef FRONTEND
extern bool EnforceLSNUpdateForEncryption(char	*buf_contents);
extern void RestoreInvalidLSN(char	*buf_contents);
#endif	/* FRONTEND */

#endif							/* ENCRYPTION_H */
