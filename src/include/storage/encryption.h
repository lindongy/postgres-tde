/*-------------------------------------------------------------------------
 *
 * encryption.h
 *	  Full database encryption support
 *
 *
 * Portions Copyright (c) 1996-2015, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/encryption.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "access/xlogdefs.h"
#include "lib/ilist.h"

#define ENCRYPTION_BLOCK 16
#define TWEAK_SIZE 16

extern PGDLLIMPORT bool data_encrypted;
extern PGDLLIMPORT char	*key_setup_command;

/*
 * Should XLOG records be aligned to ENCRYPTION_BLOCK bytes?
 *
 * The encrypted data is a series of blocks of size ENCRYPTION_BLOCK. If one
 * XLOG record ended and the following one started in the same block, we'd
 * have to either encrypt and decrypt both records together, or encrypt (after
 * having zeroed the part of the block occupied by the other record) and
 * decrypt them separate. Neither approach is compatible with streaming
 * replication. In the first case we can't ask standby not to decrypt the
 * first record until the second has been streamed. The second approach would
 * imply streaming of two different versions of the same block two times.
 *
 * We avoid this problem by aligning XLOG records to the encryption block
 * size. This way no adjacent XLOG records should appear in the same block.
 *
 * TODO If the configuration allows walsender to decrypt the XLOG stream
 * before sending it, adjust this expression so that the additional padding of
 * is not added to XLOG records in that case. (Since the XLOG alignment cannot
 * change without initdb, the same would apply to the configuration variable
 * that makes walsender perform the decryption. Does such a variable make
 * sense?)
 */
#define DO_ENCRYPTION_BLOCK_ALIGN	data_encrypted

/*
 * Use TYPEALIGN64 since besides record size we also need to align XLogRecPtr.
 */
#define ENCRYPTION_BLOCK_ALIGN(LEN)		TYPEALIGN64(ENCRYPTION_BLOCK, (LEN))

/*
 * Universal computation of XLOG record alignment.
 */
#define XLOG_REC_ALIGN(LEN) ((DO_ENCRYPTION_BLOCK_ALIGN) ?\
							 ENCRYPTION_BLOCK_ALIGN(LEN) : MAXALIGN64(LEN))

extern void setup_encryption(void);
extern void sample_encryption(char *buf);
extern void encrypt_block(const char *input, char *output, Size size,
						  const char *tweak);
extern void decrypt_block(const char *input, char *output, Size size,
						  const char *tweak);

typedef bool (*SetupEncryption_function) ();
typedef void (*EncryptBlock_function) (const char *input, char *output,
		Size size, const char *tweak);
typedef void (*DecryptBlock_function) (const char *input, char *output,
		Size size, const char *tweak);

extern void XLogEncryptionTweak(char *tweak, TimeLineID timeline,
				 XLogSegNo segment, uint32 offset);

#endif   /* ENCRYPTION_H */
