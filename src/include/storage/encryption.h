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

#ifdef USE_OPENSSL
/*
 * EVP_aes_256_xts() determines the following constants.
 *
 * Note: if the encryption algorithm changes and ENCRYPTION_BLOCK gets greater
 * than MAXALIGN, make sure that the alignment of XLOG records is at least
 * ENCRYPTION_BLOCK.
 *
 * If one XLOG record ended and the following one started in the same block,
 * we'd have to either encrypt and decrypt both records together, or encrypt
 * (after having zeroed the part of the block occupied by the other record)
 * and decrypt them separate. Neither approach is compatible with streaming
 * replication. In the first case we can't ask standby not to decrypt the
 * first record until the second has been streamed. The second approach would
 * imply streaming of two different versions of the same block two times.
 *
 * For similar reasons, the alignment to ENCRYPTION_BLOCK also has to be
 * applied when storing changes to disk in reorderbuffer.c.
 */
#define ENCRYPTION_BLOCK 1
#define TWEAK_SIZE 16
#endif

extern PGDLLIMPORT bool data_encrypted;
extern PGDLLIMPORT char	*key_setup_command;

extern void setup_encryption(void);
extern void sample_encryption(char *buf);
extern void encrypt_block(const char *input, char *output, Size size,
						  const char *tweak);
extern void decrypt_block(const char *input, char *output, Size size,
						  const char *tweak);
#ifndef OPENSSL
extern void encryption_error(bool fatal, char *message);
#endif

typedef bool (*SetupEncryption_function) ();
typedef void (*EncryptBlock_function) (const char *input, char *output,
		Size size, const char *tweak);
typedef void (*DecryptBlock_function) (const char *input, char *output,
		Size size, const char *tweak);

extern void XLogEncryptionTweak(char *tweak, XLogSegNo segment,
								uint32 offset);

#endif   /* ENCRYPTION_H */
