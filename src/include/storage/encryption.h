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

typedef bool (*SetupEncryption_function) ();
typedef void (*EncryptBlock_function) (const char *input, char *output,
		Size size, const char *tweak);
typedef void (*DecryptBlock_function) (const char *input, char *output,
		Size size, const char *tweak);

extern void XLogEncryptionTweak(char *tweak, XLogSegNo segment,
								uint32 offset);

#endif   /* ENCRYPTION_H */
