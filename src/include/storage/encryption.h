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


#define ENCRYPTION_SAMPLE_SIZE 16
#define ENCRYPTION_BLOCK 16
#define TWEAK_SIZE 16

extern PGDLLIMPORT bool encryption_enabled;


void setup_encryption(void);
void sample_encryption(char *buf);
void encrypt_block(const char *input, char *output, Size size, char *tweak);
void decrypt_block(char *input, char *output, Size size, char *tweak);

typedef bool (*SetupEncryption_function) ();
typedef void (*EncryptBlock_function) (const char *input,
		char *output,
		Size size,
		char *tweak);
typedef void (*DecryptBlock_function) (char *input,
		char *output,
		Size size,
		char *tweak);

typedef struct {
	SetupEncryption_function SetupEncryption;
	EncryptBlock_function EncryptBlock;
	DecryptBlock_function DecryptBlock;
} EncryptionRoutines;

void register_encryption_module(char *name, EncryptionRoutines *enc);

#endif   /* ENCRYPTION_H */
