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

void set_encryption_key(char *key);
void setup_encryption(void);
bool encryption_is_enabled(void);
void sample_encryption(char *buf);
void encrypt_block(char *buf, size_t size);
void decrypt_block(char *buf, size_t size);

#endif   /* ENCRYPTION_H */
