#ifndef COMMON_ENCRYPTION_H
#define COMMON_ENCRYPTION_H

#include "port/pg_crc32c.h"

/*
 * Full database encryption key.
 *
 * The key of EVP_aes_128_cbc() cipher is 128 bits long.
 */
#define	ENCRYPTION_KEY_LENGTH	16
/* Key length in characters (two characters per hexadecimal digit) */
#define ENCRYPTION_KEY_CHARS	(ENCRYPTION_KEY_LENGTH * 2)

#define KDF_PARAMS_FILE			"global/kdf_params"
#define KDF_PARAMS_FILE_SIZE	512

#define ENCRYPTION_KDF_NITER		1048576
#define	ENCRYPTION_KDF_SALT_LEN		sizeof(uint64)

/* Executable to retrieve the encryption key. */
extern char *encryption_key_command;

/* Key to encrypt / decrypt data. */
extern unsigned char encryption_key[];

extern void run_encryption_key_command(char *data_dir);
extern void read_encryption_key_f(FILE *f, char *command);
#endif /* COMMON_ENCRYPTION_H */
