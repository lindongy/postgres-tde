/*-------------------------------------------------------------------------
 *
 * encryption.h
 *	  Transparent Data Encryption specific code usable by both frontend and
 *	  backend.
 *
 * Portions Copyright (c) 2019, Cybertec Schönig & Schönig GmbH
 *
 * IDENTIFICATION
 *	  src/include/common/encryption.c
 *
 *-------------------------------------------------------------------------
 */
#ifndef COMMON_ENCRYPTION_H
#define COMMON_ENCRYPTION_H

#include "port/pg_crc32c.h"

/*
 * Full database encryption key.
 *
 * We use 128-bits key for both AES-CTR and AES-CBC.
 */
#define	ENCRYPTION_KEY_LENGTH	16
/* Key length in characters (two characters per hexadecimal digit) */
#define ENCRYPTION_KEY_CHARS	(ENCRYPTION_KEY_LENGTH * 2)

#define KDF_PARAMS_FILE			"global/kdf_params"
#define KDF_PARAMS_FILE_SIZE	512

#define ENCRYPTION_KDF_NITER		1048576
#define	ENCRYPTION_KDF_SALT_LEN		sizeof(uint64)

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

/* Executable to retrieve the encryption key. */
extern char *encryption_key_command;

/*
 * Key to encrypt / decrypt permanent data using AES-CTR cipher or any data
 * using AES-CBC cipher.
 */
extern unsigned char encryption_key[];

extern void run_encryption_key_command(char *data_dir);
extern void read_encryption_key_f(FILE *f, char *command);
extern void encryption_key_from_string(char key_str[ENCRYPTION_KEY_CHARS]);
#endif /* COMMON_ENCRYPTION_H */
