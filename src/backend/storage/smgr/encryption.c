/*-------------------------------------------------------------------------
 *
 * encryption.c
 *	  This code handles encryption and decryption of data.
 *
 * Encryption is done by extension modules loaded by encryption_library GUC.
 * The extension module must register itself and provide a cryptography
 * implementation. Key setup is left to the extension module.
 *
 *
 * Copyright (c) 2016, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/storage/smgr/encryption.c
 *
 * NOTES
 *		This file is compiled as both front-end and backend code, so it
 *		may not use ereport, server-defined static variables, etc.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "common/fe_memutils.h"
#include "common/sha2.h"
#include "common/string.h"
#include "catalog/pg_control.h"
#include "storage/bufpage.h"
#include "storage/encryption.h"
#include "storage/xts.h"
#include "miscadmin.h"
#include "fmgr.h"
#include "port.h"

/*
 * Encryption and decryption keys for full database encryption support.
 */
typedef struct {
	xts_encrypt_ctx enc_ctx[1];
	xts_decrypt_ctx dec_ctx[1];
} db_encryption_ctx;

/* Full database encryption key. */
static db_encryption_ctx db_key;

bool data_encrypted = false;
char	*key_setup_command = NULL;

static bool initialized = false;

const char* encryptionkey_prefix = "encryptionkey=";
const int encryption_key_length = 32;

static bool run_keysetup_command(uint8 *key);
static void raise_error(int elevel, char *message);

/*
 * Encrypts a fixed value into *buf to verify that encryption key is correct.
 * Caller provided buf needs to be able to hold at least ENCRYPTION_SAMPLE_SIZE
 * bytes.
 */
void
sample_encryption(char *buf)
{
	char tweak[TWEAK_SIZE];
	int i;
	for (i = 0; i < TWEAK_SIZE; i++)
		tweak[i] = i;

	encrypt_block("postgresqlcrypt", buf, ENCRYPTION_SAMPLE_SIZE, tweak);
}

/*
 * Encrypts one block of data with a specified tweak value. Input and output
 * buffer may point to the same location. Size of input must be at least
 * ENCRYPTION_BLOCK bytes. Tweak value must be TWEAK_SIZE bytes.
 *
 * All zero blocks are not encrypted or decrypted to correctly handle relation
 * extension.
 *
 * Must only be called when encryption_enabled is true.
 */
void
encrypt_block(const char *input, char *output, Size size, const char *tweak)
{
#ifndef FRONTEND
	Assert(size >= ENCRYPTION_BLOCK);
	Assert(initialized);
#endif

	if (IsAllZero(input, size))
	{
		if (input != output)
			memset(output, 0, size);
	}
	else
	{
		if (input != output)
			memcpy(output, input, size);

		xts_encrypt_block((uint8*) output, (const uint8*) tweak, size,
						  db_key.enc_ctx);
	}
}

/*
 * Decrypts one block of data with a specified tweak value. Input and output
 * buffer may point to the same location. Tweak value must match the one used
 * when encrypting.
 *
 * Must only be called when encryption_enabled is true.
 */
void
decrypt_block(const char *input, char *output, Size size, const char *tweak)
{
	Assert(size >= ENCRYPTION_BLOCK);
	Assert(initialized);

	if (IsAllZero(input, size))
	{
		if (input != output)
			memset(output, 0, size);
	}
	else
	{
		if (input != output)
			memcpy(output, input, size);

		xts_decrypt_block((uint8*) output, (const uint8*) tweak, size,
						  db_key.dec_ctx);
	}
}

/*
 * Initialize encryption subsystem for use. Must be called before any
 * encryptable data is read from or written to data directory.
 */
void
setup_encryption()
{
	uint8 key[encryption_key_length];

	/*
	 * XXX Is this necessary?
	 */
	memset(key, 0, encryption_key_length);
	memset(&db_key, 0, sizeof(db_encryption_ctx));

	/*
	 * It makes no sense to initialize the encryption multiple times.
	 */
	Assert(!initialized);

	if (!run_keysetup_command(key))
	{
		char *passphrase = getenv("PGENCRYPTIONKEY");

		/* Empty or missing passphrase means that encryption is not configured */
		if (passphrase == NULL || passphrase[0] == '\0')
		{
#ifndef FRONTEND
			ereport(FATAL,
					(errmsg("encryption key not provided"),
					errdetail("The database cluster was initialized with encryption"
							  " but the server was started without an encryption key."),
							 errhint("Set the key using PGENCRYPTIONKEY environment variable.")));
#else
			fprintf(stderr,
					"The database cluster was initialized with encryption"
					" but the server was started without an encryption key. "
					"Set the key using PGENCRYPTIONKEY environment variable.\n");
			exit(EXIT_FAILURE);
#endif
		}

		/* TODO: replace with PBKDF2 or scrypt */
		{
			pg_sha256_ctx sha_ctx;

			pg_sha256_init(&sha_ctx);
			pg_sha256_update(&sha_ctx, (uint8*) passphrase, strlen(passphrase));
			pg_sha256_final(&sha_ctx, key);
		}
	}

	if (xts_encrypt_key(key, encryption_key_length, db_key.enc_ctx) != EXIT_SUCCESS ||
		xts_decrypt_key(key, encryption_key_length, db_key.dec_ctx) != EXIT_SUCCESS)
		raise_error(FATAL, "Encryption key setup failed.");

	initialized = true;
}

static bool
run_keysetup_command(uint8 *key)
{
	FILE *fp;
	char buf[encryption_key_length*2+1];
	int bytes_read;
	int i;

	if (key_setup_command == NULL)
		return false;

	if (!strlen(key_setup_command))
		return false;

	raise_error(INFO,
				psprintf("Executing \"%s\" to set up encryption key",
						 key_setup_command));

	fp = popen(key_setup_command, "r");
	if (fp == NULL)
		raise_error(ERROR,
					psprintf("Failed to execute key_setup_command \"%s\"",
							 key_setup_command));

	if (fread(buf, 1, strlen(encryptionkey_prefix), fp) != strlen(encryptionkey_prefix))
		raise_error(ERROR, "Not enough data received from key_setup_command");

	if (strncmp(buf, encryptionkey_prefix, strlen(encryptionkey_prefix)) != 0)
		raise_error(ERROR, "Unknown data received from key_setup_command");

	bytes_read = fread(buf, 1, encryption_key_length*2 + 1, fp);
	if (bytes_read < encryption_key_length*2)
	{
		if (feof(fp))
			raise_error(ERROR,
						"Encryption key provided by key_setup_command too short");
		else
			raise_error(ERROR,
						psprintf("key_setup_command returned error code %d",
								 ferror(fp)));
	}

	for (i = 0; i < encryption_key_length; i++)
	{
		if (sscanf(buf+2*i, "%2hhx", key + i) == 0)
			raise_error(ERROR,
						psprintf("Invalid character in encryption key at position %d",
								 2 * i));
	}
	if (bytes_read > encryption_key_length*2)
	{
		if (buf[encryption_key_length*2] != '\n')
			raise_error(ERROR,
						psprintf("Encryption key too long '%s' %d.",
								 buf, buf[encryption_key_length*2]));
	}

	while (fread(buf, 1, sizeof(buf), fp) != 0)
	{
		/* Discard rest of the output */
	}

	pclose(fp);

	return true;
}

/*
 * Report an error in an universal way so that caller does not have to care
 * whether it executes in backend or front-end.
 */
static void
raise_error(int elevel, char *message)
{
#ifndef FRONTEND
	elog(elevel, "%s", message);
#else
	fprintf(stderr, "%s\n", message);
	exit(EXIT_FAILURE);
#endif
}
