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

#ifdef USE_OPENSSL
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

#include "common/fe_memutils.h"
#include "common/sha2.h"
#include "common/string.h"
#include "catalog/pg_control.h"
#include "storage/bufpage.h"
#include "storage/encryption.h"
#include "utils/memutils.h"
#include "miscadmin.h"
#include "fmgr.h"
#include "port.h"

#ifdef USE_OPENSSL
/*
 * Full database encryption key.
 *
 * EVP_aes_256_xts() needs the key twice as long as AES would do in general.
 */
#define	ENCRYPTION_KEY_LENGTH	64
#endif

#ifdef USE_OPENSSL
static unsigned char	encryption_key[ENCRYPTION_KEY_LENGTH];
const char* encryptionkey_prefix = "encryptionkey=";
#endif

bool data_encrypted = false;
char	*key_setup_command = NULL;

#ifdef USE_OPENSSL
char	*encryption_buffer = NULL;
Size	encryption_buf_size = 0;

void enlarge_encryption_buffer(Size new_size);

static bool initialized = false;

static bool run_keysetup_command(uint8 *key);
static void evp_error(void);
#endif

/*
 * Encrypts a fixed value into *buf to verify that encryption key is correct.
 * Caller provided buf needs to be able to hold at least ENCRYPTION_SAMPLE_SIZE
 * bytes.
 */
void
sample_encryption(char *buf)
{
#ifdef USE_OPENSSL
	char tweak[TWEAK_SIZE];
	int i;
	for (i = 0; i < TWEAK_SIZE; i++)
		tweak[i] = i;

	encrypt_block("postgresqlcrypt", buf, ENCRYPTION_SAMPLE_SIZE, tweak);
#else
	encryption_error(true,
		 "data encryption cannot be used because SSL is not supported by this build\n"
		 "Compile with --with-openssl to use SSL connections.");
#endif	/* USE_OPENSSL */
}

/*
 * Encrypts one block of data with a specified tweak value. May only be called
 * when encryption_enabled is true.
 *
 * Input and output buffer may point to the same location.
 *
 * "size" must be a (non-zero) multiple of ENCRYPTION_BLOCK.
 *
 * "tweak" value must be TWEAK_SIZE bytes long.
 *
 * All-zero blocks are not encrypted to correctly handle relation extension,
 * and also to simplify handling of holes created by seek past EOF and
 * consequent write (see buffile.c).
 */
void
encrypt_block(const char *input, char *output, Size size, const char *tweak)
{
#ifdef	USE_OPENSSL
	Assert(size >= ENCRYPTION_BLOCK && size % ENCRYPTION_BLOCK == 0);
	Assert(initialized);

	/*
	 * The EVP API does not seem to expect the output buffer to be equal to
	 * the input. Ensure that we pass separate pointers.
	 */
	if (input == output)
	{
		if (size > encryption_buf_size)
			enlarge_encryption_buffer(size);

		memcpy(encryption_buffer, input, size);
		input = encryption_buffer;
	}

	if (IsAllZero(input, size))
		memset(output, 0, size);
	else
	{
		int	out_size;
		EVP_CIPHER_CTX *ctx;

		if((ctx = EVP_CIPHER_CTX_new()) == NULL)
			evp_error();

		if(EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, encryption_key,
							  (unsigned char *) tweak) != 1)
			evp_error();

		/*
		 * No padding is needed, the input block size should already be a
		 * multiple of ENCRYPTION_BLOCK_OPENSSL.
		 */
		EVP_CIPHER_CTX_set_padding(ctx, 0);

		Assert(EVP_CIPHER_CTX_block_size(ctx) == ENCRYPTION_BLOCK_OPENSSL);
		Assert(EVP_CIPHER_CTX_iv_length(ctx) == TWEAK_SIZE);
		Assert(EVP_CIPHER_CTX_key_length(ctx) == ENCRYPTION_KEY_LENGTH);

		/*
		 * Do the actual encryption. As the padding is disabled,
		 * EVP_EncryptFinal_ex() won't be needed.
		 */
		if(EVP_EncryptUpdate(ctx, (unsigned char *) output, &out_size,
							 (unsigned char *) input, size) != 1)
			evp_error();

		/*
		 * The input size is a multiple of ENCRYPTION_BLOCK_OPENSSL, so the
		 * output of AES-XTS should meet this condition.
		 */
		Assert(out_size == size);

		if (EVP_CIPHER_CTX_cleanup(ctx) != 1)
			evp_error();
	}
#else
	encryption_error(true,
			"data encryption cannot be used because SSL is not supported by this build\n"
			"Compile with --with-openssl to use SSL connections.");
#endif	/* USE_OPENSSL */
}

/*
 * Decrypts one block of data with a specified tweak value. May only be called
 * when encryption_enabled is true.
 *
 * Input and output buffer may point to the same location.
 *
 * "size" must be a (non-zero) multiple of ENCRYPTION_BLOCK.
 *
 * "tweak" value must be TWEAK_SIZE bytes long.
 *
 * All-zero blocks are not decrypted to correctly handle relation extension,
 * and also to simplify handling of holes created by seek past EOF and
 * consequent write (see buffile.c).
 */
void
decrypt_block(const char *input, char *output, Size size, const char *tweak)
{
#ifdef	USE_OPENSSL
	Assert(size >= ENCRYPTION_BLOCK && size % ENCRYPTION_BLOCK == 0);
	Assert(initialized);

	/*
	 * The EVP API does not seem to expect the output buffer to be equal to
	 * the input. Ensure that we pass separate pointers.
	 */
	if (input == output)
	{
		if (size > encryption_buf_size)
			enlarge_encryption_buffer(size);

		memcpy(encryption_buffer, input, size);
		input = encryption_buffer;
	}

	if (IsAllZero(input, size))
		memset(output, 0, size);
	else
	{
		int	out_size;
		EVP_CIPHER_CTX *ctx;

		if((ctx = EVP_CIPHER_CTX_new()) == NULL)
			evp_error();

		if(EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, encryption_key,
							  (unsigned char *) tweak) != 1)
			evp_error();

		/* The same considerations apply below as those in encrypt_block(). */
		EVP_CIPHER_CTX_set_padding(ctx, 0);
		Assert(EVP_CIPHER_CTX_block_size(ctx) == ENCRYPTION_BLOCK_OPENSSL);
		Assert(EVP_CIPHER_CTX_iv_length(ctx) == TWEAK_SIZE);
		Assert(EVP_CIPHER_CTX_key_length(ctx) == ENCRYPTION_KEY_LENGTH);

		if(EVP_DecryptUpdate(ctx, (unsigned char *) output, &out_size,
							 (unsigned char *) input, size) != 1)
			evp_error();

		Assert(out_size == size);

		if (EVP_CIPHER_CTX_cleanup(ctx) != 1)
			evp_error();
	}
#else
	encryption_error(true,
			"data encryption cannot be used because SSL is not supported by this build\n"
			"Compile with --with-openssl to use SSL connections.");
#endif	/* USE_OPENSSL */
}

/*
 * Report an error in an universal way so that caller does not have to care
 * whether it executes in backend or front-end.
 */
void
encryption_error(bool fatal, char *message)
{
#ifndef FRONTEND
	elog(fatal ? FATAL : INFO, "%s", message);
#else
	fprintf(stderr, "%s\n", message);
	if (fatal)
		exit(EXIT_FAILURE);
#endif
}

/*
 * Initialize encryption subsystem for use. Must be called before any
 * encryptable data is read from or written to data directory.
 */
void
setup_encryption()
{
#ifdef USE_OPENSSL
	/*
	 * Setup OpenSSL.
	 *
	 * None of these functions should return a value or raise error.
	 */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/*
	 * XXX Is this necessary?
	 */
	memset(encryption_key, 0, ENCRYPTION_KEY_LENGTH);

	/*
	 * It makes no sense to initialize the encryption multiple times.
	 */
	Assert(!initialized);

	if (!run_keysetup_command(encryption_key))
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
#endif	/* FRONTEND */
		}

		/* TODO: replace with PBKDF2 or scrypt */
		{
			pg_sha512_ctx sha_ctx;

			pg_sha512_init(&sha_ctx);
			pg_sha512_update(&sha_ctx, (uint8*) passphrase, strlen(passphrase));
			pg_sha512_final(&sha_ctx, encryption_key);
		}
	}

	initialized = true;
#else
	encryption_error(true,
			"data encryption cannot be used because SSL is not supported by this build\n"
			"Compile with --with-openssl to use SSL connections.");
#endif	/* USE_OPENSSL */
}

#ifdef USE_OPENSSL
void
enlarge_encryption_buffer(Size new_size)
{
	Assert(new_size > 0);

	/*
	 * Shrinkage is not the use case for this routine.
	 */
	if (new_size <= encryption_buf_size)
		return;

	/*
	 * Allocate a new chunk if nothing is there yet, else reallocate the
	 * existing one.
	 */
	if (encryption_buf_size == 0)
#ifndef FRONTEND
		encryption_buffer = (char *) MemoryContextAlloc(TopMemoryContext,
														new_size);
#else
		encryption_buffer = (char *) palloc(new_size);
#endif	/* FRONTEND */
	else
		encryption_buffer = (char *) repalloc(encryption_buffer, new_size);
	encryption_buf_size = new_size;
}

static bool
run_keysetup_command(uint8 *key)
{
	FILE *fp;
	char buf[ENCRYPTION_KEY_LENGTH * 2 + 1];
	int bytes_read;
	int i;

	if (key_setup_command == NULL)
		return false;

	if (!strlen(key_setup_command))
		return false;

	encryption_error(false,
				psprintf("Executing \"%s\" to set up encryption key",
						 key_setup_command));

	fp = popen(key_setup_command, "r");
	if (fp == NULL)
		encryption_error(true,
					psprintf("Failed to execute key_setup_command \"%s\"",
							 key_setup_command));

	if (fread(buf, 1, strlen(encryptionkey_prefix), fp) != strlen(encryptionkey_prefix))
		encryption_error(true, "Not enough data received from key_setup_command");

	if (strncmp(buf, encryptionkey_prefix, strlen(encryptionkey_prefix)) != 0)
		encryption_error(true, "Unknown data received from key_setup_command");

	bytes_read = fread(buf, 1, ENCRYPTION_KEY_LENGTH * 2 + 1, fp);
	if (bytes_read < ENCRYPTION_KEY_LENGTH*2)
	{
		if (feof(fp))
			encryption_error(true,
						"Encryption key provided by key_setup_command too short");
		else
			encryption_error(true,
						psprintf("key_setup_command returned error code %d",
								 ferror(fp)));
	}

	for (i = 0; i < ENCRYPTION_KEY_LENGTH; i++)
	{
		if (sscanf(buf+2*i, "%2hhx", key + i) == 0)
			encryption_error(true,
						psprintf("Invalid character in encryption key at position %d",
								 2 * i));
	}
	if (bytes_read > ENCRYPTION_KEY_LENGTH * 2)
	{
		if (buf[ENCRYPTION_KEY_LENGTH * 2] != '\n')
			encryption_error(true,
						psprintf("Encryption key too long '%s' %d.",
								 buf, buf[ENCRYPTION_KEY_LENGTH * 2]));
	}

	while (fread(buf, 1, sizeof(buf), fp) != 0)
	{
		/* Discard rest of the output */
	}

	pclose(fp);

	return true;
}
#endif	/* USE_OPENSSL */

/*
 * Error callback for openssl.
 */
#ifdef USE_OPENSSL
static void
evp_error(void)
{
	ERR_print_errors_fp(stderr);
#ifndef FRONTEND
	/*
	 * FATAL is the appropriate level because backend can hardly fix anything
	 * if encryption / decryption has failed.
	 *
	 * XXX Do we yet need EVP_CIPHER_CTX_cleanup() here?
	 */
	elog(FATAL, "OpenSSL encountered error during encryption or decryption.");
#else
	fprintf(stderr,
			"OpenSSL encountered error during encryption or decryption.");
	exit(EXIT_FAILURE);
#endif	/* FRONTEND */
}
#endif	/* USE_OPENSSL */

/*
 * Xlog is encrypted page at a time. Each xlog page gets a unique tweak via
 * segment and offset. Unfortunately we can't include timeline because
 * exitArchiveRecovery() can copy part of the last segment of the old timeline
 * into the first segment of the new timeline.
 *
 * TODO Consider teaching exitArchiveRecovery() to decrypt the copied pages
 * and encrypt them using a tweak that mentions the new timeline.
 *
 * The function is located here rather than some of the xlog*.c modules so
 * that front-end applications can easily use it too.
 */
void
XLogEncryptionTweak(char *tweak, XLogSegNo segment, uint32 offset)
{
#ifdef USE_OPENSSL
	memset(tweak, 0, TWEAK_SIZE);
	memcpy(tweak, &segment, sizeof(XLogSegNo));
	memcpy(tweak  + sizeof(XLogSegNo), &offset, sizeof(offset));
#else
	encryption_error(true,
		 "data encryption cannot be used because SSL is not supported by this build\n"
		 "Compile with --with-openssl to use SSL connections.");
#endif	/* USE_OPENSSL */
}
