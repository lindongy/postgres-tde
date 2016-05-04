/*-------------------------------------------------------------------------
 *
 * encryption.c
 *	  This code handles encryption and decryption of data.
 *
 *
 * Copyright (c) 2016, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/storage/smgr/encryption.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "storage/encryption.h"
#include "utils/rijndael.h"

bool encryption_enabled = false;

static rijndael_ctx encryption_key;
static rijndael_ctx decryption_key;

static void set_encryption_key(char *key);


void
sample_encryption(char *buf)
{
	char tweak[TWEAK_SIZE];
	int i;
	for (i = 0; i < TWEAK_SIZE; i++)
		tweak[i] = i;

	encrypt_block("postgresqlcrypt", buf, ENCRYPTION_SAMPLE_SIZE, tweak);
}

void
encrypt_block(const char *input, char *output, Size size, char *tweak)
{
	Assert(size % 16 == 0);

	if (output != input)
		memcpy(output, input, size);
	aes_cbc_encrypt(&encryption_key, (uint8*) tweak, (uint8*) output, size);
}

void
decrypt_block(char *input, char *output, Size size, char *tweak)
{
	aes_cbc_decrypt(&decryption_key, (uint8*) tweak, (uint8*) input, size);
	if (output != input)
		memcpy(output, input, size);
}

void
setup_encryption()
{
	char* key = getenv("PGENCRYPTIONKEY");
	if (key != NULL) {
		set_encryption_key(key);
	}
}

static void
set_encryption_key(char *key)
{
	uint8 key_hash[16];
	encryption_enabled = true;

	pg_md5_binary(key, strlen(key), &key_hash);

	aes_set_key(&encryption_key, key_hash, 128, 1);
	aes_set_key(&decryption_key, key_hash, 128, 0);
}

