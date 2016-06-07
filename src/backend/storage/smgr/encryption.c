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

#include "storage/bufpage.h"
#include "storage/encryption.h"
#include "miscadmin.h"
#include "fmgr.h"
#include "port.h"

bool encryption_enabled = false;
bool have_encryption_provider = false;
EncryptionRoutines encryption_hooks;

void
register_encryption_module(char *name, EncryptionRoutines *enc)
{
	elog(DEBUG1, "Registering encryption module %s", name);

	encryption_hooks = *enc;
	have_encryption_provider = true;
}

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
	Assert(encryption_enabled);

	if (IsAllZero(input, size))
	{
		if (input != output)
			memset(output, 0, size);
	}
	else
		encryption_hooks.EncryptBlock(input, output, size, tweak);
}

void
decrypt_block(char *input, char *output, Size size, char *tweak)
{
	Assert(size % 16 == 0);
	Assert(encryption_enabled);

	if (IsAllZero(input, size))
	{
		if (input != output)
			memset(output, 0, size);
	}
	else
		encryption_hooks.DecryptBlock(input, output, size, tweak);
}

void
setup_encryption()
{
	char *filename;

	if (encryption_library_string == NULL || encryption_library_string[0] == '\0')
		return;

	filename = pstrdup(encryption_library_string);

	canonicalize_path(filename);
	load_file(filename, false);
	ereport(DEBUG1,
			(errmsg("loaded library \"%s\" for encryption", filename)));
	pfree(filename);

	elog(LOG, "setup encryption");
	if (have_encryption_provider)
	{
		encryption_enabled = encryption_hooks.SetupEncryption();
		elog(DEBUG1, "encryption %s", encryption_enabled ? "enabled" : "disabled");
	}
}

