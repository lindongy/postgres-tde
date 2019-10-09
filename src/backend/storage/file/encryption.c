/*-------------------------------------------------------------------------
 *
 * encryption.c
 *	  This code handles encryption and decryption of data.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * See src/backend/storage/file/README.encryption for explanation of the
 * design.
 *
 * IDENTIFICATION
 *	  src/backend/storage/file/encryption.c
 *
 * NOTES
 *		This file is compiled as both front-end and backend code, so the
 *		FRONTEND macro must be used to distinguish the case if we need to
 *		report error or if server-defined variable / function seems useful.
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <sys/stat.h>

#include "access/xlog.h"
#include "access/xlogdefs.h"
#include "common/fe_memutils.h"
#include "common/sha2.h"
#include "common/string.h"
#include "catalog/pg_control.h"
#include "storage/bufpage.h"
#include "storage/encryption.h"

#ifndef FRONTEND
#include "port.h"
#include "storage/shmem.h"
#include "storage/fd.h"
#include "utils/memutils.h"
#endif							/* FRONTEND */

#ifdef USE_ENCRYPTION
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

EVP_CIPHER_CTX *ctx_encrypt, *ctx_decrypt,
	*ctx_encrypt_buffile, *ctx_decrypt_buffile;
#endif							/* USE_ENCRYPTION */

#ifndef FRONTEND
ShmemEncryptionKey *encryption_key_shmem = NULL;
#endif							/* FRONTEND */

bool		data_encrypted = false;

char encryption_verification[ENCRYPTION_SAMPLE_SIZE];

bool	encryption_setup_done = false;

PGAlignedBlock encrypt_buf;
char	   *encrypt_buf_xlog = NULL;

#ifdef USE_ENCRYPTION
static void init_encryption_context(EVP_CIPHER_CTX **ctx_p, bool encrypt,
									bool buffile);
static void evp_error(void);
#endif							/* USE_ENCRYPTION */

#ifndef FRONTEND
/*
 * Report space needed for our shared memory area
 */
Size
EncryptionShmemSize(void)
{
	return sizeof(ShmemEncryptionKey);
}

/*
 * Initialize our shared memory area
 */
void
EncryptionShmemInit(void)
{
	bool	found;

	encryption_key_shmem = ShmemInitStruct("Cluster Encryption Key",
										   EncryptionShmemSize(),
										   &found);
	if (!IsUnderPostmaster)
	{
		Assert(!found);

		encryption_key_shmem->received = false;
		encryption_key_shmem->empty = false;
	}
	else
		Assert(found);
}

/*
 * Read encryption key in hexadecimal form from stdin and store it in
 * encryption_key variable.
 */
void
read_encryption_key(read_encryption_key_cb read_char)
{
	char	*buf;
	int		read_len, i, c;

	buf = (char *) palloc(ENCRYPTION_KEY_CHARS);

	read_len = 0;
	while ((c = (*read_char)()) != EOF && c != '\n')
	{
		if (read_len >= ENCRYPTION_KEY_CHARS)
			ereport(FATAL, (errmsg("Encryption key is too long")));

		buf[read_len++] = c;
	}

	if (read_len < ENCRYPTION_KEY_CHARS)
		ereport(FATAL, (errmsg("Encryption key is too short")));

	/* Turn the hexadecimal representation into an array of bytes. */
	for (i = 0; i < ENCRYPTION_KEY_LENGTH; i++)
	{
		if (sscanf(buf + 2 * i, "%2hhx", encryption_key + i) == 0)
		{
			ereport(FATAL,
					(errmsg("Invalid character in encryption key at position %d",
							2 * i)));
		}
	}

	pfree(buf);
}
#endif							/* FRONTEND */

/*
 * Initialize encryption subsystem for use. Must be called before any
 * encryptable data is read from or written to data directory.
 */
void
setup_encryption(void)
{
#ifdef USE_ENCRYPTION
	/*
	 * Setup OpenSSL.
	 *
	 * None of these functions should return a value or raise error.
	 */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	/*
	 * TODO Find out if this needs to be called for OpenSSL < 1.1.0.
	 */
	/* OPENSSL_config(NULL); */

	init_encryption_context(&ctx_encrypt, true, false);
	init_encryption_context(&ctx_decrypt, false, false);
	init_encryption_context(&ctx_encrypt_buffile, true, true);
	init_encryption_context(&ctx_decrypt_buffile, false, true);

	/*
	 * We need multiple pages here, so allocate the memory dynamically instead
	 * of using PGAlignedBlock. That also ensures it'll be MAXALIGNed, which
	 * is useful because the buffer will be used for I/O.
	 *
	 * Use TopMemoryContext because on server side this code is run by
	 * postmaster and postmaster context gets freed after fork().
	 */
#ifndef FRONTEND
	encrypt_buf_xlog = (char *) MemoryContextAlloc(TopMemoryContext,
												   ENCRYPT_BUF_XLOG_SIZE);
#else
	encrypt_buf_xlog = (char *) palloc(ENCRYPT_BUF_XLOG_SIZE);
#endif

	encryption_setup_done = true;
#else  /* !USE_ENCRYPTION */
#ifndef FRONTEND
	/*
	 * If no encryption implementation is linked and caller requests
	 * encryption, we should error out here and thus cause the calling process
	 * to fail (preferably postmaster, so the child processes don't make the
	 * same mistake).
	 */
	ereport(FATAL, (errmsg(ENCRYPTION_NOT_SUPPORTED_MSG)));
#else
	/* Front-end shouldn't actually get here, but be careful. */
	fprintf(stderr, "%s\n", ENCRYPTION_NOT_SUPPORTED_MSG);
	exit(EXIT_FAILURE);
#endif	/* FRONTEND */
#endif							/* USE_ENCRYPTION */
}

/*
 * Encrypts a fixed value into *buf to verify that encryption key is correct.
 * Caller provided buf needs to be able to hold at least ENCRYPTION_SAMPLE_SIZE
 * bytes.
 */
void
sample_encryption(char *buf)
{
	char		tweak[TWEAK_SIZE];
	int			i;

	for (i = 0; i < TWEAK_SIZE; i++)
		tweak[i] = i;

	encrypt_block("postgresqlcrypt", buf, ENCRYPTION_SAMPLE_SIZE, tweak,
				  false);
}

/*
 * Encrypts one block of data with a specified tweak value. May only be called
 * when encryption_enabled is true.
 *
 * Input and output buffer may point to the same location.
 *
 * "size" must be a (non-zero) multiple of ENCRYPTION_BLOCK.
 *
 * "tweak" value must be TWEAK_SIZE bytes long. If NULL is passed, we suppose
 * that the input data start with a page LSN which we'll use as an encryption
 * tweak. In such a case we don't encrypt the initial sizeof(PageXLogRecPtr)
 * bytes so the tweak is preserved for decryption.
 *
 * All-zero blocks are not encrypted to correctly handle relation extension,
 * and also to simplify handling of holes created by seek past EOF and
 * consequent write (see buffile.c).
 */
void
encrypt_block(const char *input, char *output, Size size, char *tweak,
			  bool buffile)
{
#ifdef USE_ENCRYPTION
	EVP_CIPHER_CTX *ctx;
	int			out_size;
	char	tweak_loc[TWEAK_SIZE];

	Assert(data_encrypted);

	/*
	 * Empty page is not worth encryption, and encryption of zeroes wouldn't
	 * even be secure.
	 */
	if (IsAllZero(input, size))
	{
		memset(output, 0, size);
		return;
	}

	/*
	 * If caller passed no tweak, we assume this is relation page and LSN
	 * should be used.
	 */
	if (tweak == NULL)
	{
		size_t	lsn_size = sizeof(PageXLogRecPtr);

		memset(tweak_loc, 0, TWEAK_SIZE);

		/*
		 * The CTR mode counter is big endian (see crypto/modes/ctr128.c in
		 * OpenSSL) and the lower part is used by OpenSSL internally.
		 * Initialize the upper eight bytes and leave the lower eight to
		 * OpenSSL - as the counter is increased once per 16 bytes of input,
		 * and as we hardly ever encrypt more than BLCKSZ bytes at a time,
		 * it's not possible for the lower part to overflow into the upper
		 * one.
		 *
		 * Endian of the LSN does not matter: no one cares about the actual
		 * value as long as it's unique for each encryption run.
		 */
		memcpy(tweak_loc, input, lsn_size);

		tweak = tweak_loc;

		/* Copy the LSN to the output. */
		if (input != output)
			memcpy(output, input, lsn_size);

		/* Do not encrypt the LSN. */
		input += lsn_size;
		output += lsn_size;
		size -= lsn_size;
	}

	ctx = !buffile ? ctx_encrypt : ctx_encrypt_buffile;

	/* The remaining initialization. */
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, encryption_key,
						   (unsigned char *) tweak) != 1)
		evp_error();

	/* Do the actual encryption. */
	if (EVP_EncryptUpdate(ctx, (unsigned char *) output,
						  &out_size, (unsigned char *) input, size) != 1)
		evp_error();

	/* TODO ereport() instead of Assert()? */
	Assert(out_size == size);
#else
	/* data_encrypted should not be set */
	Assert(false);
#endif							/* USE_ENCRYPTION */
}

/*
 * Decrypts one block of data with a specified tweak value. May only be called
 * when encryption_enabled is true.
 *
 * Input and output buffer may point to the same location.
 *
 * For detailed comments see encrypt_block().
 */
void
decrypt_block(const char *input, char *output, Size size, char *tweak,
			  bool buffile)
{
#ifdef USE_ENCRYPTION
	EVP_CIPHER_CTX *ctx;
	int			out_size;
	char	tweak_loc[TWEAK_SIZE];

	Assert(data_encrypted);

	if (IsAllZero(input, size))
	{
		memset(output, 0, size);
		return;
	}

	if (tweak == NULL)
	{
		size_t	lsn_size = sizeof(PageXLogRecPtr);

		memset(tweak_loc, 0, TWEAK_SIZE);
		memcpy(tweak_loc, input, lsn_size);
		tweak = tweak_loc;

		if (input != output)
			memcpy(output, input, lsn_size);

		input += lsn_size;
		output += lsn_size;
		size -= lsn_size;
	}

	ctx = !buffile ? ctx_decrypt : ctx_decrypt_buffile;

	/* The remaining initialization. */
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, encryption_key,
						   (unsigned char *) tweak) != 1)
		evp_error();

	/* Do the actual encryption. */
	if (EVP_DecryptUpdate(ctx, (unsigned char *) output,
						  &out_size, (unsigned char *) input, size) != 1)
		evp_error();

	/* TODO ereport() instead of Assert()? */
	Assert(out_size == size);
#else
	/* data_encrypted should not be set */
	Assert(false);
#endif							/* USE_ENCRYPTION */
}

#ifdef USE_ENCRYPTION
/*
 * Initialize the OpenSSL context for passed cipher.
 *
 * On server side this happens during postmaster startup, so other processes
 * inherit the initialized context via fork(). There's no reason to this again
 * and again in encrypt_block() / decrypt_block(), also because we should not
 * handle out-of-memory conditions encountered by OpenSSL in another way than
 * ereport(FATAL). The OOM is much less likely to happen during postmaster
 * startup, and even if it happens, troubleshooting should be easier than if
 * it happened during normal operation.
 *
 * XXX Do we need to call EVP_CIPHER_CTX_cleanup() (via on_proc_exit callback
 * for server processes and other way for front-ends)? Not sure it's
 * necessary, as the initialization does not involve any shared resources
 * (e.g. files).
 */
static void
init_encryption_context(EVP_CIPHER_CTX **ctx_p, bool encrypt, bool buffile)
{
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher;

	/*
	 * Currently we use CBC mode for buffile.c because CTR imposes much more
	 * stringent requirements on IV (i.e. the same IV must not be used
	 * repeatedly.)
	 */
	cipher = !buffile ? EVP_aes_128_ctr() : EVP_aes_128_cbc();

	if ((*ctx_p = EVP_CIPHER_CTX_new()) == NULL)
		evp_error();
	ctx = *ctx_p;

	if (encrypt)
	{
		if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
			evp_error();
	}
	else
	{
		if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
			evp_error();
	}

	/* CTR mode is effectively a stream cipher. */
	Assert((!buffile && EVP_CIPHER_CTX_block_size(ctx) == 1) ||
		   (buffile && EVP_CIPHER_CTX_block_size(ctx) == 16));

	/*
	 * No padding is needed. For relation pages the input block size should
	 * already be a multiple of ENCRYPTION_BLOCK, while for WAL we want to
	 * avoid encryption of the unused (zeroed) part of the page, see
	 * backend/storage/file/README.encryption.
	 *
	 * XXX Is this setting worth when we don't call EVP_EncryptFinal_ex()
	 * anyway? (Given the block_size==1, EVP_EncryptFinal_ex() wouldn't do
	 * anything.)
	 */
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	Assert(EVP_CIPHER_CTX_iv_length(ctx) == TWEAK_SIZE);
	Assert(EVP_CIPHER_CTX_key_length(ctx) == ENCRYPTION_KEY_LENGTH);
}

#endif							/* USE_ENCRYPTION */

#ifdef USE_ENCRYPTION
/*
 * Error callback for openssl.
 */
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
#endif							/* FRONTEND */
}
#endif							/* USE_ENCRYPTION */

/*
 * Xlog is encrypted page at a time. Each xlog page gets a unique tweak via
 * timeline, segment and offset.
 *
 * The function is located here rather than some of the xlog*.c modules so
 * that front-end applications can easily use it too.
 */
void
XLogEncryptionTweak(char *tweak, TimeLineID timeline, XLogSegNo segment,
					uint32 offset)
{
	memset(tweak, 0, TWEAK_SIZE);
	memcpy(tweak, &timeline, sizeof(timeline));
	tweak += sizeof(timeline);
	memcpy(tweak, &segment, sizeof(XLogSegNo));
	tweak += sizeof(XLogSegNo);
	memcpy(tweak, &offset, sizeof(offset));
}

/*
 * md files are encrypted block at a time. Tweak will alias higher numbered
 * forks for huge tables.
 */
void
mdtweak(char *tweak, RelFileNode *relnode, ForkNumber forknum, BlockNumber blocknum)
{
	uint32		fork_and_block = (forknum << 24) ^ blocknum;

	memcpy(tweak, relnode, sizeof(RelFileNode));
	memcpy(tweak + sizeof(RelFileNode), &fork_and_block, 4);
}

#ifndef FRONTEND
/*
 * Page LSN is used as initialization vector (IV) so encrypted page needs some
 * value here even if no real LSN is actually needed.
 *
 * Note that caller needs to restore InvalidXLogRecPtr after the write so that
 * it can be recognized later that the page needs to be treated specially.
 *
 * LW_SHARED on the buffer contents is sufficient because pd_lsn is not
 * expected to be used for other purposes (gaps in the sequence of fake LSNs
 * are fine).
 *
 * Returns true iff the LSN was updated.
 */
bool
EnforceLSNUpdateForEncryption(char	*buf_contents)
{
	PageHeader	hdr = (PageHeader) buf_contents;
	XLogRecPtr	recptr;

	/* Failure indicates incorrect user of the function. */
	Assert(data_encrypted);

	/*
	 * All-zero page shouldn't be encrypted, so don't care about the fake LSN.
	 */
	if (PageIsNew(hdr))
		return false;

	recptr = PageXLogRecPtrGet(hdr->pd_lsn);

	/*
	 * Valid LSN indicates that the relation is either logged or it's a page
	 * of unlogged GIST index. In either case we must not touch the LSN.
	 */
	if (!XLogRecPtrIsInvalid(recptr))
		return false;

	PageXLogRecPtrSet(hdr->pd_lsn, GetFakeLSNForUnloggedRel());

	return true;
}

/*
 * If EnforceLSNUpdateForEncryption() returned true and if the function can be
 * passed that buffer again, use this function to restore the
 * InvalidXLogRecPtr value.
 */
void
RestoreInvalidLSN(char	*buf_contents)
{
	PageHeader	hdr = (PageHeader) buf_contents;

	/* Failure indicates incorrect user of the function. */
	Assert(data_encrypted);

	PageXLogRecPtrSet(hdr->pd_lsn, (XLogRecPtr) InvalidXLogRecPtr);
}
#endif	/* FRONTEND */
