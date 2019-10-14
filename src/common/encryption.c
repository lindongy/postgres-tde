#ifndef FRONTEND
#include "postgres.h"
#else
#include "postgres_fe.h"
#endif

#include "common/encryption.h"
#include "common/logging.h"

#ifdef USE_ENCRYPTION
#include <openssl/evp.h>

unsigned char encryption_key[ENCRYPTION_KEY_LENGTH];
#endif	/* USE_ENCRYPTION */

char	   *encryption_key_command = NULL;

/*
 * Run the command that is supposed to generate encryption key and store it
 * where encryption_key points to. If valid string is passed for data_dir,
 * it's used to replace '%D' pattern in the command.
 */
void
run_encryption_key_command(char *data_dir)
{
	FILE	   *fp;
	char	cmd[MAXPGPATH];
	char	*sp, *dp, *endp;

	Assert(encryption_key_command != NULL &&
		   strlen(encryption_key_command) > 0);

	/*
	 * Replace %D pattern in the command with the actual data directory path.
	 */
	dp = cmd;
	endp = cmd + MAXPGPATH - 1;
	*endp = '\0';
	for (sp = encryption_key_command; *sp; sp++)
	{
		if (*sp == '%')
		{
			if (sp[1] == 'D')
			{
				if (data_dir == NULL)
				{
#ifdef FRONTEND
					pg_log_fatal("data directory is not known, %%D pattern cannot be replaced");
					exit(EXIT_FAILURE);
#else
					ereport(FATAL,
							(errmsg("data directory is not known, %%D pattern cannot be replaced")));
#endif	/* FRONTEND */
				}

				sp++;
				strlcpy(dp, data_dir, endp - dp);
				make_native_path(dp);
				dp += strlen(dp);
			}
			else if (dp < endp)
				*dp++ = *sp;
			else
				break;
		}
		else
		{
			if (dp < endp)
				*dp++ = *sp;
			else
				break;
		}
	}
	*dp = '\0';

#ifdef FRONTEND
	pg_log_debug("executing encryption key command \"%s\"", cmd);
#else
	ereport(DEBUG1,
			(errmsg("executing encryption key command \"%s\"", cmd)));
#endif	/* FRONTEND */

	fp = popen(cmd, "r");
	if (fp == NULL)
	{
#ifdef FRONTEND
		pg_log_fatal("Failed to execute \"%s\"", cmd);
		exit(EXIT_FAILURE);
#else
		ereport(FATAL,
				(errmsg("Failed to execute \"%s\"", cmd)));
#endif	/* FRONTEND */
	}

	/* Read the key. */
	read_encryption_key_f(fp);

	pclose(fp);
}

/*
 * Read the encryption key from a file stream.
 */
void
read_encryption_key_f(FILE *f)
{
	char	   *buf;
	int		read_len, i, c;

	buf = (char *) palloc(ENCRYPTION_KEY_CHARS);

	read_len = 0;
	while ((c = fgetc(f)) != EOF && c != '\n')
	{
		if (read_len >= ENCRYPTION_KEY_CHARS)
		{
#ifdef FRONTEND
			pg_log_fatal("Encryption key is too long");
			exit(EXIT_FAILURE);
#else
			ereport(FATAL,
					(errmsg("Encryption key is too long")));
#endif	/* FRONTEND */
		}

		buf[read_len++] = c;
	}

	if (read_len < ENCRYPTION_KEY_CHARS)
	{
#ifdef FRONTEND
		pg_log_fatal("Encryption key is too short");
		exit(EXIT_FAILURE);
#else
		ereport(FATAL,
				(errmsg("Encryption key is too short")));
#endif	/* FRONTEND */
	}

	/* Turn the hexadecimal representation into an array of bytes. */
	for (i = 0; i < ENCRYPTION_KEY_LENGTH; i++)
	{
		if (sscanf(buf + 2 * i, "%2hhx", encryption_key + i) == 0)
		{
#ifdef FRONTEND
			pg_log_fatal("Invalid character in encryption key at position %d",
						 2 * i);
			exit(EXIT_FAILURE);
#else
			ereport(FATAL,
					(errmsg("Invalid character in encryption key at position %d",
							2 * i)));
#endif	/* FRONTEND */
		}
	}

	pfree(buf);
}
