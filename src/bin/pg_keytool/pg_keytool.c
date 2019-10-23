/*-------------------------------------------------------------------------
 *
 * pg_keytool.c - Handle cluster encryption key.
 *
 * Copyright (c) 2013-2019, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		  src/bin/pg_keytool/pg_keytool.c
 *-------------------------------------------------------------------------
 */
/*
 * TODO Adopt the new frontend logging API, after some things are clarified:
 * https://www.postgresql.org/message-id/1939.1560773970%40localhost
 */
#define FRONTEND 1
#include "postgres.h"

#include <dirent.h>
#include <unistd.h>

#include "common/fe_memutils.h"
#include "common/logging.h"
#include "fe_utils/encryption.h"
#include "libpq-fe.h"
#include "libpq-int.h"
#include "libpq/pqcomm.h"
#include "port/pg_crc32c.h"
#include "storage/encryption.h"
#include "getopt_long.h"

#ifdef USE_ENCRYPTION
static const char *progname;

unsigned char encryption_key[ENCRYPTION_KEY_LENGTH];

static void
usage(const char *progname)
{
	const char *env;

	printf(_("%s is a tool to handle cluster encryption key.\n\n"),
		   progname);
	printf(_("Usage:\n"));
	printf(_("  %s [OPTION]...\n"), progname);
	printf(_("\nOptions:\n"));
	printf(_("  -D, --pgdata=DATADIR   data directory\n"));
	/* Display default host */
	env = getenv("PGHOST");
	printf(_("  -h, --host=HOSTNAME    database server host or socket directory (default: \"%s\")\n"),
			env ? env : _("local socket"));
	/* Display default port */
	env = getenv("PGPORT");
	printf(_("  -p, --port=PORT        database server port (default: \"%s\")\n"),
			env ? env : DEF_PGPORT_STR);
	printf(_("  -w                     expect password on input, not a key\n"));
	printf(_("  -?, --help             show this help, then exit\n\n"));
	printf(_("Password or key is read from stdin. Key is sent to PostgreSQL server being started\n"));
}
#endif							/* USE_ENCRYPTION */

int
main(int argc, char **argv)
{
/*
 * If no encryption library is linked, let the utility fail immediately. It'd
 * be weird if we reported incorrect usage just to say later that no useful
 * work can be done anyway.
 */
#ifdef USE_ENCRYPTION
	int			c;
	char		*host = NULL;
	char		*port_str = NULL;
	char	   *DataDir = NULL;
	bool		to_server = false;
	bool		expect_password = false;
	int			i, n;
	int			optindex;
	char		password[ENCRYPTION_PWD_MAX_LENGTH];
	char		key_chars[ENCRYPTION_KEY_CHARS];

	static struct option long_options[] =
	{
		{"pgdata", required_argument, NULL, 'D'},
		{"host", required_argument, NULL, 'h'},
		{"port", required_argument, NULL, 'p'},
		{NULL, 0, NULL, 0}
	};

	pg_logging_init(argv[0]);
	progname = get_progname(argv[0]);

	if (argc > 1)
	{
		if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0)
		{
			usage(progname);
			exit(0);
		}
		if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)
		{
			puts("pg_keytool (PostgreSQL) " PG_VERSION);
			exit(0);
		}
	}

	while ((c = getopt_long(argc, argv, "h:D:p:w",
							long_options, &optindex)) != -1)
	{
		switch (c)
		{
			case 'D':
				DataDir = optarg;
				break;

			case 'h':
				host = pg_strdup(optarg);
				break;

			case 'p':
				port_str = pg_strdup(optarg);
				break;

			case 'w':
				expect_password = true;
				break;

			case '?':
				/* Actual help option given */
				if (strcmp(argv[optind - 1], "-?") == 0)
				{
					usage(progname);
					exit(EXIT_SUCCESS);
				}

			default:
				pg_log_error("Try \"%s --help\" for more information.", progname);
				exit(1);
		}
	}

	/* Complain if any arguments remain */
	if (optind < argc)
	{
		fprintf(stderr, _("%s: too many command-line arguments (first is \"%s\")\n"),
				progname, argv[optind]);
		fprintf(stderr, _("Try \"%s --help\" for more information.\n"),
				progname);
		exit(1);
	}

	if (host || port_str)
	{
		/*
		 * We deliberately don't assume default values of host and port (which
		 * does not necessarily mean that we cannot read them from environment
		 * variables in future versions) to minimize the risk that the key is
		 * sent to wrong server.
		 */
		if (port_str == NULL)
		{
			pg_log_error("if host name is passed, port number must be passed too");
			exit(1);
		}
		else if (host == NULL)
		{
			pg_log_error("if port number is passed, host name must be passed too");
			exit(1);
		}

		to_server = true;
	}

#ifndef HAVE_UNIX_SOCKETS
	/*
	 * Since we currently cannot send the encryption key via SSL connection,
	 * the unix socket is the only secure channel to send the key.
	 *
	 * Maybe this limitation will be relaxed for Windows one day:
	 *
	 * https://www.postgresql.org/message-id/54bde68c-d134-4eb8-5bd3-8af33b72a010@2ndquadrant.com
	 */
	if (to_server)
	{
		pg_log_error("unix domain sockets not supported, cannot send key to server");
		exit(1);
	}
#endif

	if (to_server)
	{
#ifdef HAVE_UNIX_SOCKETS
		/*
		 * If no hostname is specified, libpq can use "localhost" as the
		 * default value if the OS does not support unix domain sockets. Since
		 * we currently cannot send the encryption key via SSL connection,
		 * such approach is not secure.
		 */
		if (host == NULL)
		{
			pg_log_error("host not specified");
			exit(1);
		}

		/*
		 * If connection via the unix socket is required, we only accept
		 * absolute path. Otherwise libpq could consider the string a host
		 * name and initiate TCP/IP connection.
		 */
		if (!is_absolute_path(host))
		{
			/*
			 * In fact the socket directory can be a relative path in
			 * postgresql.conf, but such would be considered a hostname by
			 * libpq.
			 */
			pg_log_error("\"%s\" does not look like an unix socket directory",
						 host);
			exit(1);
		}
#else  /* !HAVE_UNIX_SOCKETS */
		/* See above */
		Assert(false);
#endif /* HAVE_UNIX_SOCKETS */
	}

	/* Try to initialize DataDir using environment variable. */
	if (DataDir == NULL)
	{
		DataDir = getenv("PGDATA");
		if (DataDir)
			DataDir = pg_strdup(DataDir);
	}

	if (DataDir)
		canonicalize_path(DataDir);

	/*
	 * The KDF file is needed to derive the key from password, and this file
	 * is located in the data directory.
	 */
	if (expect_password && DataDir == NULL)
	{
		pg_log_error("%s: no data directory specified", progname);
		pg_log_error("Try \"%s --help\" for more information.", progname);
		exit(EXIT_FAILURE);
	}

	/*
	 * Read the credentials (key or password).
	 */
	n = 0;
	/* Key length in characters (two characters per hexadecimal digit) */
	while ((c = getchar()) != EOF && c != '\n')
	{
		if (!expect_password)
		{
			if (n >= ENCRYPTION_KEY_CHARS)
			{
				pg_log_error("The key is too long");
				exit(EXIT_FAILURE);
			}

			key_chars[n++] = c;
		}
		else
		{
			if (n >= ENCRYPTION_PWD_MAX_LENGTH)
			{
				pg_log_error("The password is too long");
				exit(EXIT_FAILURE);
			}

			password[n++] = c;
		}
	}

	/* If password was received, turn it into encryption key. */
	if (!expect_password)
	{
		if (n < ENCRYPTION_KEY_CHARS)
		{
			pg_log_error("The key is too short");
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < ENCRYPTION_KEY_LENGTH; i++)
		{
			if (sscanf(key_chars + 2 * i, "%2hhx", encryption_key + i) == 0)
			{
				pg_log_error("Invalid character in encryption key at position %d",
							 2 * i);
				exit(EXIT_FAILURE);
			}
		}
	}
	else
	{
		if (n < ENCRYPTION_PWD_MIN_LENGTH)
		{
			pg_log_error("The password is too short");
			exit(EXIT_FAILURE);
		}

		/* Read the KDF parameters. */
		read_kdf_file(DataDir);

		/* Run the KDF. */
		derive_key_from_password(encryption_key, password, n);
	}

	/*
	 * Send the encryption key either to stdout or to server.
	 */
	if (!to_server)
	{
		for (i = 0; i < ENCRYPTION_KEY_LENGTH; i++)
			printf("%.2x", encryption_key[i]);
		printf("\n");
	}
	else
	{
#ifdef HAVE_UNIX_SOCKETS
		/* XXX Try to find the postmaster PID? */
		if (!send_key_to_postmaster(host, port_str, encryption_key, 0))
			pg_log_error("could not send encryption key to server");
#else
		/* to_server should have caused early exit. */
		Assert(false);
#endif	/* HAVE_UNIX_SOCKETS */
	}

#else
	pg_log_fatal(ENCRYPTION_NOT_SUPPORTED_MSG);
	exit(EXIT_FAILURE);
#endif							/* USE_ENCRYPTION */
	return 0;
}
