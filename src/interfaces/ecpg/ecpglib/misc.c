/* src/interfaces/ecpg/ecpglib/misc.c */

#define POSTGRES_ECPG_INTERNAL
#include "postgres_fe.h"

#include <limits.h>
#include <unistd.h>
#include "ecpg-pthread-win32.h"
#include "ecpgtype.h"
#include "ecpglib.h"
#include "ecpgerrno.h"
#include "extern.h"
#include "sqlca.h"
#include "pgtypes_numeric.h"
#include "pgtypes_date.h"
#include "pgtypes_timestamp.h"
#include "pgtypes_interval.h"
#include "pg_config_paths.h"

#ifdef HAVE_LONG_LONG_INT
#ifndef LONG_LONG_MIN
#ifdef LLONG_MIN
#define LONG_LONG_MIN LLONG_MIN
#else
#define LONG_LONG_MIN LONGLONG_MIN
#endif   /* LLONG_MIN */
#endif   /* LONG_LONG_MIN */
#endif   /* HAVE_LONG_LONG_INT */

bool		ecpg_internal_regression_mode = false;

static struct sqlca_t sqlca_init =
{
	{
		'S', 'Q', 'L', 'C', 'A', ' ', ' ', ' '
	},
	sizeof(struct sqlca_t),
	0,
	{
		0,
		{
			0
		}
	},
	{
		'N', 'O', 'T', ' ', 'S', 'E', 'T', ' '
	},
	{
		0, 0, 0, 0, 0, 0
	},
	{
		0, 0, 0, 0, 0, 0, 0, 0
	},
	{
		'0', '0', '0', '0', '0'
	}
};

#ifdef ENABLE_THREAD_SAFETY
static pthread_key_t sqlca_key;
static pthread_once_t sqlca_key_once = PTHREAD_ONCE_INIT;
#else
static struct sqlca_t sqlca =
{
	{
		'S', 'Q', 'L', 'C', 'A', ' ', ' ', ' '
	},
	sizeof(struct sqlca_t),
	0,
	{
		0,
		{
			0
		}
	},
	{
		'N', 'O', 'T', ' ', 'S', 'E', 'T', ' '
	},
	{
		0, 0, 0, 0, 0, 0
	},
	{
		0, 0, 0, 0, 0, 0, 0, 0
	},
	{
		'0', '0', '0', '0', '0'
	}
};
#endif

#ifdef ENABLE_THREAD_SAFETY
static pthread_mutex_t debug_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t debug_init_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static int	simple_debug = 0;
static FILE *debugstream = NULL;

void
ecpg_init_sqlca(struct sqlca_t * sqlca)
{
	memcpy((char *) sqlca, (char *) &sqlca_init, sizeof(struct sqlca_t));
}

bool
ecpg_init(const struct connection * con, const char *connection_name, const int lineno)
{
	struct sqlca_t *sqlca = ECPGget_sqlca();

	ecpg_init_sqlca(sqlca);
	if (con == NULL)
	{
		ecpg_raise(lineno, ECPG_NO_CONN, ECPG_SQLSTATE_CONNECTION_DOES_NOT_EXIST,
				   connection_name ? connection_name : ecpg_gettext("NULL"));
		return (false);
	}

	return (true);
}

#ifdef ENABLE_THREAD_SAFETY
static void
ecpg_sqlca_key_destructor(void *arg)
{
	free(arg);					/* sqlca structure allocated in ECPGget_sqlca */
}

static void
ecpg_sqlca_key_init(void)
{
	pthread_key_create(&sqlca_key, ecpg_sqlca_key_destructor);
}
#endif

struct sqlca_t *
ECPGget_sqlca(void)
{
#ifdef ENABLE_THREAD_SAFETY
	struct sqlca_t *sqlca;

	pthread_once(&sqlca_key_once, ecpg_sqlca_key_init);

	sqlca = pthread_getspecific(sqlca_key);
	if (sqlca == NULL)
	{
		sqlca = malloc(sizeof(struct sqlca_t));
		ecpg_init_sqlca(sqlca);
		pthread_setspecific(sqlca_key, sqlca);
	}
	return (sqlca);
#else
	return (&sqlca);
#endif
}

bool
ECPGstatus(int lineno, const char *connection_name)
{
	struct connection *con = ecpg_get_connection(connection_name);

	if (!ecpg_init(con, connection_name, lineno))
		return (false);

	/* are we connected? */
	if (con->connection == NULL)
	{
		ecpg_raise(lineno, ECPG_NOT_CONN, ECPG_SQLSTATE_ECPG_INTERNAL_ERROR, con->name);
		return false;
	}

	return (true);
}

PGTransactionStatusType
ECPGtransactionStatus(const char *connection_name)
{
	const struct connection *con;

	con = ecpg_get_connection(connection_name);
	if (con == NULL)
	{
		/* transaction status is unknown */
		return PQTRANS_UNKNOWN;
	}

	return PQtransactionStatus(con->connection);
}

static void
raise_xact_error(struct connection *con, int lineno, const char *name)
{
	con->client_side_error = true;
	ecpg_raise(lineno, ECPG_TRANS, ECPG_SQLSTATE_S_E_INVALID_SPECIFICATION,
					(name ? name : ecpg_gettext("<empty>")));
}

static bool
find_subxact(struct connection *con, int lineno, const char *name, bool ignore,
					struct subxact_descriptor **out)
{
	struct subxact_descriptor *desc = con->subxact_desc;
	bool    found = false;

	if (!name)
	{
		raise_xact_error(con, lineno, name);
		if (out)
			*out = NULL;
		return false;
	}

	while (desc)
	{
		int ret = pg_strcasecmp(desc->name, name);

		if (ret == 0)
		{
			found = true;
			break;
		}

		desc = desc->next;
	}

	if (!found && !ignore)
		raise_xact_error(con, lineno, name);
	if (out)
		*out = desc;
	return found;
}

static void
add_savepoint(struct connection *con, int lineno, const char *savepoint_name)
{
	struct subxact_descriptor *desc, *oldptr;

	oldptr = con->subxact_desc;
	desc = (struct subxact_descriptor *)
		ecpg_alloc(sizeof(struct subxact_descriptor), lineno);
	desc->level = (oldptr ? oldptr->level + 1 : 2);
	desc->name = ecpg_strdup(savepoint_name, lineno);
	desc->next = oldptr;
	con->subxact_desc = desc;
}

static void
release_savepoint(struct connection *con, struct subxact_descriptor *ptr, bool rollback)
{
	struct subxact_descriptor *desc, *next = NULL;

	desc = con->subxact_desc;
	while (desc != ptr)
	{
		next = desc->next;
		ecpg_free(desc->name);
		ecpg_free(desc);
		desc = next;
	}

	if (desc)
	{
		/* ROLLBACK TO SAVEPOINT leaves the savepoint in place */
		if (rollback)
			con->subxact_desc = desc;
		else
		{
			/* RELEASE SAVEPOINT forgets about the savepoint */
			con->subxact_desc = desc->next;
			ecpg_free(desc->name);
			ecpg_free(desc);
		}
	}
	else
		con->subxact_desc = NULL;
}

/*
 * ECPGtrans
 * Track (sub-)transactions by flags.
 * Parameters
 *	connection_name:	connection
 *	transaction:		the SQL string
 *	prepared:		prepared transaction or not
 *	begin:			start or finish transaction
 *	rollback:		if begin == true: commit or rollback
 *	savepoint_name:		NULL -> top level transaction,
 *				subtransaction otherwise
 *
 * The following table shows the combination of flags (x is ignored):
 * prepared | begin | rollback | savepoint_name | command
 * ---------+-------+----------+----------------+-----------------------
 *   false  | false |   false  |       NULL     | COMMIT
 *   false  | false |   false  |  valid pointer | RELEASE SAVEPOINT
 *   false  | false |   true   |       NULL     | ROLLBACK
 *   false  | false |   true   |  valid pointer | ROLLBACK TO SAVEPOINT
 *   false  | true  |     x    |       NULL     | BEGIN
 *   false  | true  |     x    |  valid pointer | SAVEPOINT
 *   true   | false |   false  |        x       | COMMIT PREPARED
 *   true   | false |   true   |        x       | ROLLBACK PREPARED
 *   true   | true  |     x    |        x       | PREPARE TRANSACTION
 */
bool
ECPGtrans(int lineno, const char *connection_name, const char *transaction,
				bool prepared, bool begin, bool rollback,
				const char *savepoint_name)
{
	PGresult   *res;
	struct connection *con = ecpg_get_connection(connection_name);
	bool		rollback_override = false;

	if (!ecpg_init(con, connection_name, lineno))
		return (false);

	if (con && (con->client_side_error || PQtransactionStatus(con->connection) == PQTRANS_INERROR))
	{
		/*
		 * Follow the backend behaviour for failed transactions:
		 * - override PREPARE TRANSACTION and COMMIT as ROLLBACK
		 *   so they don't fail
		 * - allow ROLLBACK and ROLLBACK TO SAVEPOINT to get through
		 * - emit "current transaction is aborted..." for everything else
		 */
		if ((prepared && begin) ||
				(!prepared && !begin && !rollback && savepoint_name == NULL))
		{
			transaction = "rollback";
			rollback_override = true;
		}
		else if (!(!prepared && !begin && rollback))
		{
			ecpg_raise(lineno, ECPG_TRANS, ECPG_SQLSTATE_IN_FAILED_SQL_TRANSACTION, NULL);
			return false;
		}
	}

	ecpg_log("ECPGtrans on line %d: action \"%s\"; connection \"%s\"\n", lineno, transaction, con ? con->name : "null");

	/* if we have no connection we just simulate the command */
	if (con && con->connection)
	{
		/*
		 * If we got a transaction command but have no open transaction, we
		 * have to start one, unless we are in autocommit, where the
		 * developers have to take care themselves. However:
		 * - if the command is a begin statement, we just execute it once
		 * - the command is COMMIT/ROLLBACK PREPARED, it must be executed
		 *   outside of a transaction.
		 */
		if (PQtransactionStatus(con->connection) == PQTRANS_IDLE && !con->autocommit &&
			/* exclude BEGIN */
			!(!prepared && begin && savepoint_name == NULL) &&
			/* exclude COMMIT/ROLLBACK PREPARED */
			!(prepared && !begin))
		{
			res = PQexec(con->connection, "begin transaction");
			if (!ecpg_check_PQresult(res, lineno, con->connection, ECPG_COMPAT_PGSQL))
				return false;
			PQclear(res);
		}

		res = PQexec(con->connection, transaction);
		if (!ecpg_check_PQresult(res, lineno, con->connection, ECPG_COMPAT_PGSQL))
			return false;
		PQclear(res);
	}

	if (con)
	{
		struct subxact_descriptor *desc;

		/* Simplify checking rollback conditions for ecpg_commit_cursors() later */
		if (rollback_override)
		{
			prepared = false;
			begin = false;
			rollback = true;
		}

		/*
		 * We keep track of subtransactions to be able to correctly
		 * account for transactional cursors as well.
		 */
		if (!prepared && savepoint_name)
		{
			int	level;

			if (begin)
			{
				/* SAVEPOINT nnn */
				if (find_subxact(con, lineno, savepoint_name, true, &desc))
				{
					/*
					 * SAVEPOINT nnn with an already existing savepoint name
					 * does an implicit RELEASE SAVEPOINT nnn
					 */
					level = desc->level;
					release_savepoint(con, desc, false);
					ecpg_commit_cursors(lineno, con, false, level);
				}

				add_savepoint(con, lineno, savepoint_name);
			}
			else
			{
				/*
				 * ROLLBACK TO / RELEASE SAVEPOINT nnn
				 *
				 * The above PQexec() already succeeded for savepoint_name
				 * but check for completeness anyway.
				 */
				if (!find_subxact(con, lineno, savepoint_name, false, &desc))
					return false;

				level = desc->level;
				release_savepoint(con, desc, rollback);
				ecpg_commit_cursors(lineno, con, rollback, level);
			}
		}
		/* Toplevel COMMIT / ROLLBACK */
		else if (!prepared && !begin && savepoint_name == NULL)
		{
			release_savepoint(con, NULL, rollback);
			ecpg_commit_cursors(lineno, con, rollback, 1);
		}

		/* At this point there's no error anymore. */
		con->client_side_error = false;
	}

	return true;
}


void
ECPGdebug(int n, FILE *dbgs)
{
#ifdef ENABLE_THREAD_SAFETY
	pthread_mutex_lock(&debug_init_mutex);
#endif

	if (n > 100)
	{
		ecpg_internal_regression_mode = true;
		simple_debug = n - 100;
	}
	else
		simple_debug = n;

	debugstream = dbgs;

	ecpg_log("ECPGdebug: set to %d\n", simple_debug);

#ifdef ENABLE_THREAD_SAFETY
	pthread_mutex_unlock(&debug_init_mutex);
#endif
}

void
ecpg_log(const char *format,...)
{
	va_list		ap;
	struct sqlca_t *sqlca = ECPGget_sqlca();
	const char *intl_format;
	int			bufsize;
	char	   *fmt;

	if (!simple_debug)
		return;

	/* internationalize the error message string */
	intl_format = ecpg_gettext(format);

	/*
	 * Insert PID into the format, unless ecpg_internal_regression_mode is set
	 * (regression tests want unchanging output).
	 */
	bufsize = strlen(intl_format) + 100;
	fmt = (char *) malloc(bufsize);
	if (fmt == NULL)
		return;

	if (ecpg_internal_regression_mode)
		snprintf(fmt, bufsize, "[NO_PID]: %s", intl_format);
	else
		snprintf(fmt, bufsize, "[%d]: %s", (int) getpid(), intl_format);

#ifdef ENABLE_THREAD_SAFETY
	pthread_mutex_lock(&debug_mutex);
#endif

	va_start(ap, format);
	vfprintf(debugstream, fmt, ap);
	va_end(ap);

	/* dump out internal sqlca variables */
	if (ecpg_internal_regression_mode)
		fprintf(debugstream, "[NO_PID]: sqlca: code: %ld, state: %s\n",
				sqlca->sqlcode, sqlca->sqlstate);

	fflush(debugstream);

#ifdef ENABLE_THREAD_SAFETY
	pthread_mutex_unlock(&debug_mutex);
#endif

	free(fmt);
}

void
ECPGset_noind_null(enum ECPGttype type, void *ptr)
{
	switch (type)
	{
		case ECPGt_char:
		case ECPGt_unsigned_char:
		case ECPGt_string:
			*((char *) ptr) = '\0';
			break;
		case ECPGt_short:
		case ECPGt_unsigned_short:
			*((short int *) ptr) = SHRT_MIN;
			break;
		case ECPGt_int:
		case ECPGt_unsigned_int:
			*((int *) ptr) = INT_MIN;
			break;
		case ECPGt_long:
		case ECPGt_unsigned_long:
		case ECPGt_date:
			*((long *) ptr) = LONG_MIN;
			break;
#ifdef HAVE_LONG_LONG_INT
		case ECPGt_long_long:
		case ECPGt_unsigned_long_long:
			*((long long *) ptr) = LONG_LONG_MIN;
			break;
#endif   /* HAVE_LONG_LONG_INT */
		case ECPGt_float:
			memset((char *) ptr, 0xff, sizeof(float));
			break;
		case ECPGt_double:
			memset((char *) ptr, 0xff, sizeof(double));
			break;
		case ECPGt_varchar:
			*(((struct ECPGgeneric_varchar *) ptr)->arr) = 0x00;
			((struct ECPGgeneric_varchar *) ptr)->len = 0;
			break;
		case ECPGt_decimal:
			memset((char *) ptr, 0, sizeof(decimal));
			((decimal *) ptr)->sign = NUMERIC_NULL;
			break;
		case ECPGt_numeric:
			memset((char *) ptr, 0, sizeof(numeric));
			((numeric *) ptr)->sign = NUMERIC_NULL;
			break;
		case ECPGt_interval:
			memset((char *) ptr, 0xff, sizeof(interval));
			break;
		case ECPGt_timestamp:
			memset((char *) ptr, 0xff, sizeof(timestamp));
			break;
		default:
			break;
	}
}

static bool
_check(unsigned char *ptr, int length)
{
	for (length--; length >= 0; length--)
		if (ptr[length] != 0xff)
			return false;

	return true;
}

bool
ECPGis_noind_null(enum ECPGttype type, void *ptr)
{
	switch (type)
	{
		case ECPGt_char:
		case ECPGt_unsigned_char:
		case ECPGt_string:
			if (*((char *) ptr) == '\0')
				return true;
			break;
		case ECPGt_short:
		case ECPGt_unsigned_short:
			if (*((short int *) ptr) == SHRT_MIN)
				return true;
			break;
		case ECPGt_int:
		case ECPGt_unsigned_int:
			if (*((int *) ptr) == INT_MIN)
				return true;
			break;
		case ECPGt_long:
		case ECPGt_unsigned_long:
		case ECPGt_date:
			if (*((long *) ptr) == LONG_MIN)
				return true;
			break;
#ifdef HAVE_LONG_LONG_INT
		case ECPGt_long_long:
		case ECPGt_unsigned_long_long:
			if (*((long long *) ptr) == LONG_LONG_MIN)
				return true;
			break;
#endif   /* HAVE_LONG_LONG_INT */
		case ECPGt_float:
			return (_check(ptr, sizeof(float)));
			break;
		case ECPGt_double:
			return (_check(ptr, sizeof(double)));
			break;
		case ECPGt_varchar:
			if (*(((struct ECPGgeneric_varchar *) ptr)->arr) == 0x00)
				return true;
			break;
		case ECPGt_decimal:
			if (((decimal *) ptr)->sign == NUMERIC_NULL)
				return true;
			break;
		case ECPGt_numeric:
			if (((numeric *) ptr)->sign == NUMERIC_NULL)
				return true;
			break;
		case ECPGt_interval:
			return (_check(ptr, sizeof(interval)));
			break;
		case ECPGt_timestamp:
			return (_check(ptr, sizeof(timestamp)));
			break;
		default:
			break;
	}

	return false;
}

#ifdef WIN32
#ifdef ENABLE_THREAD_SAFETY

void
win32_pthread_mutex(volatile pthread_mutex_t *mutex)
{
	if (mutex->handle == NULL)
	{
		while (InterlockedExchange((LONG *) &mutex->initlock, 1) == 1)
			Sleep(0);
		if (mutex->handle == NULL)
			mutex->handle = CreateMutex(NULL, FALSE, NULL);
		InterlockedExchange((LONG *) &mutex->initlock, 0);
	}
}

static pthread_mutex_t win32_pthread_once_lock = PTHREAD_MUTEX_INITIALIZER;

void
win32_pthread_once(volatile pthread_once_t *once, void (*fn) (void))
{
	if (!*once)
	{
		pthread_mutex_lock(&win32_pthread_once_lock);
		if (!*once)
		{
			*once = true;
			fn();
		}
		pthread_mutex_unlock(&win32_pthread_once_lock);
	}
}
#endif   /* ENABLE_THREAD_SAFETY */
#endif   /* WIN32 */

#ifdef ENABLE_NLS

char *
ecpg_gettext(const char *msgid)
{
	static bool already_bound = false;

	if (!already_bound)
	{
		/* dgettext() preserves errno, but bindtextdomain() doesn't */
#ifdef WIN32
		int			save_errno = GetLastError();
#else
		int			save_errno = errno;
#endif
		const char *ldir;

		already_bound = true;
		/* No relocatable lookup here because the binary could be anywhere */
		ldir = getenv("PGLOCALEDIR");
		if (!ldir)
			ldir = LOCALEDIR;
		bindtextdomain(PG_TEXTDOMAIN("ecpglib"), ldir);
#ifdef WIN32
		SetLastError(save_errno);
#else
		errno = save_errno;
#endif
	}

	return dgettext(PG_TEXTDOMAIN("ecpglib"), msgid);
}
#endif   /* ENABLE_NLS */

struct var_list *ivlist = NULL;

void
ECPGset_var(int number, void *pointer, int lineno)
{
	struct var_list *ptr;

	for (ptr = ivlist; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->number == number)
		{
			/* already known => just change pointer value */
			ptr->pointer = pointer;
			return;
		}
	}

	/* a new one has to be added */
	ptr = (struct var_list *) calloc(1L, sizeof(struct var_list));
	if (!ptr)
	{
		struct sqlca_t *sqlca = ECPGget_sqlca();

		sqlca->sqlcode = ECPG_OUT_OF_MEMORY;
		strncpy(sqlca->sqlstate, "YE001", sizeof(sqlca->sqlstate));
		snprintf(sqlca->sqlerrm.sqlerrmc, sizeof(sqlca->sqlerrm.sqlerrmc), "out of memory on line %d", lineno);
		sqlca->sqlerrm.sqlerrml = strlen(sqlca->sqlerrm.sqlerrmc);
		/* free all memory we have allocated for the user */
		ECPGfree_auto_mem();
	}
	else
	{
		ptr->number = number;
		ptr->pointer = pointer;
		ptr->next = ivlist;
		ivlist = ptr;
	}
}

void *
ECPGget_var(int number)
{
	struct var_list *ptr;

	for (ptr = ivlist; ptr != NULL && ptr->number != number; ptr = ptr->next);
	return (ptr) ? ptr->pointer : NULL;
}
