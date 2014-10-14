/*
 * ECPG cursor support routines
 */

#define POSTGRES_ECPG_INTERNAL
#include "postgres_fe.h"

#include <stdlib.h>
#include <limits.h>

#include "ecpgtype.h"
#include "ecpglib.h"
#include "ecpgerrno.h"
#include "extern.h"

static bool	envvars_read = false;	/* the variables below are already
					   initialized */
static int	default_fetch_size = -1;/* use this value instead of the
					   passed-in per-cursor window size.
					   -1 means unset. */

static char *ecpg_cursor_direction_name[] = {
	"ECPGc_absolute",
	"ECPGc_relative",
	"ECPGc_forward",
	"ECPGc_backward",
	"ECPGc_absolute_in_var",
	"ECPGc_relative_in_var",
	"ECPGc_forward_in_var",
	"ECPGc_backward_in_var"
};

static char *ecpg_cursor_direction_sql_name[] = {
	"absolute",
	"relative",
	"forward",
	"backward",
	"absolute",
	"relative",
	"forward",
	"backward"
};

static bool ecpg_cursor_do_move_all(struct statement *stmt,
					struct cursor_descriptor *cur,
					enum ECPG_cursor_direction direction,
					int64 *return_pos);
static bool ecpg_cursor_move(struct statement *stmt,
					struct cursor_descriptor *cur,
					enum ECPG_cursor_direction direction,
					int64 amount, bool fetchall,
					bool do_override);
static bool ecpg_cursor_next_pos(struct statement *stmt,
					struct cursor_descriptor *cur,
					enum ECPG_cursor_direction direction, bool fetch,
					int64 amount, bool fetchall, long *qresult,
					int64 *next_pos_out, bool *next_atstart_out,
					bool *next_atend_out, bool *error, bool *beyond_known);

static void
raise_cursor_error(struct connection *con, int lineno, const char *name)
{
	con->client_side_error = true;
	ecpg_raise(lineno, ECPG_INVALID_CURSOR,
						ECPG_SQLSTATE_INVALID_CURSOR_NAME,
						(name ? name : ecpg_gettext("<empty>")));
}

/*
 * Find the cursor with the given name.
 * Optionally, return the previous one in the list.
 */
static bool
find_cursor(struct connection *con, int lineno, const char *name, bool ignore,
				struct cursor_descriptor **out,
				struct cursor_descriptor **out_prev)
{
	struct cursor_descriptor *desc = con->cursor_desc,
					*prev = NULL;
	int (* strcmp_fn)(const char *, const char *);
	bool	found = false;

	if (!name)
	{
		raise_cursor_error(con, lineno, name);
		if (out)
			*out = NULL;
		if (out_prev)
			*out_prev = NULL;
		return false;
	}

	/*
	 * This will ensure that:
	 * - quoted cursor names will be the first ones in the list ordered
	 *   case-sensitively
	 * - unquoted cursor names at the end, ordered case-insensitively.
	 */
	strcmp_fn = (name[0] == '"' ? strcmp : pg_strcasecmp);

	while (desc)
	{
		int ret = strcmp_fn(desc->name, name);

		if (ret == 0)
		{
			found = true;
			break;
		}
		/*
		 * The cursor list is ordered quasi alphabetically,
		 * don't search the whole list.
		 */
		if (ret > 0)
			break;
		prev = desc;
		desc = desc->next;
	}

	if (!found)
	{
		if (!ignore)
			raise_cursor_error(con, lineno, name);
		desc = NULL;
	}

	if (out)
		*out = desc;
	if (out_prev)
		*out_prev = prev;
	return found;
}

/*
 * Add a new cursor descriptor, maintain "mostly" alphabetic order.
 * - case sensitive alphabetic order for quoted cursor names
 * - case insensitive alphabetic order for non-quoted cursor names
 */
static struct cursor_descriptor *
add_cursor(int lineno, struct connection *con,
					const char *name,
					int subxact_level,
					bool with_hold,
					enum ECPG_cursor_scroll scrollable,
					long readahead)
{
	struct cursor_descriptor *desc, *prev;

	if (!name || name[0] == '\0')
		return NULL;

	if (find_cursor(con, lineno, name, true, &desc, &prev))
		return desc;

	desc = (struct cursor_descriptor *)
			ecpg_alloc(sizeof(struct cursor_descriptor),
								lineno);
	if (!desc)
		return NULL;

	/* Copy the name */
	desc->name = ecpg_strdup(name, lineno);
	if (!desc->name)
	{
		ecpg_free(desc);
		return NULL;
	}

	desc->subxact_level = subxact_level;
	desc->with_hold = with_hold;
	desc->scrollable = scrollable;
	desc->res = NULL;
	desc->readahead = readahead;
	desc->backward = false;
	desc->cache_start_pos = 0;
	desc->atstart = true;
	desc->atend = false;
	desc->pos = 0;
	desc->backend_atstart = true;
	desc->backend_atend = false;
	desc->backend_pos = 0;
	desc->mkbpos = 0;
	desc->mkbpos_is_last = false;

	if (prev)
	{
		desc->next = prev->next;
		prev->next = desc;
	}
	else
	{
		desc->next = con->cursor_desc;
		con->cursor_desc = desc;
	}

	return desc;
}

/*
 * Delete the cursor from the list of descriptors.
 */
static void
del_cursor(struct connection *con, int lineno, const char *name)
{
	struct cursor_descriptor *desc, *prev;

	if (find_cursor(con, lineno, name, true, &desc, &prev))
	{
		if (prev)
			prev->next = desc->next;
		else
			con->cursor_desc = desc->next;

		ecpg_free((void *)desc->name);
		PQclear(desc->res);
		ecpg_free(desc);
	}
}

/*
 * Commit or roll back cursors:
 * - all transactional (non-WITH HOLD) cursors are forgotten at
 *   the end of the transaction, no matter if COMMIT or ROLLBACK
 * - at RELEASE SAVEPOINT, the cursors are propagated one
 *   subtransaction level up.
 * - at ROLLBACK TO SAVEPOINT, all cursors are forgotten that were
 *   created in this subtransaction or below that level
 * - WITH HOLD cursors are kept after the transaction in case of
 *   toplevel COMMIT. The caller checks for the transaction in error
 *   and sets the rollback flag accordingly.
 */
void
ecpg_commit_cursors(int lineno, struct connection * conn,
						bool rollback, int level)
{
	struct cursor_descriptor *desc, *tmp,
					*prev = NULL;

	desc = conn->cursor_desc;
	while (desc)
	{
		/* Keep already COMMITted WITH HOLD cursors */
		if (desc->with_hold && desc->subxact_level == 0)
			;
		else if (rollback)
		{
			/*
			 * On ROLLBACK [ TO SAVEPOINT ... ] forget about
			 * every cursor DECLAREd under this level.
			 */
			if (desc->subxact_level >= level)
			{
				tmp = desc->next;
				ecpg_free(desc->name);
				PQclear(desc->res);
				ecpg_free(desc);
				desc = tmp;
				if (prev)
					prev->next = tmp;
				else
					conn->cursor_desc = tmp;
				continue;
			}
		}
		else
		{
			/*
			 * If this is a WITH HOLD cursor or we're in a
			 * subtransaction, COMMIT the cursor one level up.
			 */
			if (desc->with_hold || level > 1)
			{
				if (level > 0)
					desc->subxact_level = level - 1;
			}
			/*
			 * Otherwise (not WITH HOLD cursor AND it's the
			 * toplevel transaction) free the cursor.
			 */
			else
			{
				tmp = desc->next;
				ecpg_free(desc->name);
				PQclear(desc->res);
				ecpg_free(desc);
				desc = tmp;
				if (prev)
					prev->next = tmp;
				else
					conn->cursor_desc = tmp;
				continue;
			}
		}
		prev = desc;
		desc = desc->next;
	}
}

/*
 * Declare the cursor in the backend and create a descriptor to make tracking
 * and cursor readahead possible.
 *
 * This function is called when the ECPG code OPENs the cursor.
 */
bool
ECPGopen(const int lineno, const int compat, const int force_indicator,
			const char *connection_name, const bool questionmarks,
			const bool with_hold, enum ECPG_cursor_scroll scrollable,
			long readahead, const bool allow_ra_override, bool return_rssz,
			const char *curname, const int st, const char *query, ...)
{
	struct sqlca_t *sqlca = ECPGget_sqlca();
	struct connection *con = ecpg_get_connection(connection_name);
	struct statement *stmt;
	struct cursor_descriptor *cur;
	char	   *cmdstatus;
	int		subxact_level;
	va_list		args;

	if (curname == NULL)
	{
		ecpg_raise(lineno, ECPG_INVALID_CURSOR, ECPG_SQLSTATE_INVALID_CURSOR_NAME, ecpg_gettext("<empty>"));
		con->client_side_error = true;
		return false;
	}

	if (readahead < 1)
	{
		ecpg_raise(lineno, ECPG_INVALID_CURSOR, ECPG_SQLSTATE_INVALID_CURSOR_STATE, curname);
		con->client_side_error = true;
		return false;
	}

	/*
	 * Execute the DECLARE query in the backend.
	 */
	va_start(args, query);

	if (!ecpg_do_prologue(lineno, compat, force_indicator,
				connection_name, questionmarks,
				(enum ECPG_statement_type) st,
				query, args, &stmt))
	{
		ecpg_do_epilogue(stmt);
		va_end(args);
		return false;
	}

	va_end(args);

	if (!ecpg_build_params(stmt, false))
	{
		ecpg_do_epilogue(stmt);
		return false;
	}

	if (!ecpg_autostart_transaction(stmt))
	{
		ecpg_do_epilogue(stmt);
		return false;
	}

	if (!ecpg_execute(stmt))
	{
		ecpg_do_epilogue(stmt);
		return false;
	}

	cmdstatus = PQcmdStatus(stmt->results);
	if (strncmp(cmdstatus, "DECLARE CURSOR ", 15) == 0)
	{
		int	server_scrollable = atoi(cmdstatus + 15);

		if (server_scrollable)
			scrollable = ECPGcs_scroll;
		else
			scrollable = ECPGcs_no_scroll;
	}

	if (!ecpg_process_output(stmt, 0, PQntuples(stmt->results), LOOP_FORWARD, 0, true, false))
	{
		ecpg_do_epilogue(stmt);
		return false;
	}

	/* Process the environment variables only once */
	if (!envvars_read)
	{
		char	   *tmp, *endptr;
		long		fetch_size_env;

		/*
		 * If ECPGFETCHSZ is set, interpret it.
		 * - If invalid or unset, ignore. Leave default_fetch_size == -1
		 * - If ECPGFETCHSZ <= 0, caching is disabled (readahead = 1)
		 * - Otherwise use the actual number
		 */
		tmp = getenv("ECPGFETCHSZ");
		if (tmp)
		{
			fetch_size_env = strtol(tmp, &endptr, 10);
			if (*endptr)
				fetch_size_env = -1;
			else
			{
				/* Readahead disabled */
				if (fetch_size_env <= 0)
					fetch_size_env = 1;
			}
			default_fetch_size = fetch_size_env;
		}
		envvars_read = true;
	}

	/* Finally add the cursor to the connection. */
	if (con->subxact_desc)
		subxact_level = con->subxact_desc->level;
	else
		subxact_level =
			(PQtransactionStatus(con->connection) != PQTRANS_IDLE ?
										1 : 0);

	cur = add_cursor(lineno, con, curname, subxact_level, with_hold, scrollable,
					(allow_ra_override && default_fetch_size >= 1 ?
						default_fetch_size : readahead));

	/*
	 * Now discover the number of tuples in the result set only if:
	 * - the cursor is known scrollable, and
	 * - the user requested to return the number of tuples in
	 *   the result set.
	 * Although this slows down OPEN, for some loads caching
	 * still overweights it.
	 *
	 * One downside is the multiple evaluation of volatile functions
	 * and their possible side effects.
	 */
	if (scrollable == ECPGcs_scroll && return_rssz)
	{
		int64		return_pos;

		/*
		 * We are at the start of the result set,
		 * MOVE ALL returns the number of tuples in it.
		 */
		if (!ecpg_cursor_do_move_all(stmt, cur, ECPGc_forward, &return_pos))
		{
			del_cursor(con, lineno, curname);
			ecpg_do_epilogue(stmt);
			return false;
		}

		/* Go back to the beginning of the result set. */
		if (!ecpg_cursor_move(stmt, cur, ECPGc_absolute, 0, false, true))
		{
			del_cursor(con, lineno, curname);
			ecpg_do_epilogue(stmt);
			return false;
		}

		sqlca->sqlerrd[2] = (return_pos <= LONG_MAX ? return_pos : 0);
	}

	ecpg_do_epilogue(stmt);

	return true;
}

/*
 * Canonicalize the amount of cursor movement.
 */
static bool
ecpg_canonical_cursor_movement(enum ECPG_cursor_direction *direction, const char *amount,
				bool *fetchall, int64 *amount_out)
{
	bool		negate = false;
	int64		amount1;

	/*
	 * We might have got a constant string from the grammar.
	 * We have to handle the negative and explicitely positive constants
	 * here because e.g. '-2' arrives as '- 2' from the grammar.
	 * strtoll() under Linux stops processing at the space.
	 */
	if (amount[0] == '-' || amount[0] == '+')
	{
		negate = (amount[0] == '-');
		amount++;
		while (*amount == ' ')
			amount++;
	}

	/* FETCH/MOVE [ FORWARD | BACKWARD ] ALL */
	if (strcmp(amount, "all") == 0)
	{
		*fetchall = true;
		amount1 = 0;
	}
	else
	{
		char	   *endptr;

		amount1 = strtoll(amount, &endptr, 10);

		if (*endptr)
			return false;

		if (negate)
			amount1 = -amount1;
		*fetchall = false;
	}

	/*
	 * Canonicalize ECPGc_backward but don't lose
	 * FETCH BACKWARD ALL and FETCH BACKWARD 0 semantics.
	 */
	if ((*fetchall == false) && (amount != 0) && (*direction == ECPGc_backward))
	{
		amount1 = -amount1;
		*direction = ECPGc_forward;
	}

	*amount_out = amount1;
	return true;
}

/*
 * ecpg_cursor_do_move_all
 */
static bool
ecpg_cursor_do_move_all(struct statement *stmt, struct cursor_descriptor *cur,
					enum ECPG_cursor_direction direction,
					int64 *ntuples)
{
	bool		error;
	char	   *cmdstatus;

	if ((direction == ECPGc_forward && cur->backend_atend) ||
		(direction == ECPGc_backward && cur->backend_atstart))
	{
		*ntuples = llabs(cur->backend_pos - cur->pos) - 1;
		return true;
	}

	ecpg_log("ecpg_cursor_do_move_all on line %d: %s current positions: pos %lld atstart %d atend %d backend_pos %lld bkatstart %d bkatend %d mkbpos_is_last %d mkbpos %lld\n",
			stmt->lineno, ecpg_cursor_direction_name[direction],
			(long long)cur->pos, cur->atstart, cur->atend,
			(long long)cur->backend_pos, cur->backend_atstart, cur->backend_atend,
			cur->mkbpos_is_last, (long long)cur->mkbpos);

	ecpg_free(stmt->command);

	stmt->command = ecpg_alloc(strlen(cur->name) + 24, stmt->lineno);
	if (stmt->command == NULL)
		return false;
	sprintf(stmt->command, "move %s all in %s", ecpg_cursor_direction_sql_name[direction], cur->name);

	if (!ecpg_execute(stmt))
		return false;

	cmdstatus = PQcmdStatus(stmt->results);
	*ntuples = atol(cmdstatus + 5);

	PQclear(stmt->results);
	stmt->results = NULL;

	ecpg_cursor_next_pos(stmt, cur, direction, false, 0, true, ntuples,
				&cur->pos, &cur->atstart, &cur->atend, &error, NULL);
	cur->backend_pos = cur->pos;
	cur->backend_atstart = cur->atstart;
	cur->backend_atend = cur->atend;

	ecpg_log("ecpg_cursor_do_move_all on line %d: after: bkatstart %d bkatend %d backend_pos %lld atstart %d atend %d pos %lld return_pos %lld\n",
		stmt->lineno, cur->backend_atstart, cur->backend_atend, (long long)cur->backend_pos, cur->atstart, cur->atend, (long long)cur->pos, (long long) *ntuples);

	return true;
}

/*
 * ecpg_cursor_do_move_absolute
 *
 * Called in case of uncertainty to exactly track the
 * cursor position in the backend.
 *
 * Only called for nonzero "amount" values.
 */
static bool
ecpg_cursor_do_move_absolute(struct statement *stmt, struct cursor_descriptor *cur,
					int64 amount, int64 *return_pos)
{
	char		amount_s[64];
	bool		error;
	char	   *cmdstatus;
	long		have_tuple;

	ecpg_log("ecpg_cursor_do_move_absolute on line %d: amount %lld\n",
			stmt->lineno, (long long)amount);

	ecpg_free(stmt->command);

	sprintf(amount_s, "%lld", (long long)amount);
	stmt->command = ecpg_alloc(strlen(amount_s) + strlen(cur->name) + 20, stmt->lineno);
	if (stmt->command == NULL)
		return false;
	sprintf(stmt->command, "move absolute %s in %s", amount_s, cur->name);

	if (!ecpg_execute(stmt))
		return false;

	cmdstatus = PQcmdStatus(stmt->results);
	*return_pos = have_tuple = (cmdstatus[5] == '1');
	ecpg_log("ecpg_cursor_do_move_absolute on line %d: cmdstatus '%s', have_tuple %ld\n",
			stmt->lineno, cmdstatus, have_tuple);

	PQclear(stmt->results);
	stmt->results = NULL;

	ecpg_cursor_next_pos(stmt, cur, ECPGc_absolute, false, amount, false, &have_tuple,
				&cur->pos, &cur->atstart, &cur->atend, &error, NULL);

	cur->backend_pos = cur->pos;
	cur->backend_atstart = cur->atstart;
	cur->backend_atend = cur->atend;

	return true;
}

/*
 * ecpg_cursor_do_move_relative
 *
 * Called in case of uncertainty to exactly track the
 * cursor position in the backend.
 *
 * Only called for nonzero "amount" values.
 */
static bool
ecpg_cursor_do_move_relative(struct statement *stmt, struct cursor_descriptor *cur,
					int64 amount, int64 *return_pos)
{
	char		amount_s[64];
	bool		error;
	char	   *cmdstatus;
	long		have_tuple;

	ecpg_log("ecpg_cursor_do_move_relative on line %d: amount %lld\n",
			stmt->lineno, (long long)amount);

	if (cur->pos != cur->backend_pos)
	{
		if (cur->atend)
		{
			if (!ecpg_cursor_do_move_all(stmt, cur, ECPGc_forward, return_pos))
				return false;
		}
		else if (cur->atstart)
		{
			if (!ecpg_cursor_do_move_all(stmt, cur, ECPGc_backward, return_pos))
				return false;
		}
		else
		{
			if (!ecpg_cursor_do_move_absolute(stmt, cur, cur->pos, return_pos))
				return false;
		}
	}

	ecpg_free(stmt->command);

	sprintf(amount_s, "%lld", (long long)amount);
	stmt->command = ecpg_alloc(strlen(amount_s) + strlen(cur->name) + 20, stmt->lineno);
	if (stmt->command == NULL)
		return false;
	sprintf(stmt->command, "move relative %s in %s", amount_s, cur->name);

	if (!ecpg_execute(stmt))
		return false;

	cmdstatus = PQcmdStatus(stmt->results);
	*return_pos = have_tuple = (cmdstatus[5] == '1');
	ecpg_log("ecpg_cursor_do_move_relative on line %d: cmdstatus '%s', have_tuple %ld\n", stmt->lineno, cmdstatus, have_tuple);

	PQclear(stmt->results);
	stmt->results = NULL;

	ecpg_cursor_next_pos(stmt, cur, ECPGc_relative, false, amount, false, &have_tuple,
				&cur->pos, &cur->atstart, &cur->atend, &error, NULL);

	cur->backend_pos = cur->pos;
	cur->backend_atstart = cur->atstart;
	cur->backend_atend = cur->atend;

	return true;
}

/*
 * ecpg_cursor_do_move_forward
 *
 * Called in case of uncertainty to exactly track the
 * cursor position in the backend.
 *
 * Only called for nonzero "amount" values.
 */
static bool
ecpg_cursor_do_move_forward(struct statement *stmt, struct cursor_descriptor *cur,
					int64 amount, int64 *return_pos)
{
	char		amount_s[64];
	bool		error;
	char	   *cmdstatus;
	long		ntuples;

	ecpg_log("ecpg_cursor_do_move_forward on line %d: amount %lld\n",
			stmt->lineno, (long long)amount);

	if (cur->pos != cur->backend_pos)
	{
		if (cur->atend)
		{
			if (!ecpg_cursor_do_move_all(stmt, cur, ECPGc_forward, return_pos))
				return false;
		}
		else if (cur->atstart)
		{
			if (!ecpg_cursor_do_move_all(stmt, cur, ECPGc_backward, return_pos))
				return false;
		}
		else
		{
			if (!ecpg_cursor_do_move_absolute(stmt, cur, cur->pos, return_pos))
				return false;
		}
	}

	ecpg_free(stmt->command);

	sprintf(amount_s, "%lld", (long long)amount);
	stmt->command = ecpg_alloc(strlen(amount_s) + strlen(cur->name) + 20, stmt->lineno);
	if (stmt->command == NULL)
		return false;
	sprintf(stmt->command, "move forward %s in %s", amount_s, cur->name);

	if (!ecpg_execute(stmt))
		return false;

	cmdstatus = PQcmdStatus(stmt->results);
	*return_pos = ntuples = atol(cmdstatus + 5);
	ecpg_log("ecpg_cursor_do_move_forward on line %d: cmdstatus '%s', ntuples %ld\n", stmt->lineno, cmdstatus, ntuples);

	ecpg_cursor_next_pos(stmt, cur, ECPGc_forward, false, amount, false, &ntuples,
				&cur->pos, &cur->atstart, &cur->atend, &error, NULL);

	cur->backend_pos = cur->pos;
	cur->backend_atstart = cur->atstart;
	cur->backend_atend = cur->atend;

	return true;
}

/*
 * ecpg_cursor_negate_position
 *
 * If the number of tuples is already known for the whole
 * result set, recompute the specified position so it's
 * numeric sign matches the current cur->pos.
 */
static void
ecpg_cursor_negate_position(struct cursor_descriptor *cur, int64 *pos)
{
	if (cur->mkbpos_is_last)
	{
		int64		lpos = *pos;

		if ((cur->pos < 0 || (cur->atend  && cur->pos == 0)) && lpos > 0)
			lpos = lpos - cur->mkbpos - 1;
		else if ((cur->pos > 0 || (cur->atstart && cur->pos == 0)) && lpos < 0)
			lpos = lpos + cur->mkbpos + 1;

		*pos = lpos;
	}
}

/*
 * ecpg_cursor_move
 *
 * Save network turnaround of MOVE statements as much as possible.
 *
 * Compute the cursor position here for the application instead and send a
 * MOVE ABSOLUTE to the server before the first FETCH in ecpg_cursor_execute()
 * in case the cursor position known by the server and the application are
 * different.
 *
 * At all times, cur->pos and cur->backend_pos are assumed to use the same
 * sign (both are either >=0 or <=0) and end up having the same sign at the
 * end.
 *
 * Also, cur->atstart and cur->atend is assumed to be correctly set and
 * end up to be correctly set.
 *
 * Having any of cur->atstart and cur->atend set while the size of
 * the cursor result set is unknown at the start of implies cur->pos == 0
 * and ends up so.
 *
 * Any shortcut taken means the cur->pos will deviate from cur->backend_pos
 * and possibly a MOVE statement is saved.
 */
static bool
ecpg_cursor_move(struct statement *stmt, struct cursor_descriptor *cur,
					enum ECPG_cursor_direction direction,
					int64 amount, bool fetchall,
					bool do_override)
{
	struct sqlca_t *sqlca = ECPGget_sqlca();
	bool		next_atstart, next_atend, error, beyond_known;
	int64		next_pos;
	int64		return_pos = 0;

	ecpg_log("ecpg_cursor_move on line %d: %s %lld fetchall %d current positions: pos %lld atstart %d atend %d backend_pos %lld bkatstart %d bkatend %d mkbpos_is_last %d mkbpos %lld\n",
			stmt->lineno, ecpg_cursor_direction_name[direction], (long long)amount, fetchall,
			(long long)cur->pos, cur->atstart, cur->atend,
			(long long)cur->backend_pos, cur->backend_atstart, cur->backend_atend,
			cur->mkbpos_is_last, (long long)cur->mkbpos);

	sqlca->sqlerrd[2] = 0;

	switch (direction)
	{
	case ECPGc_absolute:
		return_pos = -1;
		if (ecpg_cursor_next_pos(stmt, cur, direction, false,
					 amount, fetchall, &return_pos,
					 &next_pos, &next_atstart, &next_atend,
					 &error, &beyond_known))
		{
			if (error)
				return false;

			if (!beyond_known)
			{
				cur->pos = next_pos;
				cur->atstart = next_atstart;
				cur->atend = next_atend;
				break;
			}
		}

		/*
		 * The application moves beyond the currently known
		 * last position, discovery cannot be avoided
		 * in order to exactly track the cursor position.
		 */
		if (!ecpg_cursor_do_move_absolute(stmt, cur, amount, &return_pos))
		{
			/*
			 * If neither SCROLL nor NO SCROLL was specified,
			 * this query failed, so the cursor proved to be
			 * non-scrollable.
			 */
			if (cur->scrollable == ECPGcs_unspecified && amount < 0)
			{
				ecpg_log("ecpg_cursor_move on line %d: ECPGc_absolute ECPGcs_unspecified -> ECPGcs_no_scroll\n", stmt->lineno);
				cur->scrollable = ECPGcs_no_scroll;
			}
			return false;
		}
		cur->scrollable = ECPGcs_scroll;

		break;

	case ECPGc_relative:
		return_pos = -1;
		if (ecpg_cursor_next_pos(stmt, cur, direction, false,
					 amount, fetchall, &return_pos,
					 &next_pos, &next_atstart, &next_atend,
					 &error, &beyond_known))
		{
			if (error)
				return false;

			if (!beyond_known)
			{
				cur->pos = next_pos;
				cur->atstart = next_atstart;
				cur->atend = next_atend;
				break;
			}
		}

		/*
		 * The application moves beyond the currently known
		 * last position, discovery cannot be avoided
		 * in order to exactly track the cursor position.
		 */
		if (!ecpg_cursor_do_move_relative(stmt, cur, amount, &return_pos))
		{
			/*
			 * If neither SCROLL nor NO SCROLL was specified,
			 * this query failed, so the cursor proved to be
			 * non-scrollable.
			 */
			if (cur->scrollable == ECPGcs_unspecified && amount < 0)
			{
				ecpg_log("ecpg_cursor_move on line %d: ECPGc_absolute ECPGcs_unspecified -> ECPGcs_no_scroll\n", stmt->lineno);
				cur->scrollable = ECPGcs_no_scroll;
			}
			return false;
		}
		cur->scrollable = ECPGcs_scroll;

		break;

	case ECPGc_forward:
	case ECPGc_backward:
		/*
		 * Handle all of MOVE [BACKWARD|FORWARD] ALL cases here.
		 *
		 * After canonicalization, ECPGc_backward shows up only
		 * when BACKWARD ALL/BACKWARD 0 was specified.
		 *
		 * MOVE BACKWARD ALL is allowed for NO SCROLL cursors,
		 * it simply restarts the scanning.
		 */

		return_pos = -1;
		if (ecpg_cursor_next_pos(stmt, cur, direction, false,
					 amount, fetchall, &return_pos,
					 &next_pos, &next_atstart, &next_atend,
					 &error, &beyond_known))
		{
			if (error)
				return false;

			if (!beyond_known)
			{
				cur->pos = next_pos;
				cur->atstart = next_atstart;
				cur->atend = next_atend;
				break;
			}
		}


		/*
		 * Use this opportunity to discover the size of the
		 * result set.
		 */
		if (fetchall)
		{
			if (!ecpg_cursor_do_move_all(stmt, cur, direction, &return_pos))
				return false;
		}
		else
		{
			if (!ecpg_cursor_do_move_forward(stmt, cur, amount, &return_pos))
				return false;
		}

		break;

	default:
		/*
		 * The ECPGc_*_in_var variants cannot occur here.
		 */
		ecpg_raise(stmt->lineno, ECPG_INVALID_CURSOR,
					ECPG_SQLSTATE_ECPG_INTERNAL_ERROR,
					NULL);
		return false;
	}

	sqlca->sqlerrd[2] = (return_pos <= LONG_MAX ? return_pos : 0);

	ecpg_cursor_negate_position(cur, &cur->backend_pos);
	ecpg_cursor_negate_position(cur, &cur->cache_start_pos);

	ecpg_log("ecpg_cursor_move on line %d: final positions: pos %lld atstart %d atend %d backend_pos %lld bkatstart %d bkatend %d mkbpos_is_last %d mkbpos %lld return_pos %lld\n",
			stmt->lineno, (long long)cur->pos, cur->atstart, cur->atend, (long long)cur->backend_pos, cur->backend_atstart, cur->backend_atend,
			cur->mkbpos_is_last, (long long)cur->mkbpos, (long long)return_pos);

	return true;
}

/*
 * ecpg_cursor_execute
 * Execute the next FETCH statement if needed.
 * 
 */
static bool
ecpg_cursor_execute(struct statement * stmt, struct cursor_descriptor *cur,
					bool backward, int64 next_pos,
					bool next_atstart, bool next_atend)
{
	bool		do_fetch = true;
	int		step;

	ecpg_log("ecpg_cursor_execute on line %d: current positions: pos %lld atstart %d atend %d backend_pos %lld bkatstart %d bkatend %d mkbpos_is_last %d mkbpos %lld\n",
			stmt->lineno, 
			(long long)cur->pos, cur->atstart, cur->atend,
			(long long)cur->backend_pos, cur->backend_atstart, cur->backend_atend,
			cur->mkbpos_is_last, (long long)cur->mkbpos);

	ecpg_log("ecpg_cursor_execute on line %d: next position: next_pos %lld next_atstart %d next_atend %d backward %d\n",
			stmt->lineno, (long long)next_pos, next_atstart, next_atend, backward);

	/*
	 * The application have fallen off the cursors's result set,
	 * in which the number of tuples is an integer multiple of
	 * the readahead window size (or the application started to
	 * read from a position that the cache ended up empty.
	 * Don't read any further and don't count it as a cache-miss
	 * either.
	 */
	if (next_atstart && backward)
	{
		ecpg_log("ecpg_cursor_execute on line %d: atstart triggers no fetch\n", stmt->lineno);
		do_fetch = false;
	}
	else if (next_atend && !backward)
	{
		ecpg_log("ecpg_cursor_execute on line %d: atend triggers no fetch\n", stmt->lineno);
		do_fetch = false;
	}
	else if (cur->res != NULL)
	{
		int		ntuples = PQntuples(cur->res);

		/*
		 * Check the conditions when the cache has to be filled
		 * up by a new FETCH command.
		 */
		ecpg_cursor_negate_position(cur, &cur->cache_start_pos);
		ecpg_cursor_negate_position(cur, &cur->backend_pos);

		/*
		 * If the numeric sign of cur->cache_start_pos matches cur->pos,
		 * the next tuple may already be in the cache.
		 */
		if ( ((next_pos < 0 || (next_atend  && next_pos == 0)) && cur->cache_start_pos < 0) ||
		     ((next_pos > 0 || (next_atstart && next_pos == 0)) && cur->cache_start_pos > 0) )
		{
			int64		start_pos, end_pos;

			if (cur->backward)
			{
				start_pos = cur->cache_start_pos - ntuples + 1;
				end_pos = cur->cache_start_pos;
			}
			else
			{
				start_pos = cur->cache_start_pos;
				end_pos = cur->cache_start_pos + ntuples - 1;
			}

			ecpg_log("ecpg_cursor_execute on line %d: start_pos %lld end_pos %lld cur->backward %d next_pos %lld next_atstart %d next_atend %d backward %d\n",
				stmt->lineno, (long long)start_pos, (long long)end_pos, cur->backward, (long long)next_pos, next_atstart, next_atend, backward);

			/*
			 * The next tuple to be fetched is in the cache.
			 */
			if ((start_pos <= next_pos) && (next_pos <= end_pos))
			{
				ecpg_log("ecpg_cursor_execute on line %d: position in cache triggers no fetch\n", stmt->lineno);
				do_fetch = false;
			}
			/*
			 * The next tuple to be fetched is over the cache and
			 * the cache is already at the edge of the result set.
			 */
			else if ((ntuples > 0) && (ntuples < cur->readahead) && (backward == cur->backward) &&
				((((next_pos < 0) || next_atend) && (next_pos < start_pos)) ||
				 (((next_pos > 0) || next_atstart) && (next_pos > end_pos))))
			{
				ecpg_log("ecpg_cursor_execute on line %d: position past end triggers no fetch: cache params start_pos %lld ntuples %d backward %d\n",
						stmt->lineno, (long long)cur->cache_start_pos, ntuples, cur->backward);
				do_fetch = false;
			}
		}
	}

	if (do_fetch)
	{
		int		ntuples;
		char		amount[64];

		ecpg_log("ecpg_cursor_execute on line %d: do_fetch bkatstart %d bkatend %d backend_pos %lld\n",
				stmt->lineno, cur->backend_atstart, cur->backend_atend, (long long)cur->backend_pos);

		if (cur->pos != cur->backend_pos)
		{
			int64		return_pos;

			if (cur->pos == 0 && cur->atend)
			{
				if (!ecpg_cursor_do_move_all(stmt, cur, ECPGc_forward, &return_pos))
					return false;
			}
			else
			{
				if (!ecpg_cursor_do_move_absolute(stmt, cur, cur->pos, &return_pos))
					return false;
			}
		}

		ecpg_free(stmt->command);

		sprintf(amount, "%lld", (long long)cur->readahead);
		stmt->command = ecpg_alloc(strlen(amount) + strlen(cur->name) + 24, stmt->lineno);
		if (stmt->command == NULL)
			return false;
		sprintf(stmt->command, "fetch %s %s from %s",
						(backward ? "backward" : "forward"),
						amount, cur->name);

		PQclear(cur->res);

		if (!ecpg_execute(stmt))
			return false;

		cur->res = stmt->results;

		ntuples = PQntuples(cur->res);

		ecpg_log("ecpg_cursor_execute on line %d: after fetch ntuples %d backward %d bkatstart %d bkatend %d backend_pos %lld\n",
				stmt->lineno, ntuples, backward, cur->backend_atstart, cur->backend_atend, (long long)cur->backend_pos);

		step = (backward ? -1 : 1);
		if ((cur->backend_atstart && backward) || (cur->backend_atend && !backward))
			cur->cache_start_pos = cur->backend_pos;
		else
			cur->cache_start_pos = cur->backend_pos + step;
		cur->backward = backward;
		cur->backend_pos += ntuples * step;

		if (llabs(cur->backend_pos) >= cur->mkbpos)
		{
			cur->mkbpos = llabs(cur->backend_pos);
			ecpg_log("ecpg_cursor_execute on line %d: mkbpos set %lld\n", stmt->lineno, (long long)cur->mkbpos);
		}
		if (ntuples < cur->readahead)
		{
			/*
			 * The cursor has moved to the start or the end:
			 * backend_pos will be either 0 or
			 * +/- (PQntuples(whole_results_set)+1)
			 * In the latter case we can adjust the maximum known
			 * backend position and mark it as the last.
			 */
			cur->mkbpos_is_last = true;
			ecpg_log("ecpg_cursor_execute on line %d: mkbpos_is_last is set\n", stmt->lineno);

			/* But don't go over zero. */
			if (cur->backend_pos != 0)
				cur->backend_pos += step;

			cur->backend_atstart = backward;
			cur->backend_atend = !backward;
		}
		else
		{
			cur->backend_atstart = false;
			cur->backend_atend = false;
		}

		cur->cache_miss++;

		ecpg_log("ecpg_cursor_execute on line %d: cache populated start_pos %lld ntuples %d backward %d mkbpos %lld\n", stmt->lineno, (long long)cur->cache_start_pos, ntuples, cur->backward, (long long)cur->mkbpos);
	}
	else
	{
		stmt->results = cur->res;
		cur->cache_miss = 0;
		ecpg_log("ecpg_cursor_execute on line %d: tuple already in cache start_pos %lld ntuples %d backward %d mkbpos %lld\n",
				stmt->lineno, (long long)cur->cache_start_pos, PQntuples(cur->res), cur->backward, (long long)cur->mkbpos);
	}

	return true;
}

/*
 * ecpg_cursor_next_pos
 * The big unified function to get the next cursor position.
 *
 * Early processing checks for NO SCROLL cursor and returns true
 * together with *error = true, raising the proper ECPG error.
 *
 * Possible values of *qresult:
 * -1:
 *	Unknown. Set the position if the range is already known.
 *	Return true and set *qresult relative to cur->pos if the range
 *	is already known.
 * 0 and up:
 *	*qresult was returned by a actual query sent to the server.
 *	Set the new position according to it. *qresult may be
 *	modified if the cur->pos and cur->backend_pos are different.
 *	Return unconditionally false in this case
 * Also return false for invalid "direction" values (which cannot happen).
 */
static bool
ecpg_cursor_next_pos(struct statement *stmt, struct cursor_descriptor *cur,
			enum ECPG_cursor_direction direction, bool fetch,
			int64 amount, bool fetchall, long *qresult,
			int64 *next_pos_out, bool *next_atstart_out,
			bool *next_atend_out, bool *error, bool *beyond_known)
{
	int64		wanted_pos, next_pos, fetchall_step = 0;
	long		lresult = *qresult;
	bool		next_atstart, next_atend;
	bool		edge_on_backward, edge_on_forward;

	ecpg_log("ecpg_cursor_next_pos on line %d: %s %lld (%ld) current positions: pos %lld atstart %d atend %d backend_pos %lld bkatstart %d bkatend %d mkbpos_is_last %d mkbpos %lld\n",
			stmt->lineno, ecpg_cursor_direction_name[direction], (long long) amount, lresult,
			(long long)cur->pos, cur->atstart, cur->atend,
			(long long)cur->backend_pos, cur->backend_atstart, cur->backend_atend,
			cur->mkbpos_is_last, (long long)cur->mkbpos);

	if (qresult)
		*qresult = -1; /* invalid value */
	if (error)
		*error = false;
	if (beyond_known)
		*beyond_known = false;

	if (cur->scrollable == ECPGcs_no_scroll)
	{
		if ((amount < 0) ||
			(fetch && amount == 0 && direction == ECPGc_backward))
		{
			ecpg_raise(stmt->lineno, ECPG_INVALID_CURSOR,
						ECPG_SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
						cur->name);
			stmt->connection->client_side_error = true;
			if (error)
				*error = true;
			return true;
		}
	}

	next_atstart = next_atend = false;
	edge_on_backward = edge_on_forward = false;

	switch (direction)
	{
	case ECPGc_absolute:
		wanted_pos = amount;
		next_atstart = (amount == 0);
		ecpg_log("ecpg_cursor_next_pos on line %d: %s set wanted_pos %lld\n",
				stmt->lineno, ecpg_cursor_direction_name[direction], (long long)wanted_pos);
		break;

	case ECPGc_backward:
		/*
		 * ECPGc_backward must only occur with BACKWARD ALL.
		 * Anyway, report the error and do the sensible thing.
		 */
		if (!fetchall)
		{
			ecpg_log("ecpg_cursor_next_pos on line %d: %s occured without fetchall set\n",
					stmt->lineno, ecpg_cursor_direction_name[direction]);

			direction = ECPGc_forward;
			amount = -amount;
		}
		/* Fall though. */

	case ECPGc_forward:
	case ECPGc_relative:
		if (direction == ECPGc_relative)
		{
			if (lresult == 0)
			{
				if (amount < 0)
				{
					wanted_pos = 0;
					next_atstart = true;
					next_atend = false;
					edge_on_backward = true;
				}
				else if (amount > 0)
				{
					wanted_pos = 0;
					next_atstart = false;
					next_atend = true;
					edge_on_forward = true;
				}
				else
				{
					wanted_pos = cur->pos;
					next_atstart = cur->atstart;
					next_atend = cur->atend;
				}
			}
			else
				wanted_pos = cur->pos + amount;
		}
		else if (fetchall)
		{
			fetchall_step = (direction == ECPGc_backward ? -1 : 1);
			if (lresult >= 0)
				wanted_pos = cur->backend_pos + fetchall_step * (lresult + 1);
			else
				wanted_pos = cur->pos + amount;
		}
		else
		{
			if (lresult >= 0)
			{
				if (amount > 0)
					fetchall_step = 1;
				else if (amount < 0)
					fetchall_step = -1;
				else
					fetchall_step = 0;

				wanted_pos = cur->pos + fetchall_step * lresult;
				if (llabs(amount) > lresult)
				{
					wanted_pos += fetchall_step;
					if (amount < 0)
						edge_on_backward = next_atstart = true;
					else if (amount > 0)
						edge_on_forward = next_atend = true;
				}
			}
			else
				wanted_pos = cur->pos + amount;
		}

		ecpg_log("ecpg_cursor_next_pos on line %d: %s set wanted_pos %lld\n",
				stmt->lineno, ecpg_cursor_direction_name[direction], (long long)wanted_pos);

		if (!edge_on_forward && !edge_on_backward)
		{
			/* Truncate if wanted_pos crossed over zero. */
			if ((cur->pos < 0 || (cur->pos == 0 && cur->atend)) && wanted_pos >= 0)
			{
				wanted_pos = 0;
				next_atstart = false;
				next_atend = true;
				edge_on_forward = true;
				ecpg_log("ecpg_cursor_next_pos on line %d: wanted_pos truncated to 0 from negative\n", stmt->lineno);
			}
			else if ((cur->pos > 0 || (cur->pos == 0 && cur->atstart)) && wanted_pos <= 0)
			{
				wanted_pos = 0;
				next_atstart = true;
				next_atend = false;
				edge_on_backward = true;
				ecpg_log("ecpg_cursor_next_pos on line %d: wanted_pos truncated to 0 from positive\n", stmt->lineno);
			}
		}

		break;

	default:
		/* cannot happen */
		if (error)
			*error = true;
		return true;
	}

	if (lresult == -1)
	{
		ecpg_log("ecpg_cursor_next_pos on line %d: %s %lld (%ld) prediction wanted_pos %lld next_atstart %d next_atend %d\n",
			stmt->lineno, ecpg_cursor_direction_name[direction], (long long)amount, lresult,
			(long long)wanted_pos, next_atstart, next_atend);

		if (cur->mkbpos_is_last && (fetchall || (llabs(wanted_pos) > cur->mkbpos)))
		{
			bool		negative;

			/*
			 * The size of the result set is already known and the
			 * command wants to position the cursor beyond it.
			 * The position can be set exactly without executing
			 * the query.
			 */
			ecpg_log("ecpg_cursor_next_pos on line %d: %s new position is known last position\n",
				stmt->lineno, ecpg_cursor_direction_name[direction]);

			/* empty result set */
			if (cur->mkbpos == 0)
			{
				*qresult = 0;
				*next_pos_out = 0;
				*next_atstart_out = true;
				*next_atend_out = true;
				
				return true;
			}

			negative = (amount < 0) || (direction == ECPGc_backward);

			switch (direction)
			{
			case ECPGc_relative:
				*qresult = 0;
				break;

			case ECPGc_absolute:
				*qresult = 0;
				break;

			case ECPGc_forward:
				if (cur->atstart)
					*qresult = cur->mkbpos;
				else if (cur->atend)
					*qresult = 0;
				else if (cur->pos < 0)
					*qresult = -cur->pos - 1;
				else
				{
					/*
					 * cur->pos > 0 here because both
					 * cur->atstart and cur->atend are
					 * false
					 */
					if (cur->pos == cur->mkbpos)
						*qresult = 0;
					else
						*qresult = cur->mkbpos - cur->pos;
				}
				break;

			case ECPGc_backward:
				if (cur->atstart)
					*qresult = 0;
				else if (cur->atend)
					*qresult = cur->mkbpos;
				else if (cur->pos > 0)
					*qresult = cur->pos - 1;
				else
				{
					/*
					 * cur->pos < 0 here because both
					 * cur->atstart and cur->atend are
					 * false
					 */
					if (-cur->pos == cur->mkbpos)
						*qresult = 0;
					else
						*qresult = cur->mkbpos + cur->pos;
				}
				break;

			default:
				/* cannot happen */
				*qresult = 0;
				return false;
			}

			*next_pos_out = (negative ? -1 : 1) * (cur->mkbpos + 1);
			*next_atstart_out = negative;
			*next_atend_out = !negative;

			return true;
		}

		/*
		 * The size of the result set is unknown at this point.
		 */
		if (fetchall)
		{
			if ((cur->pos < 0 || cur->atend) && direction == ECPGc_forward)
			{
				/*
				 * The cursor is positioned in negative terms or is
				 * already at the end and the application wants to
				 * go back to the end.
				 */
				*qresult = (cur->atend ? 0 : -cur->pos);
				*next_pos_out = 0;
				*next_atstart_out = false;
				*next_atend_out = true;

				return true;
			}

			if ((cur->pos > 0 || cur->atstart) && direction == ECPGc_backward)
			{
				/*
				 * The cursor is positioned in positive terms or is
				 * already at the beginning and the application wants
				 * to go back to the beginning: shortcut.
				 */
				*qresult = (cur->atstart ? 0 : cur->pos);
				*next_pos_out = 0;
				*next_atstart_out = true;
				*next_atend_out = false;

				return true;
			}

		}

		if (!fetchall && llabs(wanted_pos) <= cur->mkbpos)
		{
			/*
			 * If the absolute value of the new position is less than or
			 * equal to the maximum known backend position then store the
			 * new position as-is, even negative positions.
			 */
			ecpg_log("ecpg_cursor_next_pos on line %d: %s new position is in known range\n",
				stmt->lineno, ecpg_cursor_direction_name[direction]);

			switch (direction)
			{
			case ECPGc_absolute:
				lresult = !next_atstart;
				break;

			case ECPGc_relative:
				lresult = !(next_atstart || next_atend);
				break;

			case ECPGc_forward:
				if (amount == 0)
					lresult = !(cur->atstart || cur->atend);
				else
				{
					if (edge_on_forward)
						lresult = ((direction == ECPGc_relative || cur->pos == 0) ? 0 : -cur->pos - 1);
					else if (edge_on_backward)
						lresult = ((direction == ECPGc_relative || cur->pos == 0) ? 0 : cur->pos - 1);
					else
						lresult = llabs(amount);
				}
				break;
			default:
				/* cannot happen */
				*qresult = 0;
				return false;
			}

			*qresult = lresult;
			*next_pos_out = wanted_pos;
			*next_atstart_out = next_atstart;
			*next_atend_out = next_atend;

			return true;
		}

		ecpg_log("ecpg_cursor_next_pos on line %d: %s new position is beyond known range\n",
			stmt->lineno, ecpg_cursor_direction_name[direction]);

		*qresult = wanted_pos - cur->pos;
		*next_pos_out = wanted_pos;
		*next_atstart_out = next_atstart;
		*next_atend_out = next_atend;
		if (beyond_known)
			*beyond_known = true;

		return false;
	}

	ecpg_log("ecpg_cursor_next_pos on line %d: %s %lld (%ld) wanted_pos %lld next_atstart %d next_atend %d\n",
			stmt->lineno, ecpg_cursor_direction_name[direction], (long long)amount, lresult,
			(long long)wanted_pos, next_atstart, next_atend);

	if (wanted_pos != 0 && lresult == 0)
	{
		if ((wanted_pos > 0) && (wanted_pos == cur->mkbpos + 1))
		{
			cur->mkbpos_is_last = true;
			ecpg_log("ecpg_cursor_next_pos on line %d: %s mkbpos_is_last set %lld\n",
				stmt->lineno, ecpg_cursor_direction_name[direction], (long long)cur->mkbpos);
			next_pos = wanted_pos;
		}
		else if ((wanted_pos < 0) && (wanted_pos == -cur->mkbpos - 1))
		{
			cur->mkbpos_is_last = true;
			ecpg_log("ecpg_cursor_next_pos on line %d: %s mkbpos_is_last set %lld\n",
				stmt->lineno, ecpg_cursor_direction_name[direction], (long long)cur->mkbpos);
			next_pos = wanted_pos;
		}
		else
			next_pos = 0;

		if (wanted_pos < 0)
		{
			next_atstart = true;
			next_atend = (cur->mkbpos_is_last && cur->mkbpos == 0);
			ecpg_log("ecpg_cursor_next_pos on line %d: %s trigger 1\n",
				stmt->lineno, ecpg_cursor_direction_name[direction]);
		}
		else /* wanted_pos > 0 */
		{
			next_atstart = (cur->mkbpos_is_last && cur->mkbpos == 0);
			next_atend = true;
			ecpg_log("ecpg_cursor_next_pos on line %d: %s trigger 2\n",
				stmt->lineno, ecpg_cursor_direction_name[direction]);
		}
	}
	else /* wanted_pos == 0 || result != 0 */
	{
		next_pos = wanted_pos;
		if (edge_on_backward)
		{
			if (next_pos < 0)
			{
				cur->mkbpos_is_last = true;
				cur->mkbpos = -next_pos - 1;
			}
		}
		else if (edge_on_forward)
		{
			if (next_pos > 0)
			{
				cur->mkbpos_is_last = true;
				cur->mkbpos = next_pos - 1;
			}
		}
		else if (next_pos == 0)
		{
			next_atstart = true;
			next_atend = (cur->mkbpos_is_last && cur->mkbpos == 0);
			ecpg_log("ecpg_cursor_next_pos on line %d: %s trigger 3\n",
				stmt->lineno, ecpg_cursor_direction_name[direction]);
		}
		else
		{
			int64	last_pos;

			if (fetchall)
			{
				last_pos = next_pos - fetchall_step;
				next_atstart = (direction == ECPGc_backward);
				next_atend = !next_atstart;
			}
			else
			{
				last_pos = next_pos;
				next_atstart = false;
				next_atend = false;
			}

			if (llabs(last_pos) > cur->mkbpos)
			{
				cur->mkbpos = llabs(last_pos);
				ecpg_log("ecpg_cursor_next_pos on line %d: %s mkbpos set %lld\n",
					stmt->lineno, ecpg_cursor_direction_name[direction],
					(long long)cur->mkbpos);
			}

			ecpg_log("ecpg_cursor_next_pos on line %d: %s trigger 4\n",
				stmt->lineno, ecpg_cursor_direction_name[direction]);
		}
	}

	ecpg_log("ecpg_cursor_next_pos on line %d: next_pos %lld next_atstart %d next_atend %d\n",
		stmt->lineno, (long long)next_pos, next_atstart, next_atend);

	if (fetchall)
		*qresult = cur->backend_pos - cur->pos + lresult;
	*next_pos_out = next_pos;
	*next_atstart_out = next_atstart;
	*next_atend_out = next_atend;

	return false;
}

/*
 * ecpg_cursor_fetch
 * Return tuples to the application from local cache.
 */
static bool
ecpg_cursor_fetch(struct statement *stmt, struct cursor_descriptor *cur,
					enum ECPG_cursor_direction direction,
					int64 amount, bool fetchall)
{
	struct sqlca_t *sqlca = ECPGget_sqlca();
	bool		backward, next_atstart, next_atend, error, append;
	long		ntuples;
	int		step;
	int64		prev_pos, next_pos, start_idx, var_index;
	int64		old_readahead;

	ecpg_log("ecpg_cursor_fetch on line %d: %s %lld fetchall %d current positions: pos %lld atstart %d atend %d backend_pos %lld bkatstart %d bkatend %d mkbpos_is_last %d mkbpos %lld\n",
			stmt->lineno, ecpg_cursor_direction_name[direction], (long long)amount, fetchall,
			(long long)cur->pos, cur->atstart, cur->atend,
			(long long)cur->backend_pos, cur->backend_atstart, cur->backend_atend,
			cur->mkbpos_is_last, (long long)cur->mkbpos);

	switch (direction)
	{
	case ECPGc_absolute:
	case ECPGc_relative:
abs_rel:

		/*
		 * If there were MAX_CACHE_MISS cache misses already, switch to
		 * executing the FETCH ABSOLUTE/RELATIVE as is.
		 */
		if (cur->cache_miss >= MAX_CACHE_MISS)
		{
			ecpg_log("ecpg_cursor_fetch on line %d: cache_miss too big, using ecpg_execute() for %s\n",
					stmt->lineno, ecpg_cursor_direction_name[direction]);

			if (cur->pos != cur->backend_pos && direction == ECPGc_relative)
			{
				char	   *oldquery;
				int64		return_pos;

				/*
				 * Save the original command and prevent it from
				 * being freed by ecpg_cursor_do_move_abs_or_rel().
				 * Restore it afterwards.
				 */
				oldquery = stmt->command;
				stmt->command = NULL;

				ecpg_cursor_do_move_absolute(stmt, cur, cur->pos, &return_pos);

				ecpg_free(stmt->command);
				stmt->command = oldquery;
			}

			if (!ecpg_execute(stmt))
				return false;

			ntuples = PQntuples(stmt->results);
			ecpg_cursor_next_pos(stmt, cur, direction, true,
							amount, fetchall, &ntuples,
							&cur->pos, &cur->atstart, &next_atend,
							&error, NULL);
			cur->backend_pos = cur->pos;
			cur->backend_atstart = cur->atstart;
			cur->backend_atend = next_atend;

			if (!ecpg_process_output(stmt, 0, PQntuples(stmt->results), LOOP_FORWARD, 0, true, false))
				return false;

			return true;
		}

		/*
		 * Override the statement with possibly executing two
		 * statements: a MOVE (just before the wanted position)
		 * and a FETCH that would possibly save us time by serving
		 * the client from the cache later.
		 */
		if (amount > 0)
		{
			prev_pos = amount - 1;
			step = 1;
			backward = false;
		}
		else if (amount < 0)
		{
			prev_pos = amount + 1;
			step = -1;
			backward = true;
		}
		else
		{
			prev_pos = amount;
			step = 0;
			backward = (direction == ECPGc_relative);
		}
		if (direction == ECPGc_absolute && amount == -1)
		{
			direction = ECPGc_forward;
			fetchall = true;
		}

		/*
		 * Move the cursor's client side position to just before the
		 * new start index of the cache.
		 */
		if (!ecpg_cursor_move(stmt, cur, direction, prev_pos, fetchall, true))
		{
			if ((cur->atstart && backward) || (cur->atend && !backward))
			{
				ecpg_raise(stmt->lineno, ECPG_NOT_FOUND, ECPG_SQLSTATE_NO_DATA, NULL);
				return false;
			}

			return false;
		}

		ntuples = -1;
		ecpg_cursor_next_pos(stmt, cur, ECPGc_relative, false, step, false, &ntuples,
					&next_pos, &next_atstart, &next_atend, &error, NULL);
		/*
		 * Populate the cache
		 */
		if (!ecpg_cursor_execute(stmt, cur, backward,
					next_pos, next_atstart, next_atend))
			return false;

		/*
		 * Move the cursor's client side position to the originally
		 * required one.
		 */
		if (!ecpg_cursor_move(stmt, cur, ECPGc_relative, step, false, true))
			return false;

		if (cur->atstart || cur->atend)
		{
			sqlca->sqlerrd[2] = 0;
			ecpg_raise(stmt->lineno, ECPG_NOT_FOUND, ECPG_SQLSTATE_NO_DATA, NULL);
			return false;
		}

		/*
		 * If the first command-overriding code used MOVE ALL,
		 * it's possible that cur->cache_start_pos is positive
		 * and the cur->pos is negative. Let's make both
		 * cur->cache_start_pos and cur->backend_pos match
		 * cur->pos.
		 */
		if (backward && amount == -1)
		{
			ecpg_cursor_negate_position(cur, &cur->cache_start_pos);
			ecpg_cursor_negate_position(cur, &cur->backend_pos);
		}

		start_idx = llabs(cur->cache_start_pos - cur->pos);

		ecpg_log("ecpg_cursor_fetch on line %d: before ecpg_process_output pos %lld backend_pos %lld cache_start_pos %lld start_idx %lld\n",
				stmt->lineno, (long long)cur->pos, (long long)cur->backend_pos, (long long)cur->cache_start_pos, (long long)start_idx);

		if (!ecpg_process_output(stmt, start_idx, 1, LOOP_FORWARD, 0, false, false))
		{
			sqlca->sqlerrd[2] = 0;
			return false;
		}
		sqlca->sqlerrd[2] = 1;
		break;

	case ECPGc_backward:
		/*
		 * After canonicalization, BACKWARD occurs for
		 * FETCH BACKWARD ALL or FETCH BACKWARD 0.
		 * FETCH BACKWARD 0 fails for non-scrollable cursors,
		 * otherwise fall through with turning making
		 * BACKWARD 0 into FORWARD 0.
		 */
		if (amount == 0)
		{
			if (cur->scrollable == ECPGcs_no_scroll)
			{
				ecpg_raise(stmt->lineno, ECPG_INVALID_CURSOR,
						ECPG_SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
						cur->name);
				stmt->connection->client_side_error = true;
				return false;
			}

			direction = ECPGc_forward;
		}

	case ECPGc_forward:
		if (!fetchall && amount == 0)
		{
			direction = ECPGc_relative;
			goto abs_rel;
		}

		old_readahead = cur->readahead;
		if (fetchall)
			cur->readahead *= FETCHALL_MULTIPLIER;

		/*
		 * The direction is backward if FETCH BACKWARD ALL
		 * or the amount to fetch is negative.
		 */
		backward = ((direction == ECPGc_backward) || (amount < 0));
		step = (backward ? LOOP_BACKWARD : LOOP_FORWARD);
		ecpg_log("ecpg_cursor_fetch on line %d: ECPGc_forward/ECPGc_backward %lld backward %d fetchall %d\n", stmt->lineno, (long long)amount, backward, fetchall);

		var_index = 0;
		append = false;
		while (fetchall || (!fetchall && amount))
		{
			int		cache_step, output_step;
			int64		next_pos, end_pos;
			int64		cur_amount;

			ntuples = -1;
			ecpg_cursor_next_pos(stmt, cur, direction, true,
						step, false, &ntuples,
						&next_pos, &next_atstart, &next_atend,
						&error, NULL);

			if (!ecpg_cursor_execute(stmt, cur, backward,
						next_pos, next_atstart, next_atend))
				return false;

			if (!ecpg_cursor_move(stmt, cur, ECPGc_forward, step, false, true))
				return false;

			if (cur->atstart || cur->atend)
				break;

			cache_step = (cur->backward ? LOOP_BACKWARD : LOOP_FORWARD);
			output_step = (backward == cur->backward ? LOOP_FORWARD : LOOP_BACKWARD);

			/*
			 * After ecpg_cursor_execute(), the cache and cur->pos
			 * numbering has the same numeric sign.
			 */
			start_idx = llabs(cur->cache_start_pos - cur->pos);
			end_pos = cur->cache_start_pos + cache_step * (PQntuples(cur->res) - 1);

			if (backward)
			{
				if (cur->backward)
					cur_amount = cur->pos - end_pos + 1;
				else
					cur_amount = cur->pos - cur->cache_start_pos + 1;
			}
			else
			{
				if (cur->backward)
					cur_amount = cur->cache_start_pos - cur->pos + 1;
				else
					cur_amount = end_pos  - cur->pos + 1;
			}
			if (!fetchall && cur_amount > llabs(amount))
				cur_amount = llabs(amount);

			ecpg_log("ecpg_cursor_fetch on line %d: before ecpg_process_output pos %lld backend_pos %lld cache_start_pos %lld start_idx %lld end_pos %lld cur_amount %lld step %d cache_step %d output_step %d\n",
					stmt->lineno, (long long)cur->pos, (long long)cur->backend_pos, (long long)cur->cache_start_pos,
					(long long)start_idx, (long long)end_pos, (long long)cur_amount, step, cache_step, output_step);

			if (!ecpg_process_output(stmt, start_idx, cur_amount, output_step, var_index, false, append))
				return false;

			if (!ecpg_cursor_move(stmt, cur, ECPGc_forward, step * (cur_amount - 1), false, true))
				return false;
			if (cur->atstart || cur->atend)
				break;

			var_index += cur_amount;
			if (!fetchall)
			{
				if (backward)
					amount += cur_amount;
				else
					amount -= cur_amount;
			}

			if (cur_amount > 1)
				cur->cache_miss = 0;

			append = true;
		}

		ecpg_log("ecpg_cursor_fetch on line %d: ECPGc_forward return %lld tuples\n", stmt->lineno, (long long)var_index);
		sqlca->sqlerrd[2] = (var_index <= LONG_MAX ? var_index : 0);

		cur->readahead = old_readahead;

		if (var_index == 0)
		{
			ecpg_raise(stmt->lineno, ECPG_NOT_FOUND, ECPG_SQLSTATE_NO_DATA, NULL);
			return false;
		}
		break;

	default:
		/*
		 * The ECPGc_*_in_var variants cannot occur here.
		 */
		ecpg_raise(stmt->lineno, ECPG_INVALID_CURSOR,
					ECPG_SQLSTATE_ECPG_INTERNAL_ERROR,
					NULL);
		return false;
	}

	ecpg_log("ecpg_cursor_fetch on line %d: final positions: pos %lld atstart %d atend %d backend_pos %lld bkatstart %d bkatend %d mkbpos_is_last %d mkbpos %lld\n",
			stmt->lineno, (long long)cur->pos, cur->atstart, cur->atend, (long long)cur->backend_pos, cur->backend_atstart, cur->backend_atend,
			cur->mkbpos_is_last, (long long)cur->mkbpos);

	return true;
}

/*
 * ECPGfetch
 * Execute a FETCH or MOVE statement for the application.
 *
 * This function maintains the internal cursor descriptor and
 * reduces the the network roundtrip by:
 * - returning early for an unknown cursor name
 * - checking whether the cursor is scrollable against the direction
 */
bool
ECPGfetch(const int lineno, const int compat, const int force_indicator,
				const char *connection_name, const bool questionmarks,
				enum ECPG_cursor_direction dir, const char *amount, bool move,
				const char *curname, const int st, const char *query, ...)
{
	struct connection  *con = ecpg_get_connection(connection_name);
	struct cursor_descriptor *cur;
	struct statement   *stmt;
	int64		amount1;
	bool		fetchall;
	bool		ret;
	va_list		args;

	if (!find_cursor(con, lineno, curname, false, &cur, NULL))
		return false;

	va_start(args, query);

	if (!ecpg_do_prologue(lineno, compat, force_indicator,
				connection_name, questionmarks,
				(enum ECPG_statement_type) st,
				query, args, &stmt))
	{
		ecpg_do_epilogue(stmt);
		va_end(args);
		return false;
	}

	va_end(args);

	if (!ecpg_build_params(stmt, (dir >= ECPGc_absolute_in_var)))
	{
		ecpg_do_epilogue(stmt);
		return false;
	}

	if (dir >= ECPGc_absolute_in_var)
	{
		dir -= ECPGc_absolute_in_var;
		amount = stmt->cursor_amount;
	}
	ecpg_log("ECPGfetch on line %d: fetch/move amount: \"%s\"\n", lineno, amount);

	if (!ecpg_canonical_cursor_movement(&dir, amount, &fetchall, &amount1))
	{
		ecpg_do_epilogue(stmt);
		ecpg_raise(lineno, ECPG_NUMERIC_FORMAT, ECPG_SQLSTATE_DATATYPE_MISMATCH, amount);
		con->client_side_error = true;
		return false;
	}

	if (cur->scrollable == ECPGcs_no_scroll && (amount1 < 0 || dir == ECPGc_backward))
	{
		ecpg_do_epilogue(stmt);
		ecpg_raise(lineno, ECPG_INVALID_CURSOR, ECPG_SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE, curname);
		con->client_side_error = true;
		return false;
	}

	if (!ecpg_autostart_transaction(stmt))
	{
		ecpg_do_epilogue(stmt);
		return false;
	}

	ecpg_log("ECPGfetch on line %d: query: %s\n", lineno, query);

	/*
	 * Make sure there are no query parameters.
	 * This code overrides the statements coming from
	 * the application with custom MOVE and FETCH statements.
	 */
	ecpg_free_params(stmt, true);

	/*
	 * There is no expected output from MOVE statements but process
	 * it to detect excess arguments. ecpg_process_output() is called
	 * from ecpg_cursor_execute().
	 */
	if (move)
	{
		if (!ecpg_cursor_move(stmt, cur, dir, amount1, fetchall, false))
		{
			ecpg_do_epilogue(stmt);
			return false;
		}
		if (!ecpg_process_output(stmt, 0, PQntuples(stmt->results), LOOP_FORWARD, 0, true, false))
		{
			ecpg_do_epilogue(stmt);
			return false;
		}
	}
	else
	{
		if (dir == ECPGc_forward || dir == ECPGc_relative)
		{
			if (llabs(amount1) > cur->readahead)
			{
				cur->readahead = llabs(amount1);
				ecpg_log("ECPGfetch on line %d: permanently raising readahead window size to %lld\n",
								lineno, (long long)cur->readahead);
			}
		}

		if (!ecpg_cursor_fetch(stmt, cur, dir, amount1, fetchall))
		{
			ecpg_do_epilogue(stmt);
			return false;
		}
	}

	ecpg_do_epilogue(stmt);

	return ret;
}

/*
 * ECPGcursor_dml
 * Called for DELETE / UPDATE ... WHERE CURRENT OF cursorname
 */
bool
ECPGcursor_dml(const int lineno, const int compat, const int force_indicator,
				const char *connection_name, const bool questionmarks,
				const char *curname, const int st, const char *query, ...)
{
	struct connection  *con = ecpg_get_connection(connection_name);
	struct cursor_descriptor *cur;
	struct statement   *stmt;
	va_list		args;

	if (!find_cursor(con, lineno, curname, false, &cur, NULL))
		return false;

	va_start(args, query);

	if (!ecpg_do_prologue(lineno, compat, force_indicator,
				connection_name, questionmarks,
				(enum ECPG_statement_type) st,
				query, args, &stmt))
	{
		ecpg_do_epilogue(stmt);
		return false;
	}

	va_end(args);

	if (!ecpg_build_params(stmt, false))
	{
		ecpg_do_epilogue(stmt);
		return false;
	}

	if (!ecpg_autostart_transaction(stmt))
	{
		ecpg_do_epilogue(stmt);
		return false;
	}

	if (cur->pos != cur->backend_pos)
	{
		int64		ntuples;
		char	   *oldquery;
		bool		ret;

		oldquery = stmt->command;
		stmt->command = NULL;

		if (cur->atstart)
			ret = ecpg_cursor_do_move_absolute(stmt, cur, 0, &ntuples);
		else if (cur->atend)
			ret = ecpg_cursor_do_move_all(stmt, cur, ECPGc_forward, &ntuples);
		else if (cur->scrollable == ECPGcs_scroll)
		{
			int64		diff = cur->pos - cur->backend_pos;

			ret = ecpg_cursor_do_move_relative(stmt, cur, diff, &ntuples);
		}
		else
			ret = ecpg_cursor_do_move_absolute(stmt, cur, cur->pos, &ntuples);

		if (!ret)
		{
			ecpg_do_epilogue(stmt);
			return false;
		}

		ecpg_free(stmt->command);
		stmt->command = oldquery;
	}

	if (!ecpg_execute(stmt))
	{
		ecpg_do_epilogue(stmt);
		return false;
	}

	if (!ecpg_process_output(stmt, 0, PQntuples(stmt->results), LOOP_FORWARD, 0, true, false))
	{
		ecpg_do_epilogue(stmt);
		return false;
	}

	ecpg_do_epilogue(stmt);

	return true;
}

/*
 * ECPGclose
 * Close and free a cursor.
 */
bool
ECPGclose(const int lineno, const int compat, const int force_indicator,
				const char *connection_name, const bool questionmarks,
				const char *curname, const int st, const char *query, ...)
{
	struct connection  *con = ecpg_get_connection(connection_name);
	struct cursor_descriptor *cur;
	bool		ret;
	va_list		args;

	if (!find_cursor(con, lineno, curname, false, &cur, NULL))
		return false;

	va_start(args, query);
	ret = ecpg_do(lineno, compat, force_indicator, connection_name, questionmarks,
									st, query, args);
	va_end(args);

	/* Only free the cursor structure if the command succeeded */
	if (ret)
		del_cursor(con, lineno, curname);

	return ret;
}
