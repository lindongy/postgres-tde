/* src/interfaces/ecpg/preproc/output.c */

#include "postgres_fe.h"

#include "extern.h"

static void output_escaped_str(char *cmd, bool quoted);

void
output_line_number(void)
{
	char	   *line = hashline_number();

	fprintf(yyout, "%s", line);
	free(line);
}

void
output_simple_statement(char *stmt)
{
	output_escaped_str(stmt, false);
	output_line_number();
	free(stmt);
}


/*
 * store the whenever action here
 */
struct when when_error,
			when_nf,
			when_warn;

static void
print_action(struct when * w)
{
	switch (w->code)
	{
		case W_SQLPRINT:
			fprintf(yyout, "sqlprint();");
			break;
		case W_GOTO:
			fprintf(yyout, "goto %s;", w->command);
			break;
		case W_DO:
			fprintf(yyout, "%s;", w->command);
			break;
		case W_STOP:
			fprintf(yyout, "exit (1);");
			break;
		case W_BREAK:
			fprintf(yyout, "break;");
			break;
		default:
			fprintf(yyout, "{/* %d not implemented yet */}", w->code);
			break;
	}
}

void
whenever_action(int mode)
{
	if ((mode & 1) == 1 && when_nf.code != W_NOTHING)
	{
		output_line_number();
		fprintf(yyout, "\nif (sqlca.sqlcode == ECPG_NOT_FOUND) ");
		print_action(&when_nf);
	}
	if (when_warn.code != W_NOTHING)
	{
		output_line_number();
		fprintf(yyout, "\nif (sqlca.sqlwarn[0] == 'W') ");
		print_action(&when_warn);
	}
	if (when_error.code != W_NOTHING)
	{
		output_line_number();
		fprintf(yyout, "\nif (sqlca.sqlcode < 0) ");
		print_action(&when_error);
	}

	if ((mode & 2) == 2)
		fputc('}', yyout);

	output_line_number();
}

char *
hashline_number(void)
{
	/* do not print line numbers if we are in debug mode */
	if (input_filename
#ifdef YYDEBUG
		&& !yydebug
#endif
		)
	{
		/* "* 2" here is for escaping '\' and '"' below */
		char	   *line = mm_alloc(strlen("\n#line %d \"%s\"\n") + sizeof(int) * CHAR_BIT * 10 / 3 + strlen(input_filename) * 2);
		char	   *src,
				   *dest;

		sprintf(line, "\n#line %d \"", yylineno);
		src = input_filename;
		dest = line + strlen(line);
		while (*src)
		{
			if (*src == '\\' || *src == '"')
				*dest++ = '\\';
			*dest++ = *src++;
		}
		*dest = '\0';
		strcat(dest, "\"\n");

		return line;
	}

	return EMPTY;
}

static char *ecpg_statement_type_name[] = {
	"ECPGst_normal",
	"ECPGst_execute",
	"ECPGst_exec_immediate",
	"ECPGst_prepnormal"
};

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

static char *ecpg_cursor_scroll_name[] = {
	"ECPGcs_unspecified",
	"ECPGcs_no_scroll",
	"ECPGcs_scroll"
};

static void output_cursor_name(struct cursor *ptr)
{
	if (current_cursor[0] == ':')
	{
		char *curname = current_cursor + 1;

		fputs(curname, yyout);
		if (ptr->vartype == ECPGt_varchar)
			fputs(".arr", yyout);
		fputs(", ", yyout);
	}
	else
	{
		fputs("\"", yyout);
		output_escaped_str(current_cursor, false);
		fputs("\", ", yyout);
	}
}

static void
output_statement_epilogue(char *stmt, int whenever_mode, enum ECPG_statement_type st)
{
	if (st == ECPGst_execute || st == ECPGst_exec_immediate)
	{
		fprintf(yyout, "%s, %s, ", ecpg_statement_type_name[st], stmt);
	}
	else
	{
		if (st == ECPGst_prepnormal && auto_prepare)
			fputs("ECPGst_prepnormal, \"", yyout);
		else
			fputs("ECPGst_normal, \"", yyout);

		output_escaped_str(stmt, false);
		fputs("\", ", yyout);
	}

	/* dump variables to C file */
	dump_variables(argsinsert, 1);
	fputs("ECPGt_EOIT, ", yyout);
	dump_variables(argsresult, 1);
	fputs("ECPGt_EORT);", yyout);
	reset_variables();

	whenever_action(whenever_mode | 2);
	free(stmt);
	if (current_cursor)
	{
		free(current_cursor);
		current_cursor = NULL;
	}
	if (connection != NULL)
		free(connection);
}

void
output_statement(char *stmt, int whenever_mode, enum ECPG_statement_type st)
{
	fprintf(yyout, "{ ECPGdo(__LINE__, %d, %d, %s, %d, ", compat, force_indicator, connection ? connection : "NULL", questionmarks);
	output_statement_epilogue(stmt, whenever_mode, st);
}

void
output_prepare_statement(char *name, char *stmt)
{
	fprintf(yyout, "{ ECPGprepare(__LINE__, %s, %d, ", connection ? connection : "NULL", questionmarks);
	output_escaped_str(name, true);
	fputs(", ", yyout);
	output_escaped_str(stmt, true);
	fputs(");", yyout);
	whenever_action(2);
	free(name);
	if (connection != NULL)
		free(connection);
}

void
output_deallocate_prepare_statement(char *name)
{
	const char *con = connection ? connection : "NULL";

	if (strcmp(name, "all") != 0)
	{
		fprintf(yyout, "{ ECPGdeallocate(__LINE__, %d, %s, ", compat, con);
		output_escaped_str(name, true);
		fputs(");", yyout);
	}
	else
		fprintf(yyout, "{ ECPGdeallocate_all(__LINE__, %d, %s);", compat, con);

	whenever_action(2);
	free(name);
	if (connection != NULL)
		free(connection);
}

void
output_open_statement(char *stmt, int whenever_mode, enum ECPG_statement_type st)
{
	struct cursor *ptr = get_cursor(current_cursor);

	fprintf(yyout, "{ ECPGopen(__LINE__, %d, %d, %s, %d, %d, %s, %ld, %d, %d, ",
						compat, force_indicator, connection ? connection : "NULL", questionmarks,
						ptr->with_hold, ecpg_cursor_scroll_name[ptr->scrollable],
						ptr->fetch_readahead, ptr->allow_ra_override, cursor_rssz);
	output_cursor_name(ptr);
	output_statement_epilogue(stmt, whenever_mode, st);
}

void
output_fetch_statement(char *stmt, int whenever_mode, enum ECPG_statement_type st, bool move)
{
	struct cursor *ptr = get_cursor(current_cursor);
	char	   *amount;

	if (current_cursor_amount)
	{
		amount = mm_alloc(strlen(current_cursor_amount) + 3);
		sprintf(amount, "\"%s\"", current_cursor_amount);
		free(current_cursor_amount);
	}
	else
		amount = mm_strdup("NULL");

	fprintf(yyout, "{ ECPGfetch(__LINE__, %d, %d, %s, %d, %s, %s, %d, ",
						compat, force_indicator, connection ? connection : "NULL", questionmarks,
						ecpg_cursor_direction_name[current_cursor_direction], amount, move);
	output_cursor_name(ptr);
	output_statement_epilogue(stmt, whenever_mode, st);
	free(amount);
	current_cursor_amount = NULL;
}

void
output_cursor_dml_statement(char *stmt, int whenever_mode, enum ECPG_statement_type st)
{
	struct cursor *ptr = get_cursor(current_cursor);

	fprintf(yyout, "{ ECPGcursor_dml(__LINE__, %d, %d, %s, %d, ", compat, force_indicator, connection ? connection : "NULL", questionmarks);
	output_cursor_name(ptr);
	output_statement_epilogue(stmt, whenever_mode, st);
}

void
output_close_statement(char *stmt, int whenever_mode, enum ECPG_statement_type st)
{
	struct cursor *ptr = get_cursor(current_cursor);

	fprintf(yyout, "{ ECPGclose(__LINE__, %d, %d, %s, %d, ", compat, force_indicator, connection ? connection : "NULL", questionmarks);
	output_cursor_name(ptr);
	output_statement_epilogue(stmt, whenever_mode, st);
}

static void
output_escaped_str(char *str, bool quoted)
{
	int			i = 0;
	int			len = strlen(str);

	if (quoted && str[0] == '\"' && str[len - 1] == '\"')		/* do not escape quotes
																 * at beginning and end
																 * if quoted string */
	{
		i = 1;
		len--;
		fputs("\"", yyout);
	}

	/* output this char by char as we have to filter " and \n */
	for (; i < len; i++)
	{
		if (str[i] == '"')
			fputs("\\\"", yyout);
		else if (str[i] == '\n')
			fputs("\\\n", yyout);
		else if (str[i] == '\\')
		{
			int			j = i;

			/*
			 * check whether this is a continuation line if it is, do not
			 * output anything because newlines are escaped anyway
			 */

			/* accept blanks after the '\' as some other compilers do too */
			do
			{
				j++;
			} while (str[j] == ' ' || str[j] == '\t');

			if ((str[j] != '\n') && (str[j] != '\r' || str[j + 1] != '\n'))		/* not followed by a
																				 * newline */
				fputs("\\\\", yyout);
		}
		else if (str[i] == '\r' && str[i + 1] == '\n')
		{
			fputs("\\\r\n", yyout);
			i++;
		}
		else
			fputc(str[i], yyout);
	}

	if (quoted && str[0] == '\"' && str[len] == '\"')
		fputs("\"", yyout);
}
