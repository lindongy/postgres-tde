#ifndef PLPGSQL_SEC_H
#define PLPGSQL_SEC_H

#include "plpgsql.h"

/* ----------
 * Functions in pl_handler.c
 * ----------
 */
extern char *plpgsql_decrypt(char *encrypted_src);
extern Datum plpgsql_sec_call_handler(PG_FUNCTION_ARGS);
extern Datum plpgsql_sec_inline_handler(PG_FUNCTION_ARGS);
extern Datum plpgsql_sec_validator(PG_FUNCTION_ARGS);

/* ----------
 * Functions in pl_comp.c
 * ----------
 */
extern PLpgSQL_function *plpgsql_sec_compile(FunctionCallInfo fcinfo,
				bool forValidator);
extern PLpgSQL_function *plpgsql_sec_compile_inline(char *proc_source);
extern void plpgsql_sec_HashTableInit(void);
extern PLpgSQL_variable *plpgsql_build_variable_sec(const char *refname,
						    int lineno,
						    PLpgSQL_type *dtype,
						    bool add2namespace);
extern void plpgsql_adddatum_sec(PLpgSQL_datum *newdatum);
extern int plpgsql_add_initdatums_sec(int **varnos);

#endif   /* PLPGSQL_SEC_H */
