/*-------------------------------------------------------------------------
 *
 * pl_handler.c		- Handler for the PL/pgSQL
 *			  procedural language
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/pl/plpgsql/src/pl_handler.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "plpgsql_sec.h"

#include "access/htup_details.h"
#include "access/table.h"
#include "catalog/indexing.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "common/encryption.h"
#include "common/md5.h"
#include "common/scram-common.h"
#include "funcapi.h"
#include "libpq/crypt.h"
#include "libpq/scram.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/rel.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/varlena.h"

#ifdef USE_ENCRYPTION
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#endif

#ifdef USE_ENCRYPTION
static void set_encryption_tweak(char *tweak, Oid proc_oid);
static void evp_error(void);
#endif	/* USE_ENCRYPTION */
static void plpgsql_extra_warnings_assign_hook(const char *newvalue, void *extra);
static void plpgsql_extra_errors_assign_hook(const char *newvalue, void *extra);

#define ENCRHEADER      "#ENCRYPTED#"

PG_MODULE_MAGIC;

/* Custom GUC variable */
static const struct config_enum_entry variable_conflict_options[] = {
	{"error", PLPGSQL_RESOLVE_ERROR, false},
	{"use_variable", PLPGSQL_RESOLVE_VARIABLE, false},
	{"use_column", PLPGSQL_RESOLVE_COLUMN, false},
	{NULL, 0, false}
};

int			plpgsql_variable_conflict = PLPGSQL_RESOLVE_ERROR;

bool		plpgsql_print_strict_params = false;

bool		plpgsql_check_asserts = true;

char	   *plpgsql_extra_warnings_string = NULL;
char	   *plpgsql_extra_errors_string = NULL;
int			plpgsql_extra_warnings;
int			plpgsql_extra_errors;

#ifdef USE_ENCRYPTION
/*
 * Role whose password will be use to derive the encryption key.
 *
 * TODO Consider this role configurable. If so, stress in the documentation
 * that new role assigned to such a GUC must have the same password like the
 * original one, otherwise the existing functions cannot be decrypted.
 */
#define	ENCRYPTION_ROLE	"plpgsql_sec"

/* Length of the encryption key in bytes. */
#define	ENCR_KEY_LEN	32

static EVP_CIPHER_CTX *encr_ctx = NULL;

static	bool	local_encryption_setup_done = false;

static void
initialize_encryption(void)
{
	char	*password;
	char	*msg = NULL;
	PasswordType	ptype;
	const EVP_CIPHER *cipher = NULL;
	unsigned char	key[SCRAM_KEY_LEN];

	/*
	 * SCRAM_KEY_LEN should provide us with enough space, regardless the
	 * authentication type.
	 *
	 * Note that MD5_PASSWD_LEN is expressed in hexadecimal characters, and
	 * that two hexadecimal characters of the hash represent a single byte of
	 * the key.
	 */
	StaticAssertStmt(SCRAM_KEY_LEN * 2 >= (MD5_PASSWD_LEN - 3),
						 "Incorrect key length");

	/*
	 * The plpgsql_sec specific setup is what we'll do here.
	 */
	Assert(!local_encryption_setup_done);

	password = get_role_password(ENCRYPTION_ROLE, &msg);
	if (password == NULL || strlen(password) == 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PASSWORD),
				 errmsg("%s", msg)));

	/*
	 * TODO
	 *
	 * Do some more checks, e.g. one that the role has no permissions,
	 * especially LOGIN?
	 */

	ptype = get_password_type(password);
	if (ptype == PASSWORD_TYPE_MD5)
	{
		/* Store the key into the encryption_key variable */
		encryption_key_from_string(password + 3, key,
								   ENCRYPTION_KEY_LENGTH);

		cipher = EVP_aes_128_ctr();
	}
	else if (ptype == PASSWORD_TYPE_SCRAM_SHA_256)
	{
		int	iterations;
		char	*salt = NULL;
		uint8		stored_key[SCRAM_KEY_LEN];

		/* Retrieve the server key. */
		if (!parse_scram_verifier(password, &iterations, &salt, stored_key,
								  key))
			ereport(ERROR,
					(errmsg("invalid SCRAM verifier for user \"%s\"",
						ENCRYPTION_ROLE)));
		if (salt)
			pfree(salt);

		/*
		 * 128-bit key should be enough, but now that we have a 256-bit key,
		 * let's use the corresponding cipher.
		 */
		cipher = EVP_aes_256_ctr();
	}
	else
	{
		Assert(ptype == PASSWORD_TYPE_PLAINTEXT);

		/* XXX Actually we can run hash it ourselves. */
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PASSWORD),
				 errmsg("password in 'plaintext' cannot be used for encryption")));
	}
	pfree(password);

	if ((encr_ctx = EVP_CIPHER_CTX_new()) == NULL)
		evp_error();

	if (EVP_EncryptInit_ex(encr_ctx, cipher, NULL, key, NULL) != 1)
		evp_error();
	if (EVP_DecryptInit_ex(encr_ctx, cipher, NULL, key, NULL) != 1)
		evp_error();

	/* Padding is not needed because block size is 1 for the CTR mode. */
	EVP_CIPHER_CTX_set_padding(encr_ctx, 0);

	Assert(EVP_CIPHER_CTX_iv_length(encr_ctx) == TWEAK_SIZE);

	local_encryption_setup_done = true;
}
#endif	/* USE_ENCRYPTION */

/*
 * plpgsql_encrypt()
 *
 * It's called at function validation. At this point the function is already
 * stored in pg_proc. We return it from there, encrypt it and update it in
 * pg_proc. When a dumped function is restored, we are called with an already
 * encrypted function in which case we just quit.
 */
static void
plpgsql_encrypt(Oid function_oid) {
#ifdef USE_ENCRYPTION
	Relation	procRelation;
	TupleDesc	tupDesc;
	HeapTuple	proctuple;
	HeapTuple	newproctuple;
	Datum		prosrcdatum;
	char		*sourcecode;
	text		*src_encrypted;
	Datum		encr_hex;
	text		*prosrc;
	bool		isnull;
	Datum		values[Natts_pg_proc];
	bool		nulls[Natts_pg_proc];
	bool		replace[Natts_pg_proc];
	char		tweak[TWEAK_SIZE];
	size_t		encr_size_total;
	int		in_size, out_size;
	char	*c;

	if (!local_encryption_setup_done)
		initialize_encryption();

	procRelation = heap_open(ProcedureRelationId, RowExclusiveLock);

	tupDesc = RelationGetDescr(procRelation);

	proctuple = SearchSysCache(PROCOID, ObjectIdGetDatum(function_oid), 0, 0, 0);

	if (!HeapTupleIsValid(proctuple))
		elog(ERROR, "cache lookup failed for function %u", function_oid);

	prosrcdatum = SysCacheGetAttr(PROCOID, proctuple, Anum_pg_proc_prosrc, &isnull);
	if (isnull)
		elog(ERROR, "null prosrc");

	sourcecode = pstrdup(DatumGetCString(DirectFunctionCall1(textout,
										prosrcdatum)));

	/*
	 * Check whether it's already encrypted. When a dumped function is
	 * reloaded, it's in encrypted form.
	 */
	if (sourcecode[0] == ' ' && !strncmp(&sourcecode[1], ENCRHEADER, strlen(ENCRHEADER)))
	{
		pfree(sourcecode);
		ReleaseSysCache(proctuple);
		heap_close(procRelation, RowExclusiveLock);
		return;
	}

	/*
	 * Now encrypt the source.
	 */
	set_encryption_tweak(tweak, function_oid);

	/*
	 * The encryption key has been set in initialize_encryption().
	 */
	if (EVP_EncryptInit_ex(encr_ctx, NULL, NULL, NULL,
						   (unsigned char *) tweak) != 1)
		evp_error();

	in_size = strlen(sourcecode);

	/*
	 * The encryption tweak will be stored along with the actual encrypted
	 * text.
	 */
	encr_size_total = VARHDRSZ + TWEAK_SIZE + in_size;
	c = (char *) palloc(encr_size_total);
	src_encrypted = (text *) c;
	/* Skip the header so far. */
	c += VARHDRSZ;
	memcpy(c, tweak, TWEAK_SIZE);
	c += TWEAK_SIZE;

	if (EVP_EncryptUpdate(encr_ctx,
						  (unsigned char *) c,
						  &out_size,
						  (unsigned char *) sourcecode,
						  in_size) != 1)
		evp_error();

	SET_VARSIZE(src_encrypted, encr_size_total);

	/*
	 * The EVP documentation seems to allow that not all data is encrypted
	 * at the same time, but the low level code does encrypt everything.
	 *
	 * Also note that block size is 1 for the CTR mode so there's no need to
	 * call EVP_EncryptFinal_ex().
	 */
	if (out_size != in_size)
		ereport(ERROR, (errmsg("Some data left unencrypted")));

	/* Now encode the result with HEX */
	encr_hex = DirectFunctionCall2(binary_encode,
								   PointerGetDatum(src_encrypted),
								   DirectFunctionCall1(textin, CStringGetDatum("hex")));

	prosrc = palloc(1 + strlen(ENCRHEADER) + VARSIZE(encr_hex) + 1);
	c = VARDATA(prosrc);

	*(c++) = ' ';

	memcpy(c, ENCRHEADER, strlen(ENCRHEADER));
	c += strlen(ENCRHEADER);

	memcpy(c, VARDATA(encr_hex), VARSIZE(encr_hex) - VARHDRSZ);
	c += VARSIZE(encr_hex) - VARHDRSZ;

	*(c++) = ' ';

	SET_VARSIZE(prosrc, c - (char *) prosrc);

	memset(values, 0, sizeof(values));
	memset(nulls, 0, sizeof(nulls));
	memset(replace, 0, sizeof(replace));

	values[Anum_pg_proc_prosrc - 1] = PointerGetDatum(prosrc);
	replace[Anum_pg_proc_prosrc - 1] = true;

	newproctuple = heap_modify_tuple(proctuple, tupDesc, values, nulls, replace);
	CatalogTupleUpdate(procRelation, &newproctuple->t_self, newproctuple);
	ReleaseSysCache(proctuple);
	heap_freetuple(newproctuple);

	pfree(sourcecode);
	pfree(src_encrypted);
	pfree(prosrc);

	heap_close(procRelation, RowExclusiveLock);

	CommandCounterIncrement();
#else
	ereport(ERROR, (errmsg(ENCRYPTION_NOT_SUPPORTED_MSG)));
#endif	/* USE_ENCRYPTION */
}

/*
 * plpgsql_decrypt()
 *
 * It's called when the function is compiled.  Decryption is done only when we
 * find the correct frame.
 */
char *
plpgsql_decrypt(char *encrypted_src) {
#ifdef USE_ENCRYPTION
	int32	src_len;
	int32	hex_len;
	text	*hex_text;
	Datum	encr;
	char	*result;
	char		tweak[TWEAK_SIZE];
	char	*c;
	int	in_size, out_size;

	if (encrypted_src == NULL)
		return NULL;

	if (!local_encryption_setup_done)
		initialize_encryption();

	src_len = strlen(encrypted_src);
	if (!(encrypted_src[0] == ' ' &&
		  encrypted_src[src_len - 1] == ' ' &&
		  !strncmp(&encrypted_src[1], ENCRHEADER, strlen(ENCRHEADER)))	)
		return encrypted_src;

	hex_len = src_len - strlen(ENCRHEADER) - 2;
	hex_text = palloc(VARHDRSZ + hex_len);
	memcpy(VARDATA_4B(hex_text), &encrypted_src[1 + strlen(ENCRHEADER)], hex_len);
	SET_VARSIZE_4B(hex_text, hex_len + VARHDRSZ);

	encr = DirectFunctionCall2(binary_decode,
							   PointerGetDatum(hex_text),
							   DirectFunctionCall1(textin, CStringGetDatum("hex")));

	c = VARDATA(encr);
	memcpy(tweak, c, TWEAK_SIZE);
	c += TWEAK_SIZE;

	in_size = VARSIZE(encr) - VARHDRSZ - TWEAK_SIZE;
	result = (char *) palloc(in_size + 1);

	/*
	 * The encryption key has been set in initialize_encryption().
	 */
	if (EVP_DecryptInit_ex(encr_ctx, NULL, NULL, NULL,
						   (unsigned char *) tweak) != 1)
		evp_error();

	/* Do the actual encryption. */
	if (EVP_DecryptUpdate(encr_ctx, (unsigned char *) result, &out_size,
						  (unsigned char *) c, in_size) != 1)
		evp_error();

	if (out_size != in_size)
		ereport(ERROR, (errmsg("Some data left undecrypted")));

	result[out_size] = '\0';
	return result;
#else
	ereport(ERROR, (errmsg(ENCRYPTION_NOT_SUPPORTED_MSG)));
	return NULL;
#endif	/* USE_ENCRYPTION */
}

static bool
plpgsql_extra_checks_check_hook(char **newvalue, void **extra, GucSource source)
{
	char	   *rawstring;
	List	   *elemlist;
	ListCell   *l;
	int			extrachecks = 0;
	int		   *myextra;

	if (pg_strcasecmp(*newvalue, "all") == 0)
		extrachecks = PLPGSQL_XCHECK_ALL;
	else if (pg_strcasecmp(*newvalue, "none") == 0)
		extrachecks = PLPGSQL_XCHECK_NONE;
	else
	{
		/* Need a modifiable copy of string */
		rawstring = pstrdup(*newvalue);

		/* Parse string into list of identifiers */
		if (!SplitIdentifierString(rawstring, ',', &elemlist))
		{
			/* syntax error in list */
			GUC_check_errdetail("List syntax is invalid.");
			pfree(rawstring);
			list_free(elemlist);
			return false;
		}

		foreach(l, elemlist)
		{
			char	   *tok = (char *) lfirst(l);

			if (pg_strcasecmp(tok, "shadowed_variables") == 0)
				extrachecks |= PLPGSQL_XCHECK_SHADOWVAR;
			else if (pg_strcasecmp(tok, "too_many_rows") == 0)
			  extrachecks |= PLPGSQL_XCHECK_TOOMANYROWS;
			else if (pg_strcasecmp(tok, "strict_multi_assignment") == 0)
			  extrachecks |= PLPGSQL_XCHECK_STRICTMULTIASSIGNMENT;
			else if (pg_strcasecmp(tok, "all") == 0 || pg_strcasecmp(tok, "none") == 0)
			{
				GUC_check_errdetail("Key word \"%s\" cannot be combined with other key words.", tok);
				pfree(rawstring);
				list_free(elemlist);
				return false;
			}
			else
			{
				GUC_check_errdetail("Unrecognized key word: \"%s\".", tok);
				pfree(rawstring);
				list_free(elemlist);
				return false;
			}
		}

		pfree(rawstring);
		list_free(elemlist);
	}

	myextra = (int *) malloc(sizeof(int));
	if (!myextra)
		return false;
	*myextra = extrachecks;
	*extra = (void *) myextra;

	return true;
}

#ifdef USE_ENCRYPTION
/*
 * Construct the encryption tweak out of the next LSN and the procedure
 * OID. This should be unique enough.
 */
static void
set_encryption_tweak(char *tweak, Oid proc_oid)
{
	XLogRecPtr	lsn;
	char	*c = tweak;

	StaticAssertStmt(sizeof(XLogRecPtr) + sizeof(Oid) <= TWEAK_SIZE,
					 "The encryption tweak is too long");

	memset(c, 0, TWEAK_SIZE);
	lsn = GetXLogInsertRecPtr();
	memcpy(c, &lsn, sizeof(XLogRecPtr));
	c += sizeof(XLogRecPtr);
	memcpy(c, &proc_oid, sizeof(Oid));
}

static void
evp_error(void)
{
	ERR_print_errors_fp(stderr);

	ereport(ERROR,
			(errmsg("OpenSSL encountered error during encryption or decryption.")));
}
#endif	/* USE_ENCRYPTION */

static void
plpgsql_extra_warnings_assign_hook(const char *newvalue, void *extra)
{
	plpgsql_extra_warnings = *((int *) extra);
}

static void
plpgsql_extra_errors_assign_hook(const char *newvalue, void *extra)
{
	plpgsql_extra_errors = *((int *) extra);
}


/*
 * _PG_init()			- library load-time initialization
 *
 * DO NOT make this static nor change its name!
 */
void
_PG_init(void)
{
	/* Be sure we do initialization only once (should be redundant now) */
	static bool inited = false;

	if (inited)
		return;

	pg_bindtextdomain(TEXTDOMAIN);

	DefineCustomEnumVariable("plpgsql_sec.variable_conflict",
							 gettext_noop("Sets handling of conflicts between PL/pgSQL variable names and table column names."),
							 NULL,
							 &plpgsql_variable_conflict,
							 PLPGSQL_RESOLVE_ERROR,
							 variable_conflict_options,
							 PGC_SUSET, 0,
							 NULL, NULL, NULL);

	DefineCustomBoolVariable("plpgsql_sec.print_strict_params",
							 gettext_noop("Print information about parameters in the DETAIL part of the error messages generated on INTO ... STRICT failures."),
							 NULL,
							 &plpgsql_print_strict_params,
							 false,
							 PGC_USERSET, 0,
							 NULL, NULL, NULL);

	DefineCustomBoolVariable("plpgsql_sec.check_asserts",
							 gettext_noop("Perform checks given in ASSERT statements."),
							 NULL,
							 &plpgsql_check_asserts,
							 true,
							 PGC_USERSET, 0,
							 NULL, NULL, NULL);

	DefineCustomStringVariable("plpgsql_sec.extra_warnings",
							   gettext_noop("List of programming constructs that should produce a warning."),
							   NULL,
							   &plpgsql_extra_warnings_string,
							   "none",
							   PGC_USERSET, GUC_LIST_INPUT,
							   plpgsql_extra_checks_check_hook,
							   plpgsql_extra_warnings_assign_hook,
							   NULL);

	DefineCustomStringVariable("plpgsql_sec.extra_errors",
							   gettext_noop("List of programming constructs that should produce an error."),
							   NULL,
							   &plpgsql_extra_errors_string,
							   "none",
							   PGC_USERSET, GUC_LIST_INPUT,
							   plpgsql_extra_checks_check_hook,
							   plpgsql_extra_errors_assign_hook,
							   NULL);

	EmitWarningsOnPlaceholders("plpgsql_sec");

	plpgsql_sec_HashTableInit();
	RegisterXactCallback(plpgsql_xact_cb, NULL);
	RegisterSubXactCallback(plpgsql_subxact_cb, NULL);

	inited = true;
}

/* ----------
 * plpgsql_call_handler
 *
 * The PostgreSQL function manager and trigger manager
 * call this function for execution of PL/pgSQL procedures.
 * ----------
 */
PG_FUNCTION_INFO_V1(plpgsql_sec_call_handler);

Datum
plpgsql_sec_call_handler(PG_FUNCTION_ARGS)
{
	bool		nonatomic;
	PLpgSQL_function *func;
	PLpgSQL_execstate *save_cur_estate;
	Datum		retval;
	int			rc;

	nonatomic = fcinfo->context &&
		IsA(fcinfo->context, CallContext) &&
		!castNode(CallContext, fcinfo->context)->atomic;

	/*
	 * Connect to SPI manager
	 */
	if ((rc = SPI_connect_ext(nonatomic ? SPI_OPT_NONATOMIC : 0)) != SPI_OK_CONNECT)
		elog(ERROR, "SPI_connect failed: %s", SPI_result_code_string(rc));

	/* Find or compile the function */
	func = plpgsql_sec_compile(fcinfo, false);

	/* Must save and restore prior value of cur_estate */
	save_cur_estate = func->cur_estate;

	/* Mark the function as busy, so it can't be deleted from under us */
	func->use_count++;

	PG_TRY();
	{
		/*
		 * Determine if called as function or trigger and call appropriate
		 * subhandler
		 */
		if (CALLED_AS_TRIGGER(fcinfo))
			retval = PointerGetDatum(plpgsql_exec_trigger(func,
										   (TriggerData *) fcinfo->context));
		else if (CALLED_AS_EVENT_TRIGGER(fcinfo))
		{
			plpgsql_exec_event_trigger(func,
									   (EventTriggerData *) fcinfo->context);
			retval = (Datum) 0;
		}
		else
			retval = plpgsql_exec_function(func, fcinfo, NULL, !nonatomic);
	}
	PG_CATCH();
	{
		/* Decrement use-count, restore cur_estate, and propagate error */
		func->use_count--;
		func->cur_estate = save_cur_estate;
		PG_RE_THROW();
	}
	PG_END_TRY();

	func->use_count--;

	func->cur_estate = save_cur_estate;

	/*
	 * Disconnect from SPI manager
	 */
	if ((rc = SPI_finish()) != SPI_OK_FINISH)
		elog(ERROR, "SPI_finish failed: %s", SPI_result_code_string(rc));

	return retval;
}

/* ----------
 * plpgsql_inline_handler
 *
 * Called by PostgreSQL to execute an anonymous code block
 * ----------
 */
PG_FUNCTION_INFO_V1(plpgsql_sec_inline_handler);

Datum
plpgsql_sec_inline_handler(PG_FUNCTION_ARGS)
{
	LOCAL_FCINFO(fake_fcinfo, 0);
	InlineCodeBlock *codeblock = castNode(InlineCodeBlock, DatumGetPointer(PG_GETARG_DATUM(0)));
	PLpgSQL_function *func;
	FmgrInfo	flinfo;
	EState	   *simple_eval_estate;
	Datum		retval;
	int			rc;

	/*
	 * Connect to SPI manager
	 */
	if ((rc = SPI_connect_ext(codeblock->atomic ? 0 : SPI_OPT_NONATOMIC)) != SPI_OK_CONNECT)
		elog(ERROR, "SPI_connect failed: %s", SPI_result_code_string(rc));

	/* Compile the anonymous code block */
	func = plpgsql_sec_compile_inline(codeblock->source_text);

	/* Mark the function as busy, just pro forma */
	func->use_count++;

	/*
	 * Set up a fake fcinfo with just enough info to satisfy
	 * plpgsql_exec_function().  In particular note that this sets things up
	 * with no arguments passed.
	 */
	MemSet(fake_fcinfo, 0, SizeForFunctionCallInfo(0));
	MemSet(&flinfo, 0, sizeof(flinfo));
	fake_fcinfo->flinfo = &flinfo;
	flinfo.fn_oid = InvalidOid;
	flinfo.fn_mcxt = CurrentMemoryContext;

	/* Create a private EState for simple-expression execution */
	simple_eval_estate = CreateExecutorState();

	/* And run the function */
	PG_TRY();
	{
		retval = plpgsql_exec_function(func, fake_fcinfo, simple_eval_estate, codeblock->atomic);
	}
	PG_CATCH();
	{
		/*
		 * We need to clean up what would otherwise be long-lived resources
		 * accumulated by the failed DO block, principally cached plans for
		 * statements (which can be flushed with plpgsql_free_function_memory)
		 * and execution trees for simple expressions, which are in the
		 * private EState.
		 *
		 * Before releasing the private EState, we must clean up any
		 * simple_econtext_stack entries pointing into it, which we can do by
		 * invoking the subxact callback.  (It will be called again later if
		 * some outer control level does a subtransaction abort, but no harm
		 * is done.)  We cheat a bit knowing that plpgsql_subxact_cb does not
		 * pay attention to its parentSubid argument.
		 */
		plpgsql_subxact_cb(SUBXACT_EVENT_ABORT_SUB,
						   GetCurrentSubTransactionId(),
						   0, NULL);

		/* Clean up the private EState */
		FreeExecutorState(simple_eval_estate);

		/* Function should now have no remaining use-counts ... */
		func->use_count--;
		Assert(func->use_count == 0);

		/* ... so we can free subsidiary storage */
		plpgsql_free_function_memory(func);

		/* And propagate the error */
		PG_RE_THROW();
	}
	PG_END_TRY();

	/* Clean up the private EState */
	FreeExecutorState(simple_eval_estate);

	/* Function should now have no remaining use-counts ... */
	func->use_count--;
	Assert(func->use_count == 0);

	/* ... so we can free subsidiary storage */
	plpgsql_free_function_memory(func);

	/*
	 * Disconnect from SPI manager
	 */
	if ((rc = SPI_finish()) != SPI_OK_FINISH)
		elog(ERROR, "SPI_finish failed: %s", SPI_result_code_string(rc));

	return retval;
}

/* ----------
 * plpgsql_validator
 *
 * This function attempts to validate a PL/pgSQL function at
 * CREATE FUNCTION time.
 * ----------
 */
PG_FUNCTION_INFO_V1(plpgsql_sec_validator);

Datum
plpgsql_sec_validator(PG_FUNCTION_ARGS)
{
	Oid			funcoid = PG_GETARG_OID(0);
	HeapTuple	tuple;
	Form_pg_proc proc;
	char		functyptype;
	int			numargs;
	Oid		   *argtypes;
	char	  **argnames;
	char	   *argmodes;
	bool		is_dml_trigger = false;
	bool		is_event_trigger = false;
	int			i;

	if (!CheckFunctionValidatorAccess(fcinfo->flinfo->fn_oid, funcoid))
		PG_RETURN_VOID();

	plpgsql_encrypt(funcoid);

	/* Get the new function's pg_proc entry */
	tuple = SearchSysCache1(PROCOID, ObjectIdGetDatum(funcoid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for function %u", funcoid);
	proc = (Form_pg_proc) GETSTRUCT(tuple);

	functyptype = get_typtype(proc->prorettype);

	/* Disallow pseudotype result */
	/* except for TRIGGER, RECORD, VOID, or polymorphic */
	if (functyptype == TYPTYPE_PSEUDO)
	{
		/* we assume OPAQUE with no arguments means a trigger */
		if (proc->prorettype == TRIGGEROID ||
			(proc->prorettype == OPAQUEOID && proc->pronargs == 0))
			is_dml_trigger = true;
		else if (proc->prorettype == EVTTRIGGEROID)
			is_event_trigger = true;
		else if (proc->prorettype != RECORDOID &&
				 proc->prorettype != VOIDOID &&
				 !IsPolymorphicType(proc->prorettype))
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("PL/pgSQL functions cannot return type %s",
							format_type_be(proc->prorettype))));
	}

	/* Disallow pseudotypes in arguments (either IN or OUT) */
	/* except for RECORD and polymorphic */
	numargs = get_func_arg_info(tuple,
								&argtypes, &argnames, &argmodes);
	for (i = 0; i < numargs; i++)
	{
		if (get_typtype(argtypes[i]) == TYPTYPE_PSEUDO)
		{
			if (argtypes[i] != RECORDOID &&
				!IsPolymorphicType(argtypes[i]))
				ereport(ERROR,
						(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
						 errmsg("PL/pgSQL functions cannot accept type %s",
								format_type_be(argtypes[i]))));
		}
	}

	/* Postpone body checks if !check_function_bodies */
	if (check_function_bodies)
	{
		LOCAL_FCINFO(fake_fcinfo, 0);
		FmgrInfo	flinfo;
		int			rc;
		TriggerData trigdata;
		EventTriggerData etrigdata;

		/*
		 * Connect to SPI manager (is this needed for compilation?)
		 */
		if ((rc = SPI_connect()) != SPI_OK_CONNECT)
			elog(ERROR, "SPI_connect failed: %s", SPI_result_code_string(rc));

		/*
		 * Set up a fake fcinfo with just enough info to satisfy
		 * plpgsql_sec_compile().
		 */
		MemSet(fake_fcinfo, 0, SizeForFunctionCallInfo(0));
		MemSet(&flinfo, 0, sizeof(flinfo));
		fake_fcinfo->flinfo = &flinfo;
		flinfo.fn_oid = funcoid;
		flinfo.fn_mcxt = CurrentMemoryContext;
		if (is_dml_trigger)
		{
			MemSet(&trigdata, 0, sizeof(trigdata));
			trigdata.type = T_TriggerData;
			fake_fcinfo->context = (Node *) &trigdata;
		}
		else if (is_event_trigger)
		{
			MemSet(&etrigdata, 0, sizeof(etrigdata));
			etrigdata.type = T_EventTriggerData;
			fake_fcinfo->context = (Node *) &etrigdata;
		}

		/* Test-compile the function */
		plpgsql_sec_compile(fake_fcinfo, true);

		/*
		 * Disconnect from SPI manager
		 */
		if ((rc = SPI_finish()) != SPI_OK_FINISH)
			elog(ERROR, "SPI_finish failed: %s", SPI_result_code_string(rc));
	}

	ReleaseSysCache(tuple);

	PG_RETURN_VOID();
}
