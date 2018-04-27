#include "postgres.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "storage/buffile.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/resowner.h"

PG_MODULE_MAGIC;

/*
 * To cover various corner cases, the tests assume MAX_PHYSICAL_FILESIZE to be
 * exactly MAX_PHYSICAL_FILESIZE_TEST.
 */
#define MAX_PHYSICAL_FILESIZE_TEST	(4 * BLCKSZ)

static BufFile	*bf = NULL;

static void check_file(void);

extern Datum buffile_create(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(buffile_create);
Datum
buffile_create(PG_FUNCTION_ARGS)
{
	MemoryContext	old_cxt;
	ResourceOwner	old_ro;

	if (bf != NULL)
		elog(ERROR, "file already exists");

	old_cxt = MemoryContextSwitchTo(TopMemoryContext);

	/*
	 * Make sure the file is not deleted across function calls.
	 */
	old_ro = CurrentResourceOwner;
	CurrentResourceOwner = TopTransactionResourceOwner;

	bf = BufFileCreateTemp(false);

	CurrentResourceOwner = old_ro;
	MemoryContextSwitchTo(old_cxt);

	PG_RETURN_VOID();
}

extern Datum buffile_close(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(buffile_close);
Datum
buffile_close(PG_FUNCTION_ARGS)
{
	if (bf == NULL)
		elog(ERROR, "there's no file to close");

	BufFileClose(bf);
	bf = NULL;

	PG_RETURN_VOID();
}

extern Datum buffile_write(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(buffile_write);
Datum
buffile_write(PG_FUNCTION_ARGS)
{
	Datum	d = PG_GETARG_DATUM(0);
	char	*s = TextDatumGetCString(d);
	size_t	res;

	check_file();
	res = BufFileWrite(bf, s, strlen(s));

	PG_RETURN_INT64(res);
}

extern Datum buffile_read(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(buffile_read);
Datum
buffile_read(PG_FUNCTION_ARGS)
{
	int64 size = PG_GETARG_INT64(0);
	StringInfo	buf = makeStringInfo();
	size_t	res_size;
	bytea	*result;

	check_file();

	enlargeStringInfo(buf, size);
	res_size = BufFileRead(bf, buf->data, size);
	buf->len = res_size;

	result = DatumGetByteaPP(DirectFunctionCall1(bytearecv,
												 PointerGetDatum(buf)));
	PG_RETURN_BYTEA_P(result);
}

extern Datum buffile_seek(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(buffile_seek);
Datum
buffile_seek(PG_FUNCTION_ARGS)
{
	int32 fileno = PG_GETARG_INT32(0);
	int64 offset = PG_GETARG_INT64(1);
	int32	res;

	check_file();
	res = BufFileSeek(bf, fileno, offset, SEEK_SET);

	PG_RETURN_INT32(res);
}

extern Datum buffile_assert_fileno(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(buffile_assert_fileno);
Datum
buffile_assert_fileno(PG_FUNCTION_ARGS)
{
	int32	fileno_expected = PG_GETARG_INT32(0);
	int32	fileno;
	off_t	offset;

	check_file();
	BufFileTell(bf, &fileno, &offset);

	if (fileno != fileno_expected)
		elog(ERROR, "file number does not match");

	PG_RETURN_VOID();
}

static void
check_file(void)
{
	if (bf == NULL)
		elog(ERROR, "the file is not opened");
}

