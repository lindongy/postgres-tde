CREATE FUNCTION buffile_create()
RETURNS void
AS 'MODULE_PATHNAME', 'buffile_create'
LANGUAGE C;

CREATE FUNCTION buffile_close()
RETURNS void
AS 'MODULE_PATHNAME', 'buffile_close'
LANGUAGE C;

CREATE FUNCTION buffile_write(text)
RETURNS bigint
AS 'MODULE_PATHNAME', 'buffile_write'
LANGUAGE C;

CREATE FUNCTION buffile_read(bigint)
RETURNS bytea
AS 'MODULE_PATHNAME', 'buffile_read'
LANGUAGE C;

CREATE FUNCTION buffile_seek(int, bigint)
RETURNS int
AS 'MODULE_PATHNAME', 'buffile_seek'
LANGUAGE C;

CREATE FUNCTION buffile_assert_fileno(int)
RETURNS void
AS 'MODULE_PATHNAME', 'buffile_assert_fileno'
LANGUAGE C;
