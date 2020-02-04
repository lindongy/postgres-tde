/* plpgsql_sec--1.0.sql */

CREATE FUNCTION plpgsql_sec_call_handler()
	RETURNS language_handler
	AS 'plpgsql_sec' LANGUAGE C;

CREATE FUNCTION plpgsql_sec_inline_handler(internal)
	RETURNS void
	AS 'plpgsql_sec' LANGUAGE C;

CREATE FUNCTION plpgsql_sec_validator(oid)
	RETURNS void
	AS 'plpgsql_sec' LANGUAGE C;;

CREATE TRUSTED PROCEDURAL LANGUAGE plpgsql_sec
	HANDLER plpgsql_sec_call_handler
	INLINE plpgsql_sec_inline_handler
	VALIDATOR plpgsql_sec_validator;

COMMENT ON PROCEDURAL LANGUAGE plpgsql_sec IS 'PL/pgSQLSec procedural language';
