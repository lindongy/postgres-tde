/* plpgsql_sec--unpackaged--1.0.sql */

ALTER EXTENSION plpgsql_sec ADD PROCEDURAL LANGUAGE plpgsql_sec;
-- ALTER ADD LANGUAGE doesn't pick up the support functions, so we have to.
ALTER EXTENSION plpgsql_sec ADD FUNCTION plpgsql_sec_call_handler();
ALTER EXTENSION plpgsql_sec ADD FUNCTION plpgsql_sec_inline_handler(internal);
ALTER EXTENSION plpgsql_sec ADD FUNCTION plpgsql_sec_validator(oid);
