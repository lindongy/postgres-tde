BEGIN;
SELECT buffile_create();
SELECT buffile_seek(0, 8191);
-- Write data across block boundary.
SELECT buffile_write('xyz');
SELECT buffile_seek(0, 8191);
-- Check it's there
SELECT buffile_read(4);
SELECT buffile_seek(0, 8191);
-- Overwrite only part of it.
SELECT buffile_write('ab');
-- Check that the remaining part is not affected, i.e. the 2nd block was
-- loaded before we started to overwrite its contents.
SELECT buffile_seek(0, 8191);
SELECT buffile_read(4);
SELECT buffile_close();
COMMIT;
