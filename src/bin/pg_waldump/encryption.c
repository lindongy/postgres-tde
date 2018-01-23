/*
 * TODO Header
 */

#include "postgres.h"

/*
 * In the backend this variable is a GUC. Since backend is not linked to
 * pg_waldump, we need to define it separate.
 *
 * TODO Implement function (maybe in pg_waldump.c) that gets the value from
 * the control file.
 */
bool encryption_enabled = true;
