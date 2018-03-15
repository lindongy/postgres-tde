/*-------------------------------------------------------------------------
 *
 * string.c
 *		string handling helpers
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/common/string.c
 *
 *-------------------------------------------------------------------------
 */


#ifndef FRONTEND
#include "postgres.h"
#else
#include "postgres_fe.h"
#endif

#include "common/string.h"


/*
 * Returns whether the string `str' has the postfix `end'.
 */
bool
pg_str_endswith(const char *str, const char *end)
{
	size_t		slen = strlen(str);
	size_t		elen = strlen(end);

	/* can't be a postfix if longer */
	if (elen > slen)
		return false;

	/* compare the end of the strings */
	str += slen - elen;
	return strcmp(str, end) == 0;
}

/*
 * Helper function to check if a page is completely empty.
 *
 * TODO Invent name that is more consistent with that of the other function(s)
 * in this module.
 */
bool
IsAllZero(const char *input, Size size)
{
	const char *pos = input;
	const char *aligned_start = (char*) MAXALIGN64(input);
	const char *end = input + size;

	/* Check 1 byte at a time until pos is 8 byte aligned */
	while (pos < aligned_start)
		if (*pos++ != 0)
			return false;

	/*
	 * Run 8 parallel 8 byte checks in one iteration. On 2016 hardware
	 * slightly faster than 4 parallel checks.
	 **/
	while (pos + 8*sizeof(uint64) <= end)
	{
		uint64 *p = (uint64*) pos;
		if ((p[0] | p[1] | p[2] | p[3] | p[4] | p[5] | p[6] | p[7]) != 0)
			return false;
		pos += 8*sizeof(uint64);
	}

	/* Handle unaligned tail. */
	while (pos < end)
		if (*pos++ != 0)
			return false;

	return true;
}
