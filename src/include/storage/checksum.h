/*-------------------------------------------------------------------------
 *
 * checksum.h
 *	  Checksum implementation for data pages.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/checksum.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef CHECKSUM_H
#define CHECKSUM_H

#include "storage/block.h"

/*
 * Only PageIsNew() should be used to determine whether checksum should be
 * computed or not (page can have invalid checksum even if !PageIsNew(), which
 * indicates that it hasn't been written to disk yet). However, when
 * determining whether checksum needs to be checked for a page that we've just
 * read from disk, we can simply compare the stored value to this
 * constant. The important assumption is that page cannot become "new" again
 * if data was once added to it (see how pd_upper is set in
 * compactify_tuples), so a non-zero checksum that we read from disk should
 * never mean that checksum computation was just skipped for a "renewed"
 * page. On the other hand, zero checksum should only mean that it hasn't been
 * computed for the page yet (see pg_checksum_page).
 */
#define InvalidChecksum		0

/*
 * Compute the checksum for a Postgres page.  The page must be aligned on a
 * 4-byte boundary.
 */
extern uint16 pg_checksum_page(char *page, BlockNumber blkno);

#endif							/* CHECKSUM_H */
