/* Processed by ecpg (regression mode) */
/* These include files are added by the preprocessor */
#include <ecpglib.h>
#include <ecpgerrno.h>
#include <sqlca.h>
/* End of automatic include section */
#define ECPGdebug(X,Y) ECPGdebug((X)+100,(Y))

#line 1 "cursor-ra-move.pgc"
#include <stdlib.h>
#include <string.h>


#line 1 "regression.h"






#line 4 "cursor-ra-move.pgc"


/* exec sql whenever sqlerror  sqlprint ; */
#line 6 "cursor-ra-move.pgc"


int main(void)
{
	int	quit_loop;

	ECPGdebug(1, stderr);

	{ ECPGconnect(__LINE__, 0, "regress1" , NULL, NULL , NULL, 0); 
#line 14 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 14 "cursor-ra-move.pgc"


	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "create table t1 ( id serial primary key , t text )", ECPGt_EOIT, ECPGt_EORT);
#line 16 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 16 "cursor-ra-move.pgc"

	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "insert into t1 ( t ) values ( 'a' ) , ( 'b' ) , ( 'c' ) , ( 'd' ) , ( 'e' ) , ( 'f' ) , ( 'g' ) , ( 'h' ) , ( 'i' ) , ( 'j' ) , ( 'k' ) , ( 'l' ) , ( 'm' ) , ( 'n' ) , ( 'o' ) , ( 'p' ) , ( 'q' ) , ( 'r' ) , ( 's' ) , ( 't' ) , ( 'u' ) , ( 'v' ) , ( 'w' ) , ( 'x' ) , ( 'y' ) , ( 'z' )", ECPGt_EOIT, ECPGt_EORT);
#line 21 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 21 "cursor-ra-move.pgc"

	{ ECPGtrans(__LINE__, NULL, "commit", 0, 0, 0, NULL);
#line 22 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 22 "cursor-ra-move.pgc"


	/* declare scroll_cur scroll cursor for select id , t from t1 order by id */
#line 24 "cursor-ra-move.pgc"

	/* declare noscroll_cur no scroll cursor for select id , t from t1 order by id */
#line 25 "cursor-ra-move.pgc"

	/* Implicitly scrollable */
	/* declare unspec_cur1 cursor for select id , t from t1 order by id */
#line 27 "cursor-ra-move.pgc"

	/* Implicitly non-scrollable */
	/* declare unspec_cur2 cursor for select t1 . id , t1 . t , t2 . id , t2 . t from t1 join t1 as t2 on ( t1 . id = 27 - t2 . id ) order by t1 . id */
#line 29 "cursor-ra-move.pgc"


	/* Test MOVE ABSOLUTE -1 for all 4 cursors */

	printf("test scroll_cur for move absolute -1\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 8, 0, 0, "scroll_cur", ECPGst_normal, "declare scroll_cur scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 35 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 35 "cursor-ra-move.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute, "- 1", 1, "scroll_cur", ECPGst_normal, "move absolute - 1 in scroll_cur", ECPGt_EOIT, ECPGt_EORT);
#line 39 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 39 "cursor-ra-move.pgc"

	if (sqlca.sqlcode < 0)
		printf("move absolute -1 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("move absolute -1 in scroll_cur succeeded\n");

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 45 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 45 "cursor-ra-move.pgc"


	printf("test noscroll_cur for move absolute -1\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_no_scroll, 8, 0, 0, "noscroll_cur", ECPGst_normal, "declare noscroll_cur no scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 49 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 49 "cursor-ra-move.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute, "- 1", 1, "noscroll_cur", ECPGst_normal, "move absolute - 1 in noscroll_cur", ECPGt_EOIT, ECPGt_EORT);
#line 53 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 53 "cursor-ra-move.pgc"

	if (sqlca.sqlcode < 0)
		printf("move absolute -1 in noscroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("move absolute -1 in noscroll_cur succeeded\n");

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 59 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 59 "cursor-ra-move.pgc"


	printf("test unspec_cur1 for move absolute -1\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_unspecified, 8, 0, 0, "unspec_cur1", ECPGst_normal, "declare unspec_cur1 cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 63 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 63 "cursor-ra-move.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute, "- 1", 1, "unspec_cur1", ECPGst_normal, "move absolute - 1 in unspec_cur1", ECPGt_EOIT, ECPGt_EORT);
#line 67 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 67 "cursor-ra-move.pgc"

	if (sqlca.sqlcode < 0)
		printf("move absolute -1 in unspec_cur1 failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("move absolute -1 in unspec_cur1 succeeded\n");

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 73 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 73 "cursor-ra-move.pgc"


	printf("test unspec_cur2 for move absolute -1\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_unspecified, 8, 0, 0, "unspec_cur2", ECPGst_normal, "declare unspec_cur2 cursor for select t1 . id , t1 . t , t2 . id , t2 . t from t1 join t1 as t2 on ( t1 . id = 27 - t2 . id ) order by t1 . id", ECPGt_EOIT, ECPGt_EORT);
#line 77 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 77 "cursor-ra-move.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_absolute, "- 1", 1, "unspec_cur2", ECPGst_normal, "move absolute - 1 in unspec_cur2", ECPGt_EOIT, ECPGt_EORT);
#line 81 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 81 "cursor-ra-move.pgc"

	if (sqlca.sqlcode < 0)
		printf("move absolute -1 in unspec_cur2 failed with SQLSTATE %5s\n", sqlca.sqlstate);
	else
		printf("move absolute -1 in unspec_cur2 succeeded\n");

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 87 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 87 "cursor-ra-move.pgc"


	/* Test MOVE RELATIVE 8 */

	printf("test scroll_cur for move relative 8\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 8, 0, 0, "scroll_cur", ECPGst_normal, "declare scroll_cur scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 93 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 93 "cursor-ra-move.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	quit_loop = 0;
	while (!quit_loop)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_relative, "8", 1, "scroll_cur", ECPGst_normal, "move relative 8 in scroll_cur", ECPGt_EOIT, ECPGt_EORT);
#line 100 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 100 "cursor-ra-move.pgc"

		if (sqlca.sqlcode < 0)
			printf("move relative 8 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
		else
			printf("move relative 8 in scroll_cur succeeded, sqlerrd[2] %ld\n", sqlca.sqlerrd[2]);
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	printf("test scroll_cur for move relative -8\n");

	quit_loop = 0;
	while (!quit_loop)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_relative, "- 8", 1, "scroll_cur", ECPGst_normal, "move relative - 8 in scroll_cur", ECPGt_EOIT, ECPGt_EORT);
#line 113 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 113 "cursor-ra-move.pgc"

		if (sqlca.sqlcode < 0)
			printf("move relative -8 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
		else
			printf("move relative -8 in scroll_cur succeeded, sqlerrd[2] %ld\n", sqlca.sqlerrd[2]);
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 121 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 121 "cursor-ra-move.pgc"


	/* Test MOVE FORWARD 8 */

	printf("test scroll_cur for move forward 8\n");

	{ ECPGopen(__LINE__, 0, 1, NULL, 0, 0, ECPGcs_scroll, 8, 0, 0, "scroll_cur", ECPGst_normal, "declare scroll_cur scroll cursor for select id , t from t1 order by id", ECPGt_EOIT, ECPGt_EORT);
#line 127 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 127 "cursor-ra-move.pgc"

	if (sqlca.sqlcode < 0)
		printf("open failed with SQLSTATE %5s\n", sqlca.sqlstate);

	quit_loop = 0;
	while (!quit_loop)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "8", 1, "scroll_cur", ECPGst_normal, "move forward 8 in scroll_cur", ECPGt_EOIT, ECPGt_EORT);
#line 134 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 134 "cursor-ra-move.pgc"

		if (sqlca.sqlcode < 0)
			printf("move forward 8 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
		else
			printf("move forward 8 in scroll_cur succeeded, sqlerrd[2] %ld\n", sqlca.sqlerrd[2]);
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	printf("test scroll_cur for move forward -8\n");

	quit_loop = 0;
	while (!quit_loop)
	{
		{ ECPGfetch(__LINE__, 0, 1, NULL, 0, ECPGc_forward, "- 8", 1, "scroll_cur", ECPGst_normal, "move forward - 8 in scroll_cur", ECPGt_EOIT, ECPGt_EORT);
#line 147 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 147 "cursor-ra-move.pgc"

		if (sqlca.sqlcode < 0)
			printf("move forward -8 in scroll_cur failed with SQLSTATE %5s\n", sqlca.sqlstate);
		else
			printf("move forward -8 in scroll_cur succeeded, sqlerrd[2] %ld\n", sqlca.sqlerrd[2]);
		quit_loop = (sqlca.sqlerrd[2] == 0);
	}

	{ ECPGtrans(__LINE__, NULL, "rollback", 0, 0, 1, NULL);
#line 155 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 155 "cursor-ra-move.pgc"


	/* Drop the test table */

	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "drop table t1", ECPGt_EOIT, ECPGt_EORT);
#line 159 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 159 "cursor-ra-move.pgc"

	{ ECPGtrans(__LINE__, NULL, "commit", 0, 0, 0, NULL);
#line 160 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 160 "cursor-ra-move.pgc"


	{ ECPGdisconnect(__LINE__, "ALL");
#line 162 "cursor-ra-move.pgc"

if (sqlca.sqlcode < 0) sqlprint();}
#line 162 "cursor-ra-move.pgc"


	return 0;
}
